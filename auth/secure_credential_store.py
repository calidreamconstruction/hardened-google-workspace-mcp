"""Verified native-keyring OAuth storage with Windows-safe chunking."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)
SERVICE_NAME = "hardened-google-workspace-mcp"
USERS_KEY = "__registered_users__"
SCHEMA_VERSION = 1
CHUNK_SIZE = 900
MAX_CHUNKS = 64
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"[0-9a-f]{24}")


class CredentialIntegrityError(RuntimeError):
    """A committed keyring record is missing, malformed, or altered."""


def _email(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("valid user email required")
    value = value.strip()
    if not value or len(value) > 320:
        raise ValueError("valid user email required")
    return value


def _payload(email: str, credentials: Any) -> dict[str, Any]:
    expiry = getattr(credentials, "expiry", None)
    return {
        "schema_version": SCHEMA_VERSION,
        "user_email": email,
        "token": getattr(credentials, "token", None),
        "refresh_token": getattr(credentials, "refresh_token", None),
        "token_uri": getattr(credentials, "token_uri", None),
        "client_id": getattr(credentials, "client_id", None),
        "client_secret": getattr(credentials, "client_secret", None),
        "scopes": list(getattr(credentials, "scopes", None) or []),
        "expiry": expiry.isoformat() if expiry else None,
    }


_credential_payload = _payload


def _credential_factory(data: dict[str, Any]) -> Any:
    from google.oauth2.credentials import Credentials

    expiry = datetime.fromisoformat(data["expiry"]) if data.get("expiry") else None
    if expiry and expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    return Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        scopes=data.get("scopes"),
        expiry=expiry,
    )


class ChunkedKeyringCredentialStore:
    """Store credentials in a trusted native keyring; never write token files."""

    def __init__(
        self,
        *,
        keyring_module: Any | None = None,
        legacy_store: Any | None = None,
        credential_factory: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        if keyring_module is None:
            import keyring as keyring_module
        self._keyring = keyring_module
        self._legacy = legacy_store
        self._factory = credential_factory or _credential_factory

    @staticmethod
    def _identity(email: str) -> str:
        normalized = _email(email).casefold().encode()
        return hashlib.sha256(normalized).hexdigest()[:32]

    def _manifest_key(self, email: str) -> str:
        return f"__credential__:{self._identity(email)}:manifest"

    def _chunk_key(self, email: str, generation: str, index: int) -> str:
        return f"__credential__:{self._identity(email)}:{generation}:{index:03d}"

    def _delete(self, username: str) -> None:
        try:
            self._keyring.delete_password(SERVICE_NAME, username)
        except Exception as exc:
            if type(exc).__name__ != "PasswordDeleteError":
                raise

    @staticmethod
    def _decode_users(raw: str | None) -> set[str]:
        if not raw:
            return set()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError("user registry is malformed") from exc
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise CredentialIntegrityError("user registry is malformed")
        return set(value)

    def _users(self) -> set[str]:
        raw = self._keyring.get_password(SERVICE_NAME, USERS_KEY)
        return self._decode_users(raw)

    def _save_users(self, users: set[str]) -> None:
        raw = json.dumps(sorted(users), separators=(",", ":"))
        self._keyring.set_password(SERVICE_NAME, USERS_KEY, raw)
        if self._keyring.get_password(SERVICE_NAME, USERS_KEY) != raw:
            raise CredentialIntegrityError("user registry verification failed")

    @staticmethod
    def _parse_manifest(raw: str) -> dict[str, Any]:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError("manifest is malformed") from exc
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise CredentialIntegrityError("manifest schema is invalid")
        generation, digest, chunks = (
            value.get("generation"),
            value.get("sha256"),
            value.get("chunks"),
        )
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise CredentialIntegrityError("manifest generation is invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise CredentialIntegrityError("manifest digest is invalid")
        if (
            isinstance(chunks, bool)
            or not isinstance(chunks, int)
            or not 1 <= chunks <= MAX_CHUNKS
        ):
            raise CredentialIntegrityError("manifest chunk count is invalid")
        return value

    def _manifest(self, email: str) -> dict[str, Any] | None:
        raw = self._keyring.get_password(SERVICE_NAME, self._manifest_key(email))
        return self._parse_manifest(raw) if raw else None

    def _read_payload(
        self, email: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        parts = []
        for index in range(manifest["chunks"]):
            part = self._keyring.get_password(
                SERVICE_NAME,
                self._chunk_key(email, manifest["generation"], index),
            )
            if not isinstance(part, str):
                raise CredentialIntegrityError("credential chunk is missing")
            parts.append(part)
        raw = "".join(parts)
        if hashlib.sha256(raw.encode()).hexdigest() != manifest["sha256"]:
            raise CredentialIntegrityError("credential digest mismatch")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError("credential payload is malformed") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise CredentialIntegrityError("credential payload schema is invalid")
        if data.get("user_email") != email:
            raise CredentialIntegrityError("credential identity mismatch")
        return data

    def _delete_generation(self, email: str, manifest: dict[str, Any]) -> None:
        for index in range(manifest["chunks"]):
            self._delete(
                self._chunk_key(email, manifest["generation"], index)
            )

    def _cleanup_legacy(self, email: str) -> bool:
        if self._legacy is None:
            return True
        try:
            if email not in set(self._legacy.list_users()):
                return True
            return bool(self._legacy.delete_credential(email))
        except Exception as exc:
            logger.error("Legacy cleanup failed for %s: %s", email, exc)
            return False

    def _restore_raw(self, key: str, old: str | None) -> None:
        if old is None:
            self._delete(key)
            if self._keyring.get_password(SERVICE_NAME, key) is not None:
                raise CredentialIntegrityError("rollback delete was not verified")
            return
        self._keyring.set_password(SERVICE_NAME, key, old)
        if self._keyring.get_password(SERVICE_NAME, key) != old:
            raise CredentialIntegrityError("rollback restore was not verified")

    def store_credential(self, user_email: str, credentials: Any) -> bool:
        written: list[str] = []
        old_manifest: dict[str, Any] | None = None
        generation = ""
        email = str(user_email)
        try:
            email = _email(user_email)
            manifest_key = self._manifest_key(email)
            old_manifest_raw = self._keyring.get_password(
                SERVICE_NAME, manifest_key
            )
            old_manifest = (
                self._parse_manifest(old_manifest_raw)
                if old_manifest_raw
                else None
            )
            old_users_raw = self._keyring.get_password(SERVICE_NAME, USERS_KEY)
            users = self._decode_users(old_users_raw)

            data = _payload(email, credentials)
            raw = json.dumps(
                data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            digest = hashlib.sha256(raw.encode()).hexdigest()
            generation = digest[:24]
            chunks = [raw[i : i + CHUNK_SIZE] for i in range(0, len(raw), CHUNK_SIZE)]
            if not chunks or len(chunks) > MAX_CHUNKS:
                raise CredentialIntegrityError("credential payload is too large")

            for index, part in enumerate(chunks):
                key = self._chunk_key(email, generation, index)
                self._keyring.set_password(SERVICE_NAME, key, part)
                written.append(key)
                if self._keyring.get_password(SERVICE_NAME, key) != part:
                    raise CredentialIntegrityError("chunk verification failed")

            manifest = {
                "schema_version": 1,
                "generation": generation,
                "chunks": len(chunks),
                "sha256": digest,
            }
            manifest_raw = json.dumps(
                manifest, sort_keys=True, separators=(",", ":")
            )
            self._keyring.set_password(SERVICE_NAME, manifest_key, manifest_raw)
            if self._keyring.get_password(SERVICE_NAME, manifest_key) != manifest_raw:
                raise CredentialIntegrityError("manifest verification failed")
            verified = self._read_payload(email, manifest)
            if verified.get("refresh_token") != data.get("refresh_token"):
                raise CredentialIntegrityError("round-trip verification failed")

            users.add(email)
            self._save_users(users)
        except Exception as exc:
            logger.error("Secure credential write failed for %s: %s", email, exc)
            try:
                if "manifest_key" in locals():
                    self._restore_raw(manifest_key, old_manifest_raw)
                if "old_users_raw" in locals():
                    self._restore_raw(USERS_KEY, old_users_raw)
            except Exception as rollback_exc:
                logger.critical("Credential rollback failed: %s", rollback_exc)
            if not old_manifest or old_manifest.get("generation") != generation:
                for key in written:
                    try:
                        self._delete(key)
                    except Exception:
                        pass
            return False

        if old_manifest and old_manifest["generation"] != generation:
            try:
                self._delete_generation(email, old_manifest)
            except Exception as exc:
                logger.warning("Old generation cleanup failed for %s: %s", email, exc)
        try:
            self._delete(email)
        except Exception as exc:
            logger.warning("Legacy key cleanup failed for %s: %s", email, exc)
        if not self._cleanup_legacy(email):
            logger.error(
                "Secure credential committed for %s but plaintext cleanup failed",
                email,
            )
            return False
        return True

    def get_credential(self, user_email: str) -> Optional[Any]:
        email = str(user_email)
        try:
            email = _email(user_email)
            manifest = self._manifest(email)
            if manifest:
                credential = self._factory(self._read_payload(email, manifest))
                self._delete(email)
                return credential if self._cleanup_legacy(email) else None

            raw = self._keyring.get_password(SERVICE_NAME, email)
            if raw:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise CredentialIntegrityError(
                        "legacy keyring record is malformed"
                    ) from exc
                if not isinstance(data, dict):
                    raise CredentialIntegrityError(
                        "legacy keyring record is malformed"
                    )
                credential = self._factory(
                    {"schema_version": 1, "user_email": email, **data}
                )
                return credential if self.store_credential(email, credential) else None

            if self._legacy is not None:
                credential = self._legacy.get_credential(email)
                if credential is not None:
                    return (
                        credential
                        if self.store_credential(email, credential)
                        else None
                    )
            return None
        except Exception as exc:
            logger.error("Secure credential read failed for %s: %s", email, exc)
            return None

    def delete_credential(self, user_email: str) -> bool:
        email = str(user_email)
        ok = True
        try:
            email = _email(user_email)
            manifest = self._manifest(email)
            if manifest:
                self._delete_generation(email, manifest)
            self._delete(self._manifest_key(email))
            self._delete(email)
            users = self._users()
            users.discard(email)
            self._save_users(users)
        except Exception as exc:
            logger.error("Secure credential delete failed for %s: %s", email, exc)
            ok = False
        if self._legacy is not None:
            ok = bool(self._legacy.delete_credential(email)) and ok
        return ok

    def list_users(self) -> list[str]:
        try:
            users = self._users()
        except Exception as exc:
            logger.error("Secure user listing failed: %s", exc)
            users = set()
        if self._legacy is not None:
            users.update(self._legacy.list_users())
        return sorted(users)


def install_secure_credential_store() -> ChunkedKeyringCredentialStore:
    """Install the native-only store as the process credential owner."""
    from auth.credential_store import (
        LocalDirectoryCredentialStore,
        _validate_keyring_backend,
        set_credential_store,
    )

    _validate_keyring_backend()
    store = ChunkedKeyringCredentialStore(
        legacy_store=LocalDirectoryCredentialStore()
    )
    set_credential_store(store)
    logger.info("Installed Windows-safe native credential store")
    return store
