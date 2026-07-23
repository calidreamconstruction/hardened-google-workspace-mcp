"""Native-keyring credential storage with Windows-safe chunking.

The existing OAuth credential payload can exceed Windows Credential Manager's
per-entry size limit. This module stores the payload as verified chunks and
commits a small manifest last. It never writes a new plaintext token file.
"""
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
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_GENERATION_RE = re.compile(r"[0-9a-f]{24}")


class CredentialIntegrityError(RuntimeError):
    """Raised when a keyring record is incomplete or has been altered."""


def _credential_payload(user_email: str, credentials: Any) -> dict[str, Any]:
    expiry = getattr(credentials, "expiry", None)
    return {
        "schema_version": SCHEMA_VERSION,
        "user_email": user_email,
        "token": getattr(credentials, "token", None),
        "refresh_token": getattr(credentials, "refresh_token", None),
        "token_uri": getattr(credentials, "token_uri", None),
        "client_id": getattr(credentials, "client_id", None),
        "client_secret": getattr(credentials, "client_secret", None),
        "scopes": list(getattr(credentials, "scopes", None) or []),
        "expiry": expiry.isoformat() if expiry else None,
    }


def _default_credential_factory(payload: dict[str, Any]) -> Any:
    from google.oauth2.credentials import Credentials

    expiry = None
    if payload.get("expiry"):
        expiry = datetime.fromisoformat(str(payload["expiry"]))
        if expiry.tzinfo is not None:
            expiry = expiry.replace(tzinfo=None)
    return Credentials(
        token=payload.get("token"),
        refresh_token=payload.get("refresh_token"),
        token_uri=payload.get("token_uri"),
        client_id=payload.get("client_id"),
        client_secret=payload.get("client_secret"),
        scopes=payload.get("scopes"),
        expiry=expiry,
    )


class ChunkedKeyringCredentialStore:
    """Store OAuth credentials only in a validated native keyring backend."""

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
        self._legacy_store = legacy_store
        self._credential_factory = credential_factory or _default_credential_factory

    @staticmethod
    def _identity(user_email: str) -> str:
        normalized = user_email.strip().casefold()
        if not normalized or len(normalized) > 320:
            raise ValueError("valid user email required")
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]

    def _manifest_key(self, user_email: str) -> str:
        return f"__credential__:{self._identity(user_email)}:manifest"

    def _chunk_key(self, user_email: str, generation: str, index: int) -> str:
        return (
            f"__credential__:{self._identity(user_email)}:"
            f"{generation}:{index:03d}"
        )

    def _delete_password(self, username: str) -> None:
        try:
            self._keyring.delete_password(SERVICE_NAME, username)
        except Exception as exc:
            if type(exc).__name__ != "PasswordDeleteError":
                raise

    def _users(self) -> set[str]:
        raw = self._keyring.get_password(SERVICE_NAME, USERS_KEY)
        if not raw:
            return set()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError(
                "keyring user registry is malformed"
            ) from exc
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise CredentialIntegrityError("keyring user registry is malformed")
        return set(value)

    def _save_users(self, users: set[str]) -> None:
        raw = json.dumps(sorted(users), separators=(",", ":"))
        self._keyring.set_password(SERVICE_NAME, USERS_KEY, raw)
        if self._keyring.get_password(SERVICE_NAME, USERS_KEY) != raw:
            raise CredentialIntegrityError(
                "keyring user registry verification failed"
            )

    def _parse_manifest(self, raw: str) -> dict[str, Any]:
        try:
            manifest = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError(
                "credential manifest is malformed"
            ) from exc
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema_version") != SCHEMA_VERSION
        ):
            raise CredentialIntegrityError("credential manifest schema is invalid")
        generation = manifest.get("generation")
        digest = manifest.get("sha256")
        chunks = manifest.get("chunks")
        if (
            not isinstance(generation, str)
            or not _GENERATION_RE.fullmatch(generation)
        ):
            raise CredentialIntegrityError("credential generation is invalid")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise CredentialIntegrityError("credential digest is invalid")
        if (
            isinstance(chunks, bool)
            or not isinstance(chunks, int)
            or not 1 <= chunks <= MAX_CHUNKS
        ):
            raise CredentialIntegrityError("credential chunk count is invalid")
        return manifest

    def _manifest(self, user_email: str) -> dict[str, Any] | None:
        raw = self._keyring.get_password(
            SERVICE_NAME, self._manifest_key(user_email)
        )
        return self._parse_manifest(raw) if raw else None

    def _payload_from_manifest(
        self, user_email: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        parts: list[str] = []
        for index in range(manifest["chunks"]):
            part = self._keyring.get_password(
                SERVICE_NAME,
                self._chunk_key(user_email, manifest["generation"], index),
            )
            if not isinstance(part, str):
                raise CredentialIntegrityError("credential chunk is missing")
            parts.append(part)
        raw = "".join(parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if digest != manifest["sha256"]:
            raise CredentialIntegrityError("credential digest mismatch")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError(
                "credential payload is malformed"
            ) from exc
        if not isinstance(payload, dict):
            raise CredentialIntegrityError("credential payload is malformed")
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise CredentialIntegrityError("credential payload schema is invalid")
        if payload.get("user_email") != user_email:
            raise CredentialIntegrityError("credential identity mismatch")
        return payload

    def _delete_generation(
        self, user_email: str, manifest: dict[str, Any]
    ) -> None:
        for index in range(manifest["chunks"]):
            self._delete_password(
                self._chunk_key(user_email, manifest["generation"], index)
            )

    def _decode_legacy(self, user_email: str, raw: str) -> Any:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialIntegrityError(
                "legacy keyring credential is malformed"
            ) from exc
        if not isinstance(payload, dict):
            raise CredentialIntegrityError(
                "legacy keyring credential is malformed"
            )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "user_email": user_email,
            **payload,
        }
        return self._credential_factory(payload)

    def store_credential(self, user_email: str, credentials: Any) -> bool:
        user_email = user_email.strip()
        written: list[str] = []
        manifest_key = ""
        old_manifest_raw: str | None = None
        old_manifest: dict[str, Any] | None = None
        generation = ""
        committed = False
        try:
            self._identity(user_email)
            payload = _credential_payload(user_email, credentials)
            raw = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            generation = digest[:24]
            chunks = [
                raw[offset : offset + CHUNK_SIZE]
                for offset in range(0, len(raw), CHUNK_SIZE)
            ]
            if not chunks or len(chunks) > MAX_CHUNKS:
                raise CredentialIntegrityError("credential payload is too large")

            manifest_key = self._manifest_key(user_email)
            old_manifest_raw = self._keyring.get_password(
                SERVICE_NAME, manifest_key
            )
            if old_manifest_raw:
                try:
                    old_manifest = self._parse_manifest(old_manifest_raw)
                except CredentialIntegrityError:
                    old_manifest = None

            for index, part in enumerate(chunks):
                key = self._chunk_key(user_email, generation, index)
                self._keyring.set_password(SERVICE_NAME, key, part)
                written.append(key)
                if self._keyring.get_password(SERVICE_NAME, key) != part:
                    raise CredentialIntegrityError(
                        "credential chunk verification failed"
                    )

            manifest = {
                "schema_version": SCHEMA_VERSION,
                "generation": generation,
                "chunks": len(chunks),
                "sha256": digest,
            }
            manifest_raw = json.dumps(
                manifest, sort_keys=True, separators=(",", ":")
            )
            self._keyring.set_password(
                SERVICE_NAME, manifest_key, manifest_raw
            )
            if (
                self._keyring.get_password(SERVICE_NAME, manifest_key)
                != manifest_raw
            ):
                raise CredentialIntegrityError(
                    "credential manifest verification failed"
                )
            verified = self._payload_from_manifest(user_email, manifest)
            if verified.get("refresh_token") != payload.get("refresh_token"):
                raise CredentialIntegrityError(
                    "credential round-trip verification failed"
                )

            users = self._users()
            users.add(user_email)
            self._save_users(users)
            committed = True
        except Exception as exc:
            logger.error(
                "Secure keyring credential write failed for %s: %s",
                user_email,
                exc,
            )
            if manifest_key:
                try:
                    if old_manifest_raw is not None:
                        self._keyring.set_password(
                            SERVICE_NAME, manifest_key, old_manifest_raw
                        )
                    else:
                        self._delete_password(manifest_key)
                except Exception:
                    pass
            preserve_written = bool(
                old_manifest
                and old_manifest.get("generation") == generation
            )
            if not preserve_written:
                for key in written:
                    try:
                        self._delete_password(key)
                    except Exception:
                        pass
            return False

        if committed:
            if old_manifest and old_manifest["generation"] != generation:
                try:
                    self._delete_generation(user_email, old_manifest)
                except Exception as exc:
                    logger.warning(
                        "Could not remove old keyring generation for %s: %s",
                        user_email,
                        exc,
                    )
            try:
                self._delete_password(user_email)
            except Exception as exc:
                logger.warning(
                    "Could not remove legacy keyring record for %s: %s",
                    user_email,
                    exc,
                )
            return True
        return False

    def get_credential(self, user_email: str) -> Optional[Any]:
        try:
            user_email = user_email.strip()
            manifest = self._manifest(user_email)
            if manifest is not None:
                return self._credential_factory(
                    self._payload_from_manifest(user_email, manifest)
                )

            legacy_raw = self._keyring.get_password(
                SERVICE_NAME, user_email
            )
            if legacy_raw:
                credential = self._decode_legacy(user_email, legacy_raw)
                if not self.store_credential(user_email, credential):
                    return None
                return credential

            if self._legacy_store is not None:
                credential = self._legacy_store.get_credential(user_email)
                if credential is not None:
                    if not self.store_credential(user_email, credential):
                        return None
                    if not self._legacy_store.delete_credential(user_email):
                        logger.error(
                            "Migrated %s to keyring but could not remove "
                            "legacy file",
                            user_email,
                        )
                        return None
                    return credential
            return None
        except Exception as exc:
            logger.error(
                "Secure keyring credential read failed for %s: %s",
                user_email,
                exc,
            )
            return None

    def delete_credential(self, user_email: str) -> bool:
        ok = True
        try:
            manifest = self._manifest(user_email)
            if manifest is not None:
                self._delete_generation(user_email, manifest)
            self._delete_password(self._manifest_key(user_email))
            self._delete_password(user_email)
            users = self._users()
            users.discard(user_email)
            self._save_users(users)
        except Exception as exc:
            logger.error(
                "Secure keyring credential delete failed for %s: %s",
                user_email,
                exc,
            )
            ok = False
        if self._legacy_store is not None:
            ok = self._legacy_store.delete_credential(user_email) and ok
        return ok

    def list_users(self) -> list[str]:
        try:
            users = self._users()
        except Exception as exc:
            logger.error("Secure keyring user listing failed: %s", exc)
            users = set()
        if self._legacy_store is not None:
            users.update(self._legacy_store.list_users())
        return sorted(users)


def install_secure_credential_store() -> ChunkedKeyringCredentialStore:
    """Install the native-only store as the canonical process credential owner."""
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
    logger.info("Installed Windows-safe chunked native credential store")
    return store
