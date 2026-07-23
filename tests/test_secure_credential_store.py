from __future__ import annotations

import importlib.util
import json
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "auth" / "secure_credential_store.py"
SPEC = importlib.util.spec_from_file_location(
    "secure_credential_store", MODULE_PATH
)
assert SPEC and SPEC.loader
STORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORE)


class PasswordDeleteError(Exception):
    pass


class FakeKeyring:
    class errors:
        PasswordDeleteError = PasswordDeleteError

    def __init__(self, limit: int = 1000) -> None:
        self.limit = limit
        self.values: dict[tuple[str, str], str] = {}
        self.fail_users_write = False

    def set_password(self, service: str, username: str, value: str) -> None:
        if self.fail_users_write and username == STORE.USERS_KEY:
            raise RuntimeError("user registry unavailable")
        if len(value) > self.limit:
            raise RuntimeError("credential too large")
        self.values[(service, username)] = value

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        key = (service, username)
        if key not in self.values:
            raise PasswordDeleteError(username)
        del self.values[key]


class FakeLegacyStore:
    def __init__(self, credential=None) -> None:
        self.credential = credential
        self.deleted = False
        self.writes = 0

    def get_credential(self, _user_email: str):
        return self.credential

    def store_credential(self, _user_email: str, _credential) -> bool:
        self.writes += 1
        return True

    def delete_credential(self, _user_email: str) -> bool:
        self.deleted = True
        self.credential = None
        return True

    def list_users(self) -> list[str]:
        return ["legacy@example.com"] if self.credential else []


def credential(*, refresh: str = "r" * 3200, token: str = "t" * 400):
    return SimpleNamespace(
        token=token,
        refresh_token=refresh,
        token_uri="https://oauth2.googleapis.com/token",
        client_id="client-id.apps.googleusercontent.com",
        client_secret="client-secret",
        scopes=[f"scope-{index}" for index in range(22)],
        expiry=datetime(2026, 7, 23, 12, 0, 0),
    )


def factory(payload: dict):
    value = dict(payload)
    if isinstance(value.get("expiry"), str):
        value["expiry"] = datetime.fromisoformat(value["expiry"])
    return SimpleNamespace(**value)


class SecureCredentialStoreTests(unittest.TestCase):
    def store(self, *, keyring=None, legacy=None):
        return STORE.ChunkedKeyringCredentialStore(
            keyring_module=keyring or FakeKeyring(),
            legacy_store=legacy,
            credential_factory=factory,
        )

    def test_large_windows_payload_uses_verified_chunks_only(self) -> None:
        keyring = FakeKeyring(limit=1000)
        legacy = FakeLegacyStore()
        store = self.store(keyring=keyring, legacy=legacy)
        original = credential()

        self.assertTrue(store.store_credential("owner@example.com", original))
        manifest_key = store._manifest_key("owner@example.com")
        manifest = json.loads(
            keyring.get_password(STORE.SERVICE_NAME, manifest_key)
        )
        self.assertGreater(manifest["chunks"], 1)
        self.assertEqual(legacy.writes, 0)
        restored = store.get_credential("owner@example.com")
        self.assertEqual(restored.refresh_token, original.refresh_token)
        self.assertNotIn(
            (STORE.SERVICE_NAME, "owner@example.com"), keyring.values
        )

    def test_legacy_single_key_is_migrated(self) -> None:
        keyring = FakeKeyring(limit=1000)
        original = credential(refresh="legacy-refresh")
        legacy_payload = STORE._credential_payload(
            "owner@example.com", original
        )
        legacy_payload.pop("schema_version")
        legacy_payload.pop("user_email")
        keyring.values[(STORE.SERVICE_NAME, "owner@example.com")] = json.dumps(
            legacy_payload
        )
        store = self.store(keyring=keyring)

        restored = store.get_credential("owner@example.com")

        self.assertEqual(restored.refresh_token, "legacy-refresh")
        self.assertIsNotNone(
            keyring.get_password(
                STORE.SERVICE_NAME,
                store._manifest_key("owner@example.com"),
            )
        )
        self.assertIsNone(
            keyring.get_password(STORE.SERVICE_NAME, "owner@example.com")
        )

    def test_plaintext_legacy_store_is_migrated_then_deleted(self) -> None:
        keyring = FakeKeyring(limit=1000)
        legacy = FakeLegacyStore(credential(refresh="file-refresh"))
        store = self.store(keyring=keyring, legacy=legacy)

        restored = store.get_credential("legacy@example.com")

        self.assertEqual(restored.refresh_token, "file-refresh")
        self.assertTrue(legacy.deleted)
        self.assertEqual(legacy.writes, 0)

    def test_missing_chunk_fails_closed(self) -> None:
        keyring = FakeKeyring(limit=1000)
        store = self.store(keyring=keyring)
        self.assertTrue(store.store_credential("owner@example.com", credential()))
        manifest = store._manifest("owner@example.com")
        keyring.delete_password(
            STORE.SERVICE_NAME,
            store._chunk_key(
                "owner@example.com", manifest["generation"], 0
            ),
        )
        self.assertIsNone(store.get_credential("owner@example.com"))

    def test_failed_chunk_write_never_commits_manifest(self) -> None:
        keyring = FakeKeyring(limit=100)
        store = self.store(keyring=keyring)
        self.assertFalse(store.store_credential("owner@example.com", credential()))
        self.assertIsNone(
            keyring.get_password(
                STORE.SERVICE_NAME,
                store._manifest_key("owner@example.com"),
            )
        )

    def test_new_generation_removes_old_chunks(self) -> None:
        keyring = FakeKeyring(limit=1000)
        store = self.store(keyring=keyring)
        self.assertTrue(
            store.store_credential(
                "owner@example.com", credential(refresh="a" * 3200)
            )
        )
        old = store._manifest("owner@example.com")
        old_keys = {
            store._chunk_key(
                "owner@example.com", old["generation"], index
            )
            for index in range(old["chunks"])
        }
        self.assertTrue(
            store.store_credential(
                "owner@example.com", credential(refresh="b" * 3200)
            )
        )
        current_keys = {
            username
            for service, username in keyring.values
            if service == STORE.SERVICE_NAME
        }
        self.assertFalse(old_keys & current_keys)

    def test_failed_user_registry_update_restores_old_generation(self) -> None:
        keyring = FakeKeyring(limit=1000)
        store = self.store(keyring=keyring)
        self.assertTrue(
            store.store_credential(
                "owner@example.com", credential(refresh="old" * 1000)
            )
        )
        old_manifest = keyring.get_password(
            STORE.SERVICE_NAME,
            store._manifest_key("owner@example.com"),
        )
        keyring.fail_users_write = True

        self.assertFalse(
            store.store_credential(
                "owner@example.com", credential(refresh="new" * 1000)
            )
        )
        self.assertEqual(
            keyring.get_password(
                STORE.SERVICE_NAME,
                store._manifest_key("owner@example.com"),
            ),
            old_manifest,
        )
        restored = store.get_credential("owner@example.com")
        self.assertEqual(restored.refresh_token, "old" * 1000)

    def test_secure_entrypoint_disables_dotenv_before_importing_main(self) -> None:
        source = (ROOT / "secure_main.py").read_text(encoding="utf-8")
        disable = source.index('PYTHON_DOTENV_DISABLED", "1"')
        import_main = source.index("from main import main as upstream_main")
        self.assertLess(disable, import_main)


if __name__ == "__main__":
    unittest.main()
