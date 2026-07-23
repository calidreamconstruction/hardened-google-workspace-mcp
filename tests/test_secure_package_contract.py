from __future__ import annotations

import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURE_MAIN_PATH = ROOT / "secure_main.py"
SPEC = importlib.util.spec_from_file_location("secure_main", SECURE_MAIN_PATH)
assert SPEC and SPEC.loader
SECURE_MAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURE_MAIN)


class SecurePackageContractTests(unittest.TestCase):
    def test_installed_command_uses_secure_bootstrap(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(
            'hardened-google-workspace-mcp = "secure_main:main"', pyproject
        )
        self.assertIn('version = "1.8.0"', pyproject)
        self.assertIn('"python-dotenv>=1.2.2"', pyproject)
        self.assertIn(
            "github.com/calidreamconstruction/hardened-google-workspace-mcp",
            pyproject,
        )

    def test_bootstrap_enforces_security_before_importing_server(self) -> None:
        source = SECURE_MAIN_PATH.read_text(encoding="utf-8")
        import_main = source.index("from main import main as upstream_main")
        for required in (
            'PYTHON_DOTENV_DISABLED", "1"',
            "validated_client_secret_path(",
            'os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)',
            'os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)',
            "install_secure_credential_store()",
        ):
            self.assertLess(source.index(required), import_main)

    def test_oauth_json_must_be_absolute_existing_and_external(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "required"):
            SECURE_MAIN.validated_client_secret_path(None)
        with self.assertRaisesRegex(RuntimeError, "absolute"):
            SECURE_MAIN.validated_client_secret_path("client_secret.json")

        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "client_secret.json"
            external.write_text("{}", encoding="utf-8")
            self.assertEqual(
                SECURE_MAIN.validated_client_secret_path(str(external)),
                external.resolve(),
            )

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            internal = Path(directory) / "client_secret.json"
            internal.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "outside the checkout"):
                SECURE_MAIN.validated_client_secret_path(str(internal))

    def test_secure_store_has_no_plaintext_write_path(self) -> None:
        path = ROOT / "auth" / "secure_credential_store.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        forbidden_calls = []
        legacy_writes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "open":
                    forbidden_calls.append(node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value
                if (
                    isinstance(owner, ast.Attribute)
                    and isinstance(owner.value, ast.Name)
                    and owner.value.id == "self"
                    and owner.attr == "_legacy"
                    and node.func.attr == "store_credential"
                ):
                    legacy_writes.append(node.lineno)
        self.assertEqual(forbidden_calls, [])
        self.assertEqual(legacy_writes, [])

    def test_public_setup_has_no_raw_secret_or_mac_only_contract(self) -> None:
        docs = "\n".join(
            (ROOT / name).read_text(encoding="utf-8")
            for name in ("README.md", "SETUP.md", "OAUTH_SETUP.md", "SECURITY.md")
        )
        for forbidden in (
            "github.com/c0webster/google_workspace_mcp",
            "/Users/YOUR_USERNAME",
            '"GOOGLE_OAUTH_CLIENT_SECRET":',
            "GOOGLE_OAUTH_CLIENT_SECRET=",
        ):
            self.assertNotIn(forbidden, docs)
        self.assertIn("GOOGLE_CLIENT_SECRET_PATH", docs)
        self.assertIn("Windows Credential Manager", docs)
        self.assertIn("Desktop app", docs)


if __name__ == "__main__":
    unittest.main()
