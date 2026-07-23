from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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

    def test_bootstrap_disables_dotenv_before_importing_server(self) -> None:
        source = (ROOT / "secure_main.py").read_text(encoding="utf-8")
        self.assertLess(
            source.index('PYTHON_DOTENV_DISABLED", "1"'),
            source.index("from main import main as upstream_main"),
        )
        self.assertLess(
            source.index("install_secure_credential_store()"),
            source.index("from main import main as upstream_main"),
        )

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
