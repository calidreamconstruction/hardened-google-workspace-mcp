"""Security-first executable entrypoint for Hardened Google Workspace MCP."""
from __future__ import annotations

import os


def main() -> object:
    # The public runtime must not silently import repository-local secrets.
    os.environ.setdefault("PYTHON_DOTENV_DISABLED", "1")

    from auth.secure_credential_store import install_secure_credential_store

    install_secure_credential_store()

    from main import main as upstream_main

    return upstream_main()


if __name__ == "__main__":
    main()
