"""Security-first executable entrypoint for Hardened Google Workspace MCP."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Sequence

_DOTENV_DISABLE = ("PYTHON_DOTENV_DISABLED", "1")


def validated_client_secret_path(raw: str | None) -> Path:
    """Require an existing absolute OAuth JSON path outside the checkout."""
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError("GOOGLE_CLIENT_SECRET_PATH is required")
    candidate = Path(raw.strip()).expanduser()
    if not candidate.is_absolute():
        raise RuntimeError("GOOGLE_CLIENT_SECRET_PATH must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("OAuth client JSON is not readable") from exc
    if not resolved.is_file():
        raise RuntimeError("OAuth client JSON path is not a file")

    checkout = Path(__file__).resolve().parent
    if resolved == checkout or checkout in resolved.parents:
        raise RuntimeError("OAuth client JSON must be stored outside the checkout")
    return resolved


def disable_dotenv_loading() -> None:
    """Prevent the legacy server import from reading any dotenv file or stream."""
    import dotenv

    def disabled_load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
        return False

    dotenv.load_dotenv = disabled_load_dotenv


def validate_runtime_arguments(argv: Sequence[str]) -> None:
    """Keep the hardened executable on its supported local stdio boundary."""
    arguments = list(argv[1:])
    if "--single-user" not in arguments:
        raise RuntimeError("hardened entrypoint requires --single-user")

    transport = "stdio"
    for index, argument in enumerate(arguments):
        if argument == "--transport":
            if index + 1 >= len(arguments):
                raise RuntimeError("--transport requires a value")
            transport = arguments[index + 1]
        elif argument.startswith("--transport="):
            transport = argument.split("=", 1)[1]
    if transport != "stdio":
        raise RuntimeError("hardened entrypoint supports stdio transport only")


def main() -> object:
    # The supported runtime never imports repository-local dotenv values or raw
    # OAuth client credentials from process variables.
    validate_runtime_arguments(sys.argv)
    os.environ[_DOTENV_DISABLE[0]] = _DOTENV_DISABLE[1]
    disable_dotenv_loading()
    secret_path = validated_client_secret_path(
        os.environ.get("GOOGLE_CLIENT_SECRET_PATH")
    )
    os.environ["GOOGLE_CLIENT_SECRET_PATH"] = str(secret_path)
    os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)

    from auth.secure_credential_store import install_secure_credential_store

    install_secure_credential_store()

    from main import main as upstream_main

    return upstream_main()


if __name__ == "__main__":
    main()
