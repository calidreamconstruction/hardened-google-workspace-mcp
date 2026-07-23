# Hardened Google Workspace MCP

A security-focused local Google Workspace MCP server for Claude Code on Windows, macOS, and Linux.

This project is maintained at [calidreamconstruction/hardened-google-workspace-mcp](https://github.com/calidreamconstruction/hardened-google-workspace-mcp) and is based on [taylorwilsdon/google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp). See [SECURITY.md](./SECURITY.md) for the exact threat model and remaining risks.

## Capabilities

- **Gmail:** read and search mail, manage labels, create and update drafts; no send tool
- **Drive:** read, search, create, and edit files; no external sharing tool
- **Docs, Sheets, Slides, and Forms:** read and edit supported content
- **Calendar:** read and manage events; attendee creation is removed

## Security differences

- No Gmail send operation
- No Gmail filter or forwarding-rule creation
- No Drive external-sharing operation
- No calendar attendee invitation operation
- No Drive or Gmail trash operation
- OAuth tokens stored in a validated native credential manager
- Windows-safe chunking prevents Credential Manager size limits from creating plaintext fallback files
- Each generation is SHA-256 verified before its manifest is committed
- Existing legacy keyring records and v1.7.1 local token files are migrated on first successful read; the local file is deleted only after the native-keyring write verifies
- The installed executable disables automatic repository `.env` loading before importing the server

This narrows risk; it does not make untrusted email or document content safe. Review tool calls and treat external content as untrusted data, not instructions.

## Requirements

- Python 3.10 or newer
- [uv](https://docs.astral.sh/uv/)
- Claude Code
- A Google account and a Google Cloud OAuth **Desktop app** client
- A supported native credential manager:
  - Windows Credential Manager
  - macOS Keychain
  - Linux SecretService or KWallet

The server fails closed if the active keyring backend is not trusted.

## Windows PC quick start

### 1. Clone and install

```powershell
$Repo = Join-Path $HOME "src\hardened-google-workspace-mcp"
git clone https://github.com/calidreamconstruction/hardened-google-workspace-mcp.git $Repo
Set-Location $Repo
uv sync
```

### 2. Create the Google OAuth client

Follow [OAUTH_SETUP.md](./OAUTH_SETUP.md), create a **Desktop app** OAuth client, and download its JSON file. Do not copy the client secret into Claude configuration.

Store the downloaded JSON outside the repository:

```powershell
$SecretDir = Join-Path $env:LOCALAPPDATA "hardened-google-workspace-mcp"
$SecretPath = Join-Path $SecretDir "client_secret.json"
New-Item -ItemType Directory -Force $SecretDir | Out-Null
Copy-Item "C:\Path\To\Downloaded\client_secret.json" $SecretPath
```

### 3. Register the local MCP server

Claude Code requires its options before the server name and uses `--` to separate the server command:

```powershell
claude mcp add `
  --transport stdio `
  --scope user `
  --env "GOOGLE_CLIENT_SECRET_PATH=$SecretPath" `
  hardened-workspace `
  -- uv run --directory $Repo hardened-google-workspace-mcp --single-user
```

The MCP definition contains only the path to the OAuth JSON file, not the client secret value.

### 4. Verify and authorize

```powershell
claude mcp get hardened-workspace
claude mcp list
```

Open Claude Code, run `/mcp`, and use a Google Workspace tool. The first request opens the Google authorization flow. After consent, refresh and access tokens are stored in Windows Credential Manager as verified chunks.

## macOS or Linux quick start

```bash
repo="$HOME/src/hardened-google-workspace-mcp"
git clone https://github.com/calidreamconstruction/hardened-google-workspace-mcp.git "$repo"
cd "$repo"
uv sync

secret_dir="${XDG_CONFIG_HOME:-$HOME/.config}/hardened-google-workspace-mcp"
mkdir -p "$secret_dir"
cp /path/to/downloaded/client_secret.json "$secret_dir/client_secret.json"

claude mcp add \
  --transport stdio \
  --scope user \
  --env "GOOGLE_CLIENT_SECRET_PATH=$secret_dir/client_secret.json" \
  hardened-workspace \
  -- uv run --directory "$repo" hardened-google-workspace-mcp --single-user
```

Linux requires a running SecretService or KWallet backend. The server intentionally rejects plaintext keyring backends.

## Existing installations

Upgrade and restart Claude Code:

```powershell
Set-Location $Repo
git pull --ff-only
uv sync --locked
```

The hardened runtime no longer writes oversized Windows OAuth payloads to `~/.google_workspace_mcp/credentials`. If a v1.7.1 plaintext fallback file exists, the secure store reads it once, commits and verifies the chunked native-keyring generation, then removes the file. If migration or deletion cannot be proven, authentication fails closed and the file is retained for recovery rather than silently discarded.

## Example prompts

```text
List my recent emails from the past week.
Create a Gmail draft replying to the latest customer message.
Read the document named Q4 Planning.
Show my calendar for next Monday.
Update cell A1 in the Budget spreadsheet.
```

## Troubleshooting

### OAuth client not found

Confirm `GOOGLE_CLIENT_SECRET_PATH` is an absolute path to the downloaded Desktop-app JSON file and that the current Windows user can read it.

### Untrusted keyring backend

Install or start a supported native credential manager. Do not install `keyrings.alt` or enable plaintext credential storage.

### Authorization must be repeated

Check the server logs for a credential integrity or migration error. A missing chunk, digest mismatch, malformed manifest, or unverifiable migration is rejected instead of falling back to a token file.

### MCP connection closed

Run the exact command outside Claude Code:

```powershell
uv run --directory $Repo hardened-google-workspace-mcp --single-user
```

Then verify `claude mcp get hardened-workspace` points to the same absolute repository and OAuth JSON paths.

## Development

```bash
uv sync --locked --group dev
uv run --locked python -m py_compile auth/secure_credential_store.py secure_main.py
uv run --locked python tests/test_secure_credential_store.py -q
uv run --locked python tests/test_secure_package_contract.py -q
```

## Support

Report defects at [calidreamconstruction/hardened-google-workspace-mcp/issues](https://github.com/calidreamconstruction/hardened-google-workspace-mcp/issues). Never include OAuth client JSON, tokens, credentials, or raw tool output containing private Workspace data.

---

Based on `google_workspace_mcp` by Taylor Wilsdon and licensed under MIT.
