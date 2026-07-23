# Cross-Platform Setup

This guide installs the hardened local MCP server without placing OAuth secrets in the repository or in Claude's MCP JSON.

## 1. Install prerequisites

Required:

- Python 3.10+
- Git
- `uv`
- Claude Code
- A browser for Google consent
- A supported native keyring backend

Verify:

```powershell
python --version
uv --version
claude --version
```

## 2. Clone the maintained fork

### Windows PowerShell

```powershell
$Repo = Join-Path $HOME "src\hardened-google-workspace-mcp"
git clone https://github.com/calidreamconstruction/hardened-google-workspace-mcp.git $Repo
Set-Location $Repo
uv sync
```

### macOS or Linux

```bash
repo="$HOME/src/hardened-google-workspace-mcp"
git clone https://github.com/calidreamconstruction/hardened-google-workspace-mcp.git "$repo"
cd "$repo"
uv sync
```

## 3. Create and store the OAuth Desktop-app JSON

Complete [OAUTH_SETUP.md](./OAUTH_SETUP.md), then download the OAuth client JSON.

### Windows

```powershell
$SecretDir = Join-Path $env:LOCALAPPDATA "hardened-google-workspace-mcp"
$SecretPath = Join-Path $SecretDir "client_secret.json"
New-Item -ItemType Directory -Force $SecretDir | Out-Null
Copy-Item "C:\Path\To\Downloaded\client_secret.json" $SecretPath
```

### macOS or Linux

```bash
secret_dir="${XDG_CONFIG_HOME:-$HOME/.config}/hardened-google-workspace-mcp"
mkdir -p "$secret_dir"
cp /path/to/downloaded/client_secret.json "$secret_dir/client_secret.json"
chmod 600 "$secret_dir/client_secret.json"
```

The file must remain outside the Git checkout. Never paste `client_secret` into `.mcp.json`, `~/.claude.json`, issue comments, logs, shell history, or chat.

## 4. Register the MCP server

### Windows PowerShell

```powershell
claude mcp add `
  --transport stdio `
  --scope user `
  --env "GOOGLE_CLIENT_SECRET_PATH=$SecretPath" `
  hardened-workspace `
  -- uv run --directory $Repo hardened-google-workspace-mcp --single-user
```

### macOS or Linux

```bash
claude mcp add \
  --transport stdio \
  --scope user \
  --env "GOOGLE_CLIENT_SECRET_PATH=$secret_dir/client_secret.json" \
  hardened-workspace \
  -- uv run --directory "$repo" hardened-google-workspace-mcp --single-user
```

Use user scope for a private machine-wide utility. Do not commit a user-specific OAuth path to a project `.mcp.json`.

## 5. Verify the exact definition

```powershell
claude mcp get hardened-workspace
claude mcp list
```

Confirm:

- command is `uv`;
- repository path is the current local clone;
- executable is `hardened-google-workspace-mcp`;
- `--single-user` is present;
- environment contains only `GOOGLE_CLIENT_SECRET_PATH`, not a secret value.

## 6. Authorize Google

Open Claude Code, run `/mcp`, and invoke one read-only Workspace tool. Complete the browser consent flow with the intended Google account.

After consent:

- access and refresh tokens are written to the native credential manager;
- Windows payloads are split into verified chunks;
- the manifest is committed only after every chunk round-trips correctly;
- missing or altered chunks fail closed;
- no new plaintext token file is created.

## 7. Upgrade an existing PC installation

```powershell
Set-Location $Repo
git pull --ff-only
uv sync
claude mcp get hardened-workspace
```

Restart Claude Code after changing the executable definition.

Version 1.8.0 can migrate:

1. a legacy one-entry keyring record; or
2. a v1.7.1 local JSON fallback record.

Migration writes and verifies the chunked native-keyring record first. The legacy record is removed afterward. If the secure commit or local-file deletion fails, the operation fails closed.

## Troubleshooting

### `Untrusted keyring backend`

The runtime refuses plaintext or unknown keyring backends. Use Windows Credential Manager, macOS Keychain, Linux SecretService, or KWallet.

### `credential chunk is missing` or `digest mismatch`

The stored generation is incomplete or corrupted. Do not bypass the integrity check. Revoke the app at Google Account permissions, remove the affected native credential entries, and authorize again.

### Browser does not open

Use the authorization URL printed by the local server. Confirm the OAuth client type is **Desktop app** and the current account is an allowed test user.

### Server closes immediately

Run the canonical command directly:

```powershell
uv run --directory $Repo hardened-google-workspace-mcp --single-user
```

Fix the first startup error, then recheck `claude mcp get hardened-workspace`.

### Remove the server definition

```powershell
claude mcp remove hardened-workspace
```

Removing the MCP definition does not revoke Google access. Revoke the application separately in your Google Account permissions when decommissioning it.
