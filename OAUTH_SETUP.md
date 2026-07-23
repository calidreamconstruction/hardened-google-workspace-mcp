# Create Google OAuth Desktop Credentials

This guide creates the OAuth client used by the local hardened Workspace MCP server. The downloaded JSON is stored outside the Git repository and passed to the process by absolute path.

## 1. Create or select a Google Cloud project

1. Open Google Cloud Console.
2. Select an existing project or create a dedicated project such as `Claude Workspace MCP`.
3. Record the exact Google account and project being configured.

## 2. Enable only the APIs you use

Enable the APIs for the tool groups you intend to expose:

- Gmail API
- Google Drive API
- Google Docs API
- Google Sheets API
- Google Calendar API
- Google Forms API
- Google Slides API

Disabling a tool group in the server reduces the requested scope set; APIs that are not used do not need to be enabled.

## 3. Configure the OAuth consent screen

1. Open **Google Auth Platform** or **APIs & Services → OAuth consent screen**.
2. Choose **Internal** for a Workspace-only organizational integration when available, otherwise choose **External**.
3. Set an accurate application name, support email, and developer contact.
4. For an External app in Testing mode, add the exact Google accounts that may authorize it.
5. Save the configuration.

The server requests scopes dynamically for enabled tool groups. Review the consent screen at authorization time and deny scopes or accounts you did not intend to use.

## 4. Create a Desktop app client

1. Open **APIs & Services → Credentials**.
2. Select **Create credentials → OAuth client ID**.
3. Choose **Desktop app**.
4. Use a recognizable name such as `Hardened Workspace MCP - PC`.
5. Create the client.
6. Select **Download JSON**.

Do not paste the displayed client secret into Claude configuration. The downloaded JSON already contains the client ID and client secret in the format expected by Google's installed-app flow.

## 5. Store the JSON outside the repository

### Windows PowerShell

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

Pass the resulting absolute path as `GOOGLE_CLIENT_SECRET_PATH`. Continue with [SETUP.md](./SETUP.md).

## 6. Verify authorization

On the first Google Workspace tool call:

1. Confirm the browser shows the intended Google Cloud project and OAuth client.
2. Confirm the signed-in Google account is the intended account.
3. Review the requested scopes.
4. Complete consent.
5. Return to Claude Code and verify the tool result.

Google supports granular consent. The application must tolerate missing scopes by disabling or failing the affected tool rather than assuming every requested permission was granted.

## Troubleshooting

### `Access blocked` or `request is invalid`

Confirm:

- OAuth client type is **Desktop app**;
- the consent screen is complete;
- the current user is an allowed test user;
- every required API is enabled;
- the JSON path points to the downloaded file for the intended project.

### `This app isn't verified`

A private External app in Testing mode can show an unverified-app warning. Use only a project and OAuth client you control. Public distribution may require Google's verification process.

### Wrong account or scopes

Revoke the application in Google Account permissions and authorize again with the correct account. Do not reuse a token from another Google account or OAuth project.

### Client JSON exposed

Treat a committed or disclosed client secret as compromised. Create a replacement OAuth client, update the external JSON path, verify authorization, and revoke/delete the old client only after the replacement works.

## Security rules

- Never commit the OAuth JSON.
- Never paste `client_secret` into chat, logs, issues, `.mcp.json`, or `~/.claude.json`.
- Never place the JSON under the repository root.
- Keep the OAuth project in Testing mode unless public verification and policy requirements are intentionally completed.
- Periodically review Google Account permissions and remove unused clients.
