# Security Model

Hardened Google Workspace MCP reduces the Google Workspace actions available to an AI client and protects OAuth tokens at rest. It does not make untrusted email, documents, links, or prompts safe.

## Threat model

Assume that content read from Gmail, Drive, Docs, Sheets, Forms, Slides, and Calendar can contain malicious instructions intended to manipulate the model. Retrieved content is data, not authority.

The hardening boundary covers this MCP server only. Claude Code may also have browser, shell, file, network, plugin, or other MCP capabilities that can move data outside Google Workspace.

## Removed high-risk operations

The maintained fork removes or blocks these Google Workspace operations:

- sending Gmail messages;
- creating Gmail filters or forwarding rules;
- sharing Drive files with external identities;
- adding Calendar attendees;
- moving Gmail messages or Drive files to trash;
- operations that expose or mutate unsupported Chat, Tasks, or Search surfaces.

Gmail draft creation remains available, but sending requires a separate user action in Gmail.

## OAuth client configuration

Use a Google OAuth **Desktop app** JSON file through `GOOGLE_CLIENT_SECRET_PATH`.

- Store the JSON outside the Git repository.
- Pass only its absolute path to the MCP process.
- Do not paste `client_secret` into `.mcp.json`, `~/.claude.json`, issue comments, logs, shell history, or chat.
- Revoke and replace the OAuth client if its secret was committed or disclosed.

The installed `hardened-google-workspace-mcp` command enters through `secure_main.py`, which sets `PYTHON_DOTENV_DISABLED=1` before importing the upstream server. Repository-local `.env` loading is therefore disabled on the supported entrypoint.

Running `python -m main` is a legacy bypass and is not covered by this secure-entrypoint guarantee. Use the installed command or `python -m secure_main`.

## OAuth token storage

OAuth access and refresh tokens are stored in a validated native credential manager:

- Windows Credential Manager;
- macOS Keychain;
- Linux SecretService or KWallet.

Plaintext, null, chainer, and unknown keyring backends are rejected at startup.

### Windows-safe chunking

A Google OAuth payload can exceed the per-entry size accepted by Windows Credential Manager. Version 1.8.0 does not fall back to a new token file. It:

1. serializes the credential with an explicit schema and user identity;
2. splits it into bounded keyring chunks;
3. writes and reads back every chunk;
4. computes and verifies SHA-256 over the complete payload;
5. commits a small generation manifest last;
6. updates the user registry only after the manifest round-trip succeeds;
7. removes the previous generation after the new generation is committed.

A missing chunk, malformed manifest, wrong identity, unsupported schema, or digest mismatch fails closed.

### Legacy migration

The secure store can migrate:

- the previous single-entry native-keyring record; and
- the v1.7.1 local JSON fallback record under the legacy credentials directory.

Migration order is secure-store write, chunk and digest verification, manifest commit, registry commit, then legacy deletion. If secure storage cannot be proven, authentication fails and the legacy record remains available for recovery. If local-file deletion cannot be proven, the read also fails rather than silently claiming the plaintext copy was removed.

The secure store never calls the legacy store's write method.

## Integrity and failure behavior

- New chunks are generation-addressed so readers continue to see the previous committed generation until the new manifest is written.
- A failed registry update restores the previous manifest and removes uncommitted chunks.
- Missing or altered chunks are not reconstructed from plaintext.
- Credential values are never printed by the secure store.
- The user registry and manifest are read back after writes.
- Deletion removes the committed generation, manifest, prior single-entry record, user registry entry, and any legacy local record.

## Remaining risks

Hardening cannot prevent every data path. Important remaining risks include:

- writing sensitive content into a folder already shared externally;
- editing a document controlled by an external identity;
- the model copying Workspace data through another network, browser, shell, or MCP tool;
- overly broad OAuth scopes needed by enabled read/write tools;
- a compromised operating-system account reading data available to that user;
- a malicious dependency or modified local checkout;
- users approving the wrong Google account or OAuth scopes.

Use a dedicated Google account when appropriate, enable only required tool groups, review provider consent, and monitor Google account activity.

## Supported deployment boundary

Security claims in this document require:

- the maintained fork from `calidreamconstruction/hardened-google-workspace-mcp`;
- the `hardened-google-workspace-mcp` or `python -m secure_main` entrypoint;
- an external OAuth Desktop-app JSON path;
- a trusted native keyring backend;
- unmodified hardening guards and tool registry.

## Reporting a vulnerability

Open a private security advisory or contact the repository owner without including OAuth client JSON, access tokens, refresh tokens, private Workspace content, or raw credential-manager exports.

Repository issues: https://github.com/calidreamconstruction/hardened-google-workspace-mcp/issues
