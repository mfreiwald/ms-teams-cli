# Teams Graph Token Grabber

A minimal Chrome extension (Manifest V3) that captures the **Microsoft Graph**
access token from your active Teams / Office web session and lets you copy it —
or a ready-to-paste `teams auth login --token` command — from the toolbar popup.

It exists to feed [`teams-cli`](../README.md): the CLI talks to
`graph.microsoft.com`, so it needs a token whose audience is Microsoft Graph.
This extension grabs exactly that token.

## What it does

- Observes requests to `https://graph.microsoft.com/*` (and the MCAS-proxied
  `https://graph.microsoft.com.mcas.ms/*`) and reads the `Authorization:
  Bearer …` header (non-blocking; it never modifies traffic).
- Decodes the JWT (unverified) and keeps the **freshest, non-expired Graph
  token** — tokens for other audiences (e.g. the Outlook/substrate token behind
  `outlook.office.com/owa/service.svc`) are ignored, because Graph rejects them.
- Shows a toolbar badge with the remaining lifetime (e.g. `58m`, red under 5
  minutes) and a popup with the user, audience, expiry countdown, and scopes.
- One click to **Copy token** or **Copy `login --token` command**.

## Install (load unpacked)

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select this `chrome-extension/` folder.
4. Pin the extension so its toolbar icon is visible.

## Use

1. Open **teams.microsoft.com** (or Outlook web) and sign in.
2. Click around a little so the app calls Graph.
3. Click the extension icon → the token and its details appear.
4. **Copy `login --token` command** and paste it into your terminal:

   ```bash
   teams auth login --token 'eyJ0…'
   ```

   or copy just the token and pipe it (keeps it out of shell history):

   ```bash
   pbpaste | teams auth login --token
   ```
5. Verify the CLI accepted a Graph token:

   ```bash
   teams auth status --output json    # expect "is_graph_audience": true
   ```

## Security

- The token is a live credential. It is kept in `chrome.storage.session`
  (in memory only) and is **wiped when Chrome closes** — nothing is written to
  disk by this extension.
- Host access is scoped to `https://graph.microsoft.com/*` only.
- The token still expires (typically ~1 hour) and has **no refresh token**, so
  re-capture and re-run `teams auth login --token` when it lapses. For a
  long-lived session, use `teams auth login` / `--device-code` instead.

## Troubleshooting

**No token appears.** The extension only sees a token once the browser actually
requests Microsoft Graph. Open **teams.microsoft.com** *and* **Outlook web**,
click around (open chats, calendar, people), and give it a few seconds.

**Tenant behind MCAS / Defender for Cloud Apps.** Conditional-access app control
rewrites hosts by appending `.mcas.ms` (e.g. `graph.microsoft.com.mcas.ms`).
Both variants are covered out of the box. If your tenant uses a different suffix
(you'll see it in the address bar), add it in two places and reload the
extension:

- `manifest.json` → `host_permissions`
- `background.js` → the `urls` array of the `onBeforeSendHeaders` listener

The captured token is still a genuine Graph token (MCAS only proxies the
connection; the token's audience stays `https://graph.microsoft.com`), so
`teams-cli` uses it against the real Graph endpoint.

**Why not the `outlook.office.com` token?** That token's audience is the
Outlook/substrate service, which Microsoft Graph rejects with
`InvalidAuthenticationToken: Invalid audience`. It is the right token for tools
that call Outlook APIs directly, but not for `teams-cli`, which talks to Graph.

**Still nothing?** Fall back to the OAuth flow, which mints a proper Graph token
with a refresh token: `teams auth login` or `teams auth login --device-code`.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest, permissions, action/popup wiring |
| `background.js` | Service worker: capture, classify, store, badge |
| `jwt.js` | Shared unverified-JWT decode + Graph-audience check |
| `popup.html` / `popup.css` / `popup.js` | Toolbar popup UI |
| `icons/` | Toolbar icons |
