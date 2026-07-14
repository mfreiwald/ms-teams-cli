// Minimal, dependency-free JWT helpers shared by the service worker and popup.
// Decoding is unverified — we only read claims to classify and display the
// token, never to make a trust decision. Exposed on globalThis so it works
// both via importScripts() in the service worker and <script> in the popup.
(function (root) {
  // Audiences Microsoft Graph tokens carry. Must stay in sync with the CLI
  // (src/auth/token.rs: GRAPH_AUDIENCES).
  const GRAPH_AUDIENCES = new Set([
    "https://graph.microsoft.com",
    "https://graph.microsoft.com/",
    "00000003-0000-0000-c000-000000000000",
  ]);

  function base64UrlDecode(input) {
    let s = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);
    const binary = atob(s);
    // Decode as UTF-8 so non-ASCII claim values (names) survive.
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  }

  function parseJwt(token) {
    try {
      const parts = token.split(".");
      if (parts.length < 2) return null;
      return JSON.parse(base64UrlDecode(parts[1]));
    } catch (_e) {
      return null;
    }
  }

  function audienceString(aud) {
    if (Array.isArray(aud)) return aud.length ? String(aud[0]) : null;
    return aud == null ? null : String(aud);
  }

  function isGraphAudience(claims) {
    const aud = audienceString(claims && claims.aud);
    return aud != null && GRAPH_AUDIENCES.has(aud);
  }

  root.TeamsJwt = { GRAPH_AUDIENCES, parseJwt, audienceString, isGraphAudience };
})(globalThis);
