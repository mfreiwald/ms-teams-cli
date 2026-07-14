// Service worker: observe requests to Microsoft Graph (direct or MCAS-proxied),
// capture the bearer token from the Authorization header, and keep the freshest
// valid Graph token in session storage for the popup to copy.
//
// The listener is registered at the top level so it is re-established every
// time the (ephemeral) service worker restarts.

importScripts("jwt.js");

const STORAGE_KEY = "graphToken";
const DIAG_KEY = "seenAudiences"; // troubleshooting: which token audiences flow
const { parseJwt, isGraphAudience, audienceString } = globalThis.TeamsJwt;

function sessionGet(key) {
  return chrome.storage.session.get(key).then((o) => o[key]);
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch (_e) {
    return url;
  }
}

// Record observation stats so the popup can show what is actually flowing when
// no Graph token is captured: a running count of Bearer requests seen, plus the
// distinct token audiences (Graph or not) and the host each was seen on. The
// count is best-effort (concurrent observers may race) but a non-zero value is
// the signal that the listener is working at all.
async function recordObservation(aud, host, graph) {
  const diag = (await sessionGet(DIAG_KEY)) || { count: 0, audiences: [] };
  diag.count = (diag.count || 0) + 1;
  if (!diag.audiences.some((e) => e.aud === aud)) {
    diag.audiences.unshift({ aud, host, graph, at: Date.now() });
    diag.audiences = diag.audiences.slice(0, 12);
  }
  await chrome.storage.session.set({ [DIAG_KEY]: diag });
}

// The token is deliberately kept in `chrome.storage.session` (in-memory, wiped
// when the browser closes) rather than `local` (persisted to disk), since a
// bearer token is a live credential.
async function observeToken(token, url) {
  const claims = parseJwt(token);
  if (!claims) return;

  const aud = audienceString(claims.aud) || "unknown";
  const graph = isGraphAudience(claims);
  await recordObservation(aud, hostOf(url), graph);
  if (!graph) return; // only Graph-audience tokens are usable by teams-cli

  const expMs = claims.exp ? claims.exp * 1000 : null;
  if (expMs && Date.now() >= expMs) return; // ignore already-expired

  const record = {
    token,
    audience: aud,
    expiresAt: expMs,
    scopes: claims.scp || null,
    user: claims.preferred_username || claims.upn || null,
    tenantId: claims.tid || null,
    appId: claims.appid || claims.azp || null,
    capturedAt: Date.now(),
  };

  const existing = await sessionGet(STORAGE_KEY);
  // Skip churn if the identical token is already stored; otherwise prefer the
  // token that stays valid longest so a shorter-lived call doesn't clobber a
  // fresher one.
  if (existing) {
    if (existing.token === record.token) return;
    if (existing.expiresAt && record.expiresAt && record.expiresAt < existing.expiresAt) {
      return;
    }
  }
  await chrome.storage.session.set({ [STORAGE_KEY]: record });
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const headers = details.requestHeaders || [];
    const auth = headers.find((h) => h.name.toLowerCase() === "authorization");
    if (auth && auth.value && auth.value.startsWith("Bearer ")) {
      // Fire and forget: observers must return synchronously.
      observeToken(auth.value.slice(7), details.url).catch(() => {});
    }
  },
  {
    // Broad Microsoft-365 net so we catch the Graph token wherever the browser
    // sends it — directly, via MCAS/Defender for Cloud Apps (*.mcas.ms), or
    // from the new Teams client (*.cloud.microsoft). The audience check keeps
    // only genuine Graph tokens; everything else is recorded for diagnostics
    // only. Must stay in sync with manifest host_permissions.
    urls: [
      "https://graph.microsoft.com/*",
      "https://*.microsoft.com/*",
      "https://*.cloud.microsoft/*",
      "https://*.office.com/*",
      "https://*.office365.com/*",
      "https://*.live.com/*",
      "https://*.skype.com/*",
      "https://*.mcas.ms/*",
    ],
  },
  ["requestHeaders", "extraHeaders"]
);

// --- Toolbar badge ---------------------------------------------------------

function updateBadge(record) {
  const valid = record && (!record.expiresAt || Date.now() < record.expiresAt);
  if (!valid) {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setTitle({ title: "Teams Graph Token — none captured" });
    return;
  }
  let text = "✓";
  let color = "#0b8043"; // green
  if (record.expiresAt) {
    const mins = Math.max(0, Math.round((record.expiresAt - Date.now()) / 60000));
    text = mins >= 60 ? `${Math.floor(mins / 60)}h` : `${mins}m`;
    if (mins <= 5) color = "#d93025"; // red near expiry
  }
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setTitle({ title: "Teams Graph Token captured — click to copy" });
}

// Keep the badge in sync whenever the stored token changes (capture or clear).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes[STORAGE_KEY]) {
    updateBadge(changes[STORAGE_KEY].newValue || null);
  }
});

// Refresh the countdown once a minute and drop the token once it expires.
chrome.alarms.create("tick", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "tick") return;
  const record = await sessionGet(STORAGE_KEY);
  if (record && record.expiresAt && Date.now() >= record.expiresAt) {
    await chrome.storage.session.remove(STORAGE_KEY);
    updateBadge(null);
  } else {
    updateBadge(record || null);
  }
});

// Restore the badge when the worker (re)starts.
sessionGet(STORAGE_KEY).then((r) => updateBadge(r || null));
