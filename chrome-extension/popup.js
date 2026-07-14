// Popup: render the captured Graph token and let the user copy it (or a
// ready-to-paste `teams auth login --token` command) and clear it.

const STORAGE_KEY = "graphToken";

const el = {
  pill: document.getElementById("status-pill"),
  have: document.getElementById("have-token"),
  none: document.getElementById("no-token"),
  user: document.getElementById("m-user"),
  audience: document.getElementById("m-audience"),
  expiry: document.getElementById("m-expiry"),
  scopes: document.getElementById("m-scopes"),
  copyToken: document.getElementById("copy-token"),
  copyCmd: document.getElementById("copy-cmd"),
  clear: document.getElementById("clear"),
  toast: document.getElementById("toast"),
};

let current = null;
let toastTimer = null;

function sessionGet(key) {
  return chrome.storage.session.get(key).then((o) => o[key]);
}

function formatCountdown(ms) {
  if (ms <= 0) return "expired";
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function setPill(kind, label) {
  el.pill.className = `pill pill-${kind}`;
  el.pill.textContent = label;
}

function render() {
  if (!current) {
    el.have.hidden = true;
    el.none.hidden = false;
    setPill("none", "none");
    return;
  }

  el.have.hidden = false;
  el.none.hidden = true;

  el.user.textContent = current.user || "unknown";

  const graphOk =
    current.audience === "https://graph.microsoft.com" ||
    current.audience === "https://graph.microsoft.com/" ||
    current.audience === "00000003-0000-0000-c000-000000000000";
  el.audience.textContent = graphOk
    ? `${current.audience}  ✓ Graph`
    : `${current.audience}  ✗ not Graph`;
  el.audience.style.color = graphOk ? "var(--ok)" : "var(--err)";

  const scopes = current.scopes ? current.scopes.split(/\s+/).filter(Boolean) : [];
  el.scopes.textContent = scopes.length ? scopes.join(", ") : "—";

  updateExpiry();
}

function updateExpiry() {
  if (!current) return;
  if (!current.expiresAt) {
    el.expiry.textContent = "unknown";
    setPill("warn", "no exp");
    return;
  }
  const remaining = current.expiresAt - Date.now();
  el.expiry.textContent = `${formatCountdown(remaining)} (${new Date(
    current.expiresAt
  ).toLocaleTimeString()})`;

  if (remaining <= 0) {
    setPill("err", "expired");
  } else if (remaining <= 5 * 60 * 1000) {
    setPill("warn", "expiring");
  } else {
    setPill("ok", "valid");
  }
}

function toast(message) {
  el.toast.textContent = message;
  el.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.toast.hidden = true;
  }, 1800);
}

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch (_e) {
    toast("Copy failed — clipboard blocked");
  }
}

el.copyToken.addEventListener("click", () => {
  if (current) copy(current.token, "Token copied");
});

el.copyCmd.addEventListener("click", () => {
  // JWTs only contain [A-Za-z0-9._-], so single-quoting is shell-safe.
  if (current) copy(`teams auth login --token '${current.token}'`, "Command copied");
});

el.clear.addEventListener("click", async () => {
  await chrome.storage.session.remove(STORAGE_KEY);
  current = null;
  render();
  toast("Cleared");
});

// Live-update when a token is captured/cleared while the popup is open.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes[STORAGE_KEY]) {
    current = changes[STORAGE_KEY].newValue || null;
    render();
  }
});

// Tick the countdown every second.
setInterval(updateExpiry, 1000);

sessionGet(STORAGE_KEY).then((r) => {
  current = r || null;
  render();
});
