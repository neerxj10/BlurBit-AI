const state = {
  sessions: [],
  selectedSessionId: "",
};
const inviteState = {
  isAdmin: false,
  tokens: [],
  requests: [],
};
let wsPingTimer = null;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 48;

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value ?? "-");
}

function formatTime(ts) {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleTimeString();
}

function getVerdictClass(verdict = "") {
  const key = verdict.toUpperCase();
  if (key === "PHISHING") return "verdict-phishing";
  if (key === "SUSPICIOUS") return "verdict-suspicious";
  if (key === "ERROR") return "verdict-error";
  return "verdict-safe";
}

function addEvent(message) {
  const list = document.getElementById("eventsList");
  if (!list) return;
  const li = document.createElement("li");
  li.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  list.prepend(li);
  while (list.children.length > 8) list.removeChild(list.lastChild);
}

function gaugeColor(level, value) {
  const normalized = String(level || "").toUpperCase();
  if (normalized === "CRITICAL" || value >= 85) return "#ff6e94";
  if (normalized === "HIGH" || value >= 65) return "#ffc15d";
  if (normalized === "MEDIUM" || value >= 35) return "#3de8ff";
  return "#34f5be";
}

function renderProbabilityGauge(value = 0, level = "LOW", label = "Live Max Session Probability") {
  const safe = Math.max(0, Math.min(100, Number(value || 0)));
  const fill = document.getElementById("gaugeFill");
  const pct = document.getElementById("gaugePercent");
  const risk = document.getElementById("gaugeRiskLevel");
  const gaugeLabel = document.getElementById("gaugeLabel");
  if (!fill || !pct || !risk || !gaugeLabel) return;

  fill.style.strokeDasharray = `${GAUGE_CIRCUMFERENCE}`;
  fill.style.strokeDashoffset = `${GAUGE_CIRCUMFERENCE - (safe / 100) * GAUGE_CIRCUMFERENCE}`;
  fill.style.stroke = gaugeColor(level, safe);
  pct.textContent = `${safe.toFixed(1)}%`;
  risk.textContent = String(level || "LOW").toUpperCase();
  gaugeLabel.textContent = label;
}

function updateGaugeFromSessions() {
  if (!state.sessions.length) {
    renderProbabilityGauge(0, "LOW", "No active sessions");
    return;
  }

  const selected = state.selectedSessionId
    ? state.sessions.find((s) => s.sessionId === state.selectedSessionId)
    : null;
  if (selected) {
    renderProbabilityGauge(
      Number(selected.scamProbability || 0),
      String(selected.riskLevel || "LOW"),
      `Selected: ${selected.sessionId}`,
    );
    return;
  }

  const top = [...state.sessions].sort((a, b) => Number(b.scamProbability || 0) - Number(a.scamProbability || 0))[0];
  renderProbabilityGauge(
    Number(top.scamProbability || 0),
    String(top.riskLevel || "LOW"),
    `Live Max: ${top.sessionId}`,
  );
}

function renderThreatPill(level = "LOW") {
  const pill = document.getElementById("threatPill");
  pill.textContent = `Threat: ${level}`;
  if (level === "CRITICAL") {
    pill.style.color = "#ff6e94";
    pill.style.borderColor = "rgba(255, 110, 148, 0.46)";
    pill.style.background = "rgba(255, 110, 148, 0.12)";
    return;
  }
  if (level === "ELEVATED") {
    pill.style.color = "#ffc15d";
    pill.style.borderColor = "rgba(255, 193, 93, 0.45)";
    pill.style.background = "rgba(255, 193, 93, 0.12)";
    return;
  }
  if (level === "GUARDED") {
    pill.style.color = "#3de8ff";
    pill.style.borderColor = "rgba(61, 232, 255, 0.45)";
    pill.style.background = "rgba(61, 232, 255, 0.12)";
    return;
  }
  pill.style.color = "#34f5be";
  pill.style.borderColor = "rgba(52, 245, 190, 0.45)";
  pill.style.background = "rgba(52, 245, 190, 0.12)";
}

function drawVerdictChart(breakdown = {}) {
  const canvas = document.getElementById("verdictChart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const cssWidth = Math.max(canvas.clientWidth || 320, 320);
  const cssHeight = 220;
  canvas.style.width = `${cssWidth}px`;
  canvas.style.height = `${cssHeight}px`;
  canvas.width = Math.floor(cssWidth * dpr);
  canvas.height = Math.floor(cssHeight * dpr);

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  const labels = ["SAFE", "SUSPICIOUS", "PHISHING", "ERROR"];
  const colors = ["#34f5be", "#ffc15d", "#ff6e94", "#9da8bd"];
  const values = ["SAFE", "SUSPICIOUS", "PHISHING", "ERROR"].map((k) => Number(breakdown[k] || 0));
  const total = values.reduce((a, b) => a + b, 0);

  const pad = 24;
  const chartW = cssWidth - pad * 2;
  const baseY = cssHeight - 28;
  const max = Math.max(...values, 1);
  const barW = chartW / labels.length - 14;

  labels.forEach((label, i) => {
    const x = pad + i * (chartW / labels.length) + 7;
    const ratio = values[i] / max;
    const barH = ratio * (cssHeight - 82);
    const y = baseY - barH;

    ctx.fillStyle = colors[i];
    ctx.globalAlpha = 0.92;
    ctx.fillRect(x, y, barW, barH);

    ctx.globalAlpha = 1;
    ctx.fillStyle = "#91a7cb";
    ctx.font = "12px JetBrains Mono";
    ctx.fillText(label, x, baseY + 16);

    const pct = total ? Math.round((values[i] / total) * 100) : 0;
    ctx.fillStyle = "#e8f2ff";
    ctx.fillText(`${values[i]} (${pct}%)`, x, y - 8);
  });
}

function renderAlerts(alerts = []) {
  const list = document.getElementById("alertsList");
  list.innerHTML = "";

  alerts.forEach((a) => {
    const li = document.createElement("li");
    const title = a.title || "Untitled page";
    li.textContent = `${a.verdict} | ${a.sessionId} | ${title}`;
    list.appendChild(li);
  });

  if (!list.children.length) {
    const li = document.createElement("li");
    li.textContent = "No threat alerts yet";
    list.appendChild(li);
  }
}

async function fetchOverview() {
  const res = await fetch("/api/overview");
  if (res.status === 401) {
    window.location.href = "/login";
    return;
  }
  const data = await res.json();
  renderOverview(data);
}

async function fetchSessions() {
  const res = await fetch("/api/sessions");
  if (res.status === 401) {
    window.location.href = "/login";
    return;
  }
  const data = await res.json();
  state.sessions = data.sessions || [];
  renderSessions();
  updateGaugeFromSessions();
}

async function loadSessionDetail(sessionId) {
  const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}`);
  if (res.status === 401) {
    window.location.href = "/login";
    return;
  }
  const data = await res.json();
  document.getElementById("sessionDetail").textContent = JSON.stringify(data, null, 2);
  renderProbabilityGauge(
    Number(data.scamProbability || 0),
    String(data.riskLevel || "LOW"),
    `Selected: ${sessionId}`,
  );
}

function renderOverview(data) {
  setText("totalSessions", data.totalSessions);
  setText("totalMessages", data.totalMessages);
  setText("totalScannedLinks", data.totalScannedLinks);
  setText("phishingLinks", data.phishingLinks);
  setText("avgRiskScore", Number(data.avgRiskScore || 0).toFixed(2));
  setText("criticalSessions", Number(data.criticalSessions || 0));
  setText("lastUpdated", `${"Last update"}: ${formatTime(data.updatedAt)}`);

  const intel = data.intelTotals || {};
  setText("bankAccounts", intel.bankAccounts || 0);
  setText("upiIds", intel.upiIds || 0);
  setText("phoneNumbers", intel.phoneNumbers || 0);
  setText("threatScore", data.threatScore || 0);

  renderThreatPill(data.threatLevel || "LOW");
  drawVerdictChart(data.verdictBreakdown || {});
  renderAlerts(data.recentAlerts || []);

  const keywords = document.getElementById("keywordsList");
  keywords.innerHTML = "";
  (data.topKeywords || []).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = `${item.word}: ${item.count}`;
    keywords.appendChild(li);
  });

  if (!keywords.children.length) {
    const li = document.createElement("li");
    li.textContent = "No suspicious keywords yet";
    keywords.appendChild(li);
  }
}

function renderSessions() {
  const body = document.getElementById("sessionsBody");
  body.innerHTML = "";

  for (const session of state.sessions) {
    const verdict = session.latestVerdict || "SAFE";
    const riskLevel = String(session.riskLevel || "LOW").toUpperCase();
    const scamProbability = Number(session.scamProbability || 0);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${session.sessionId}</td>
      <td>${session.messages}</td>
      <td><span class="chip chip-risk">${Number(session.riskScore || 0).toFixed(2)}</span></td>
      <td><span class="chip chip-risk">${scamProbability.toFixed(1)}%</span></td>
      <td><span class="chip risk-${riskLevel.toLowerCase()}">${riskLevel}</span></td>
      <td><span class="chip ${getVerdictClass(verdict)}">${verdict}</span></td>
    `;
    tr.addEventListener("click", () => {
      state.selectedSessionId = session.sessionId;
      loadSessionDetail(session.sessionId);
    });
    body.appendChild(tr);
  }

  if (!state.sessions.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6">${"No active sessions"}</td>`;
    body.appendChild(tr);
  }
}

function setInviteStatus(message, isError = false) {
  const status = document.getElementById("inviteStatus");
  if (!status) return;
  status.textContent = message;
  status.style.color = isError ? "#ff6e94" : "";
}

function formatTs(ts) {
  if (!ts) return "--";
  return new Date(Number(ts) * 1000).toLocaleString();
}

function renderInviteTokens() {
  const panel = document.getElementById("telegramAdminPanel");
  const list = document.getElementById("inviteTokenList");
  const latest = document.getElementById("latestInviteToken");
  if (!panel || !list || !latest) return;

  if (!inviteState.isAdmin) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");

  const tokens = [...inviteState.tokens].sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
  latest.textContent = tokens.length ? tokens[0].token : "No token generated yet.";
  list.innerHTML = "";

  tokens.slice(0, 10).forEach((token) => {
    const li = document.createElement("li");
    const expires = token.expiresAt ? formatTs(token.expiresAt) : "never";
    const meta = `Uses: ${token.usedCount || 0}/${token.maxUses || 1} | Expires: ${expires} | Revoked: ${token.revoked ? "Yes" : "No"}`;
    li.innerHTML = `
      <div>${token.token}</div>
      <div class="muted">${meta}</div>
      ${token.revoked ? "" : `<button class="invite-revoke-btn secondary" data-token="${token.token}" type="button">Revoke</button>`}
    `;
    list.appendChild(li);
  });

  if (!tokens.length) {
    const li = document.createElement("li");
    li.textContent = "No invite tokens created yet.";
    list.appendChild(li);
  }
}

function renderAccessRequests() {
  const list = document.getElementById("accessRequestList");
  if (!list) return;
  list.innerHTML = "";

  const requests = [...inviteState.requests];
  requests.sort((a, b) => Number(b.lastRequestedAt || 0) - Number(a.lastRequestedAt || 0));

  requests.slice(0, 15).forEach((req) => {
    const chatId = Number(req.chatId || 0);
    const name = req.fullName || req.username || `chat:${chatId}`;
    const meta = `chatId: ${chatId} | requests: ${req.requestCount || 1} | last: ${formatTs(req.lastRequestedAt)}`;

    const li = document.createElement("li");
    li.innerHTML = `
      <div>${name}</div>
      <div class="muted">${meta}</div>
      <div class="request-actions">
        <button class="approve-request-btn" data-chat-id="${chatId}" type="button">Approve</button>
        <button class="reject request-reject-btn" data-chat-id="${chatId}" type="button">Reject</button>
      </div>
    `;
    list.appendChild(li);
  });

  if (!requests.length) {
    const li = document.createElement("li");
    li.textContent = "No pending access requests.";
    list.appendChild(li);
  }
}

async function fetchInviteTokens({ silent = false } = {}) {
  const panel = document.getElementById("telegramAdminPanel");
  if (!panel) return;
  try {
    const res = await fetch("/api/telegram/invite-tokens");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (res.status === 403) {
      inviteState.isAdmin = false;
      renderInviteTokens();
      return;
    }
    if (!res.ok) {
      if (!silent) setInviteStatus("Failed to load invite tokens.", true);
      return;
    }
    const data = await res.json();
    inviteState.isAdmin = true;
    inviteState.tokens = Array.isArray(data.tokens) ? data.tokens : [];
    renderInviteTokens();
    await fetchAccessRequests({ silent: true });
    if (!silent) setInviteStatus("Invite tokens loaded.");
  } catch {
    if (!silent) setInviteStatus("Failed to load invite tokens.", true);
  }
}

async function fetchAccessRequests({ silent = false } = {}) {
  if (!inviteState.isAdmin) return;
  try {
    const res = await fetch("/api/telegram/access-requests");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (res.status === 403) {
      return;
    }
    if (!res.ok) {
      if (!silent) setInviteStatus("Failed to load access requests.", true);
      return;
    }
    const data = await res.json();
    inviteState.requests = Array.isArray(data.requests) ? data.requests : [];
    renderAccessRequests();
  } catch {
    if (!silent) setInviteStatus("Failed to load access requests.", true);
  }
}

async function createInviteToken() {
  const expiresEl = document.getElementById("inviteExpires");
  const maxUsesEl = document.getElementById("inviteMaxUses");
  const expiresInMinutes = Math.max(1, Number(expiresEl?.value || 10));
  const maxUses = Math.max(1, Number(maxUsesEl?.value || 1));

  setInviteStatus("Generating token...");
  try {
    const res = await fetch("/api/telegram/invite-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expiresInMinutes, maxUses }),
    });

    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (res.status === 403) {
      setInviteStatus("Admin access required.", true);
      return;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      setInviteStatus(err.detail || "Failed to generate token.", true);
      return;
    }

    const data = await res.json();
    setInviteStatus("Token generated successfully.");
    const latest = document.getElementById("latestInviteToken");
    if (latest && data.token) latest.textContent = data.token;
    await fetchInviteTokens({ silent: true });
  } catch {
    setInviteStatus("Failed to generate token.", true);
  }
}

async function revokeInviteToken(token) {
  setInviteStatus("Revoking token...");
  try {
    const res = await fetch("/api/telegram/invite-token/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      setInviteStatus(err.detail || "Failed to revoke token.", true);
      return;
    }
    setInviteStatus("Token revoked.");
    await fetchInviteTokens({ silent: true });
  } catch {
    setInviteStatus("Failed to revoke token.", true);
  }
}

async function approveAccessRequest(chatId) {
  const expiresEl = document.getElementById("inviteExpires");
  const maxUsesEl = document.getElementById("inviteMaxUses");
  const expiresInMinutes = Math.max(1, Number(expiresEl?.value || 10));
  const maxUses = Math.max(1, Number(maxUsesEl?.value || 1));

  setInviteStatus(`Approving request for ${chatId}...`);
  try {
    const res = await fetch("/api/telegram/access-request/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chatId: Number(chatId), expiresInMinutes, maxUses }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      setInviteStatus(err.detail || "Failed to approve access request.", true);
      return;
    }
    setInviteStatus(`Approved ${chatId} and token sent on Telegram.`);
    await Promise.all([fetchInviteTokens({ silent: true }), fetchAccessRequests({ silent: true })]);
  } catch {
    setInviteStatus("Failed to approve access request.", true);
  }
}

async function rejectAccessRequest(chatId) {
  setInviteStatus(`Rejecting request for ${chatId}...`);
  try {
    const res = await fetch("/api/telegram/access-request/reject", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chatId: Number(chatId) }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      setInviteStatus(err.detail || "Failed to reject access request.", true);
      return;
    }
    setInviteStatus(`Rejected request for ${chatId}.`);
    await fetchAccessRequests({ silent: true });
  } catch {
    setInviteStatus("Failed to reject access request.", true);
  }
}

async function copyLatestInviteToken() {
  const latest = document.getElementById("latestInviteToken");
  if (!latest) return;

  const text = (latest.textContent || "").trim();
  if (!text || text.toLowerCase().includes("no token generated")) {
    setInviteStatus("No token to copy yet.", true);
    return;
  }

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const temp = document.createElement("textarea");
      temp.value = text;
      document.body.appendChild(temp);
      temp.select();
      document.execCommand("copy");
      document.body.removeChild(temp);
    }
    setInviteStatus("Token copied.");
  } catch {
    setInviteStatus("Copy failed. Please copy manually.", true);
  }
}

function setupInvitePanel() {
  const generateBtn = document.getElementById("generateInviteBtn");
  const refreshBtn = document.getElementById("refreshInviteBtn");
  const copyBtn = document.getElementById("copyInviteBtn");
  const tokenList = document.getElementById("inviteTokenList");
  const accessRequestList = document.getElementById("accessRequestList");
  if (!generateBtn || !refreshBtn || !copyBtn || !tokenList || !accessRequestList) return;

  generateBtn.addEventListener("click", createInviteToken);
  refreshBtn.addEventListener("click", () => fetchInviteTokens());
  copyBtn.addEventListener("click", copyLatestInviteToken);
  tokenList.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (!target.classList.contains("invite-revoke-btn")) return;
    const token = target.dataset.token;
    if (!token) return;
    revokeInviteToken(token);
  });

  accessRequestList.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const chatId = target.dataset.chatId;
    if (!chatId) return;
    if (target.classList.contains("approve-request-btn")) {
      approveAccessRequest(chatId);
      return;
    }
    if (target.classList.contains("request-reject-btn")) {
      rejectAccessRequest(chatId);
    }
  });
}

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
  const connStatus = document.getElementById("connStatus");

  ws.onopen = () => {
    connStatus.textContent = "Live";
    connStatus.style.color = "#34f5be";
    connStatus.style.borderColor = "rgba(52, 245, 190, 0.4)";
    connStatus.style.background = "rgba(52, 245, 190, 0.12)";
    addEvent("WebSocket connected");
  };

  ws.onmessage = (event) => {
    const payload = JSON.parse(event.data);

    if (payload.type === "init") {
      renderOverview(payload.overview || {});
      state.sessions = payload.sessions || [];
      renderSessions();
      updateGaugeFromSessions();
      addEvent("Initial state loaded");
      return;
    }

    if (payload.type === "session_update") {
      renderOverview(payload.overview || {});
      fetchSessions();
      addEvent(`Session updated: ${payload.sessionId}`);
    }
  };

  ws.onclose = () => {
    if (wsPingTimer) {
      clearInterval(wsPingTimer);
      wsPingTimer = null;
    }
    connStatus.textContent = "Reconnecting...";
    connStatus.style.color = "#ffc15d";
    connStatus.style.borderColor = "rgba(255, 193, 93, 0.4)";
    connStatus.style.background = "rgba(255, 193, 93, 0.12)";
    setTimeout(connectWebSocket, 2000);
  };

  ws.onerror = () => {
    ws.close();
  };

  wsPingTimer = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send("ping");
  }, 15000);
}

window.addEventListener("resize", () => fetchOverview());

(async function init() {
  setupInvitePanel();
  await Promise.all([fetchOverview(), fetchSessions()]);
  await fetchInviteTokens({ silent: true });
  connectWebSocket();
  setInterval(() => {
    fetchOverview();
    fetchSessions();
  }, 10000);
})();
