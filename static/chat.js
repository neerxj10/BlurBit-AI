const els = {
  sessionId: document.getElementById("sessionId"),
  apiKey: document.getElementById("apiKey"),
  newSessionBtn: document.getElementById("newSessionBtn"),
  testTelegramBtn: document.getElementById("testTelegramBtn"),
  exportJsonBtn: document.getElementById("exportJsonBtn"),
  exportCsvBtn: document.getElementById("exportCsvBtn"),
  chatThread: document.getElementById("chatThread"),
  chatForm: document.getElementById("chatForm"),
  msgInput: document.getElementById("msgInput"),
  intelView: document.getElementById("intelView"),
  typingIndicator: document.getElementById("typingIndicator"),
};
const conversation = [];

function randomSessionId() {
  return `session-${Math.random().toString(36).slice(2, 10)}`;
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

function appendMessage(role, text, timestamp = Math.floor(Date.now() / 1000)) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  const body = document.createElement("div");
  body.textContent = text;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = `${role === "bot" ? "Honeypot" : "Scammer"} • ${fmtTime(timestamp)}`;
  div.appendChild(body);
  div.appendChild(meta);
  els.chatThread.appendChild(div);
  els.chatThread.scrollTop = els.chatThread.scrollHeight;
  conversation.push({ role, text, timestamp });
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function refreshIntel() {
  const sid = els.sessionId.value.trim();
  if (!sid) return;
  try {
    const res = await fetch(`/api/sessions/${encodeURIComponent(sid)}`);
    if (res.status === 404) {
      els.intelView.textContent = "No session data yet for this Session ID.";
      return;
    }
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    const data = await res.json();
    els.intelView.textContent = JSON.stringify(data.intel || {}, null, 2);
  } catch {
    els.intelView.textContent = "Failed to fetch session intel.";
  }
}

els.newSessionBtn.addEventListener("click", () => {
  els.sessionId.value = randomSessionId();
  els.chatThread.innerHTML = "";
  els.intelView.textContent = "No data yet.";
  conversation.length = 0;
});

els.testTelegramBtn.addEventListener("click", async () => {
  const sid = els.sessionId.value.trim();
  if (!sid) {
    alert("Please set Session ID.");
    return;
  }
  try {
    const res = await fetch("/api/test-telegram", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: sid,
        message: conversation.length ? conversation[conversation.length - 1].text : "Manual test from chat console",
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.detail || "Telegram test failed");
      return;
    }
    alert(`Telegram test alert sent for ${data.sessionId}`);
  } catch {
    alert("Telegram test failed (network).");
  }
});

els.exportJsonBtn.addEventListener("click", () => {
  const sid = els.sessionId.value.trim() || "session";
  const payload = {
    sessionId: sid,
    exportedAt: new Date().toISOString(),
    messages: conversation,
  };
  downloadFile(`${sid}-chat.json`, JSON.stringify(payload, null, 2), "application/json");
});

els.exportCsvBtn.addEventListener("click", () => {
  const sid = els.sessionId.value.trim() || "session";
  const rows = ["timestamp,role,text"];
  for (const m of conversation) {
    const safe = String(m.text).replace(/\"/g, '\"\"');
    rows.push(`${m.timestamp},${m.role},\"${safe}\"`);
  }
  downloadFile(`${sid}-chat.csv`, rows.join("\n"), "text/csv");
});

els.chatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const sid = els.sessionId.value.trim();
  const apiKey = els.apiKey.value.trim();
  const text = els.msgInput.value.trim();

  if (!sid) {
    alert("Please set Session ID.");
    return;
  }
  if (!apiKey) {
    alert("Please enter Honeypot API Key.");
    return;
  }
  if (!text) return;

  appendMessage("scammer", text);
  els.msgInput.value = "";
  els.typingIndicator.classList.add("show");

  try {
    const res = await fetch("/honeypot", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
      },
      body: JSON.stringify({
        sessionId: sid,
        message: {
          sender: "scammer",
          text,
          timestamp: Math.floor(Date.now() / 1000),
        },
        conversationHistory: [],
        metadata: {},
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      appendMessage("bot", `Error: ${data.detail || "Request failed"}`);
      els.typingIndicator.classList.remove("show");
      return;
    }

    appendMessage("bot", data.reply || "...");
    els.typingIndicator.classList.remove("show");
    refreshIntel();
  } catch {
    appendMessage("bot", "Network error. Please try again.");
    els.typingIndicator.classList.remove("show");
  }
});

(function init() {
  els.sessionId.value = randomSessionId();
  setInterval(refreshIntel, 5000);
})();
