(function () {
  const dictionaries = {
    en: {
      language: "Language",
      aiThreatMonitoring: "AI Threat Monitoring",
      commandCenter: "Agentic Honeypot Command Center",
      signedIn: "Signed in",
      logout: "Logout",
      lastUpdate: "Last update",
      connecting: "Connecting...",
      live: "Live",
      reconnecting: "Reconnecting...",
      threat: "Threat",
      threatLow: "Threat: LOW",
      totalSessions: "Total Sessions",
      totalMessages: "Total Messages",
      scannedLinks: "Scanned Links",
      phishingLinks: "Phishing Links",
      averageRiskScore: "Average Risk Score",
      verdictDistribution: "Verdict Distribution",
      verdictLegend: "SAFE / SUSPICIOUS / PHISHING / ERROR",
      intelSnapshot: "Intel Capture Snapshot",
      intelSignals: "Extracted PII signals",
      bankAccounts: "Bank Accounts",
      upiIds: "UPI IDs",
      phoneNumbers: "Phone Numbers",
      threatScore: "Threat Score",
      liveSessions: "Live Sessions",
      clickRowDetail: "Click a row for full detail",
      sessionId: "Session ID",
      messages: "Messages",
      risk: "Risk",
      verdict: "Verdict",
      topKeywords: "Top Suspicious Keywords",
      recentAlerts: "Recent Alerts",
      liveEvents: "Live Events",
      selectedSessionDetail: "Selected Session Detail",
      clickSessionInspect: "Click a session row to inspect details.",
      noThreatAlerts: "No threat alerts yet",
      noKeywords: "No suspicious keywords yet",
      noActiveSessions: "No active sessions",
      wsConnected: "WebSocket connected",
      initialLoaded: "Initial state loaded",
      sessionUpdated: "Session updated",
      safe: "SAFE",
      suspicious: "SUSPICIOUS",
      phishing: "PHISHING",
      error: "ERROR",
      agenticHoneypot: "Agentic Honeypot",
      createAccountTitle: "Create your account",
      signInTitle: "Sign in to dashboard",
      fullName: "Full name",
      enterName: "Enter name",
      email: "Email",
      emailPlaceholder: "you@example.com",
      password: "Password",
      passwordPlaceholder: "Min 8 characters",
      createAccountBtn: "Create account",
      signInBtn: "Sign in",
      continueGoogle: "Continue with Google",
      googleDisabledHint: "Google sign-in is disabled. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.",
      googleRedirectHint: "If Google redirects fail, add the exact callback URL shown in your browser host: `/auth/google/callback`.",
      alreadyAccount: "Already have an account?",
      signIn: "Sign in",
      newHere: "New here?",
      createAccountLink: "Create account"
    },
    hi: {
      language: "Bhasha",
      aiThreatMonitoring: "AI Threat Monitoring",
      commandCenter: "Agentic Honeypot Command Center",
      signedIn: "Login User",
      logout: "Logout",
      lastUpdate: "Aakhri Update",
      connecting: "Connect ho raha hai...",
      live: "Live",
      reconnecting: "Dobara connect ho raha hai...",
      threat: "Khatra",
      threatLow: "Khatra: LOW",
      totalSessions: "Kul Sessions",
      totalMessages: "Kul Messages",
      scannedLinks: "Scan kiye gaye Links",
      phishingLinks: "Phishing Links",
      averageRiskScore: "Average Risk Score",
      verdictDistribution: "Verdict Distribution",
      verdictLegend: "SAFE / SUSPICIOUS / PHISHING / ERROR",
      intelSnapshot: "Intel Capture Snapshot",
      intelSignals: "Extracted PII signals",
      bankAccounts: "Bank Accounts",
      upiIds: "UPI IDs",
      phoneNumbers: "Phone Numbers",
      threatScore: "Threat Score",
      liveSessions: "Live Sessions",
      clickRowDetail: "Details ke liye row par click karein",
      sessionId: "Session ID",
      messages: "Messages",
      risk: "Risk",
      verdict: "Verdict",
      topKeywords: "Top Suspicious Keywords",
      recentAlerts: "Recent Alerts",
      liveEvents: "Live Events",
      selectedSessionDetail: "Selected Session Detail",
      clickSessionInspect: "Details dekhne ke liye session row par click karein.",
      noThreatAlerts: "Abhi koi threat alert nahi hai",
      noKeywords: "Abhi koi suspicious keyword nahi hai",
      noActiveSessions: "Koi active session nahi hai",
      wsConnected: "WebSocket connect ho gaya",
      initialLoaded: "Initial data load ho gaya",
      sessionUpdated: "Session update hua",
      safe: "SAFE",
      suspicious: "SUSPICIOUS",
      phishing: "PHISHING",
      error: "ERROR",
      agenticHoneypot: "Agentic Honeypot",
      createAccountTitle: "Apna account banayein",
      signInTitle: "Dashboard me sign in karein",
      fullName: "Poora naam",
      enterName: "Naam enter karein",
      email: "Email",
      emailPlaceholder: "you@example.com",
      password: "Password",
      passwordPlaceholder: "Minimum 8 characters",
      createAccountBtn: "Account banayein",
      signInBtn: "Sign in karein",
      continueGoogle: "Google se continue karein",
      googleDisabledHint: "Google sign-in disabled hai. `GOOGLE_CLIENT_ID` aur `GOOGLE_CLIENT_SECRET` set karein.",
      googleRedirectHint: "Agar Google redirect fail ho, to browser host ke saath exact callback URL add karein: `/auth/google/callback`.",
      alreadyAccount: "Pehle se account hai?",
      signIn: "Sign in",
      newHere: "Naye user hain?",
      createAccountLink: "Account banayein"
    }
  };

  let current = localStorage.getItem("lang") || "en";
  const listeners = [];
  let initialized = false;

  function t(key, fallback) {
    return (dictionaries[current] && dictionaries[current][key]) || fallback || key;
  }

  function applyTranslations() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      el.textContent = t(key, el.textContent);
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      const key = el.getAttribute("data-i18n-placeholder");
      el.setAttribute("placeholder", t(key, el.getAttribute("placeholder") || ""));
    });

    listeners.forEach((fn) => fn(current));
  }

  function setLanguage(lang) {
    current = lang === "hi" ? "hi" : "en";
    localStorage.setItem("lang", current);
    applyTranslations();
  }

  function init() {
    if (initialized) return current;
    initialized = true;
    const select = document.getElementById("langSelect");
    if (select) {
      select.value = current;
      select.addEventListener("change", (e) => setLanguage(e.target.value));
    }
    applyTranslations();
    return current;
  }

  window.I18N = {
    init,
    t,
    setLanguage,
    getLanguage: () => current,
    onChange: (fn) => listeners.push(fn),
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
