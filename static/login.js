(function () {
  const form = document.getElementById("authForm");
  if (!form) return;

  const mode = form.dataset.mode || "";
  if (mode !== "login") return;

  const emailEl = document.getElementById("email");
  const passwordEl = document.getElementById("password");
  const hiddenTrapEl = document.getElementById("usernameHidden");
  const toggleBtn = document.getElementById("togglePassword");
  const signInBtn = document.getElementById("submitBtn");
  const btnText = document.getElementById("submitText");
  const btnSpinner = document.getElementById("submitSpinner");
  const errorEl = document.getElementById("authError");
  const rememberEl = document.getElementById("rememberMe");

  const defaultBtnText = (btnText?.textContent || "Sign in").trim();

  function setLoading(isLoading) {
    if (!signInBtn || !btnText || !btnSpinner) return;
    signInBtn.disabled = isLoading;
    btnText.textContent = isLoading ? "Signing in..." : defaultBtnText;
    btnSpinner.classList.toggle("hidden", !isLoading);
  }

  function setError(message) {
    if (!errorEl) return;
    if (!message) {
      errorEl.classList.add("hidden");
      errorEl.textContent = "";
      return;
    }
    errorEl.textContent = message;
    errorEl.classList.remove("hidden");
  }

  async function honeypotLog(payload) {
    try {
      await fetch("/honeypot/log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        keepalive: true,
      });
    } catch (_) {
      // Silent logging failure by design
    }
  }

  if (toggleBtn && passwordEl) {
    toggleBtn.addEventListener("click", () => {
      const isPassword = passwordEl.type === "password";
      passwordEl.type = isPassword ? "text" : "password";
      toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
      toggleBtn.textContent = isPassword ? "🙈" : "👁";
    });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("");

    const email = (emailEl?.value || "").trim();
    const password = passwordEl?.value || "";
    const usernameHidden = (hiddenTrapEl?.value || "").trim();
    const rememberMe = !!rememberEl?.checked;

    // Non-blocking telemetry log
    honeypotLog({
      event: "login_attempt",
      email,
      userAgent: navigator.userAgent,
      screenResolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      platform: navigator.platform,
      language: navigator.language,
      loginTime: new Date().toISOString(),
      rememberMe,
    });

    // Honeypot trap log
    if (usernameHidden) {
      honeypotLog({
        event: "bot_detected_login",
        bot_detected: true,
        username_hidden: usernameHidden,
        email,
        userAgent: navigator.userAgent,
        loginTime: new Date().toISOString(),
      });
    }

    setLoading(true);

    try {
      await new Promise((resolve) => setTimeout(resolve, 1500));

      const body = new URLSearchParams();
      body.set("email", email);
      body.set("password", password);
      body.set("username_hidden", usernameHidden);
      body.set("remember_me", rememberMe ? "1" : "0");

      const response = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        credentials: "same-origin",
        redirect: "follow",
      });

      const finalUrl = response.url || "";
      if (response.redirected && finalUrl.includes("/dashboard")) {
        window.location.href = "/dashboard";
        return;
      }
      if (finalUrl.includes("/dashboard")) {
        window.location.href = "/dashboard";
        return;
      }

      setError("Invalid email or password. Please try again.");
      setLoading(false);
    } catch (_) {
      setError("Unable to sign in right now. Please try again.");
      setLoading(false);
    }
  });
})();
