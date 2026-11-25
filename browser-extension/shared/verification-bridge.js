(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const tokenFields = ["Token", "token", "verificationToken", "HumanVerificationToken", "humanVerificationToken"];
  let lastSentToken = "";

  function sendToken(value) {
    if (typeof value !== "string" || value.length < 20 || value.length > 8192 || /^https?:\/\//i.test(value)) return;
    if (value === lastSentToken) return;
    lastSentToken = value;
    try {
      api.runtime.sendMessage({ type: "FREETON_HUMAN_VERIFICATION_TOKEN", token: value }).catch(() => undefined);
    } catch {
      // The extension may be reloaded while the verification tab is open.
    }
  }

  window.addEventListener("message", (event) => {
    const data = event.data;
    if (typeof data === "string") {
      if (data.trim().startsWith("{")) {
        try {
          const parsed = JSON.parse(data);
          for (const key of tokenFields) sendToken(parsed?.[key]);
        } catch {
          // Ignore unrelated page messages.
        }
      } else sendToken(data);
      return;
    }
    if (data && typeof data === "object") {
      for (const key of tokenFields) sendToken(data[key]);
    }
  }, false);
})();
