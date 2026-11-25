(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const diagnosticLog = (event, details = {}, level = "info") =>
    globalThis.FreetonDiagnostics?.log("login", event, details, level);
  const els = Object.fromEntries([
    "status", "statusText", "authPanel", "authTitle", "authDescription", "loginForm", "username", "password",
    "loginButton", "twoFactorForm", "twoFactorCode", "twoFactorButton", "challengePanel", "challengeMessage",
    "openVerification", "authMessage", "successPanel", "exportLogs", "clearLogs",
  ].map((id) => [id, document.getElementById(id)]));

  let busy = false;
  let currentStateKey = "";
  let pendingVerificationLogin = null;
  let automaticVerificationRetryUsed = false;
  let authState = { authenticated: false, needsTwoFactor: false, needsHumanVerification: false, verificationTokenCaptured: false };

  function setStatus(message, kind = "neutral") {
    els.status.dataset.kind = kind;
    els.statusText.textContent = message;
  }

  function setMessage(message, kind = "error") {
    els.authMessage.textContent = message;
    els.authMessage.dataset.kind = kind;
    els.authMessage.hidden = !message;
  }

  function setBusy(value) {
    busy = value;
    els.loginButton.disabled = value;
    els.twoFactorButton.disabled = value;
    els.openVerification.disabled = value;
    els.exportLogs.disabled = value;
  }

  async function refreshAuthState() {
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_STATUS" });
      if (!result?.ok) throw new Error(result?.error || "Không đọc được trạng thái đăng nhập Proton.");
      authState = {
        authenticated: Boolean(result.authenticated),
        needsTwoFactor: Boolean(result.needsTwoFactor),
        needsHumanVerification: Boolean(result.needsHumanVerification),
        verificationTokenCaptured: Boolean(result.verificationTokenCaptured),
      };
      const stateKey = JSON.stringify(authState);
      if (stateKey !== currentStateKey) {
        currentStateKey = stateKey;
        void diagnosticLog("auth_session_status", {
          authenticated: authState.authenticated,
          twoFactorPending: authState.needsTwoFactor,
          challengePending: authState.needsHumanVerification,
          challengeReady: authState.verificationTokenCaptured,
        });
      }
      if (authState.needsHumanVerification && !authState.verificationTokenCaptured) {
        automaticVerificationRetryUsed = false;
      }
      renderAuthState();
      maybeRetryAfterVerification();
      return authState;
    } catch (error) {
      setMessage(error?.message || "Không kiểm tra được phiên đăng nhập.");
      setStatus("Không đọc được trạng thái đăng nhập.", "error");
      void diagnosticLog("auth_status_failed", { errorName: error?.name || "Error" }, "error");
      throw error;
    }
  }

  function renderAuthState() {
    const { authenticated, needsTwoFactor, needsHumanVerification, verificationTokenCaptured } = authState;
    els.authPanel.hidden = authenticated;
    els.successPanel.hidden = !authenticated;
    els.loginForm.hidden = authenticated || needsTwoFactor;
    els.twoFactorForm.hidden = authenticated || !needsTwoFactor;
    els.challengePanel.hidden = authenticated || !needsHumanVerification;

    if (needsTwoFactor) {
      els.authTitle.textContent = "Xác thực hai bước";
      els.authDescription.textContent = "Nhập mã 2FA để hoàn tất phiên Proton. Tab này sẽ giữ trạng thái khi bạn chuyển sang ứng dụng xác thực.";
      els.challengePanel.hidden = true;
      setStatus("Đang chờ mã 2FA Proton.", "loading");
    } else if (needsHumanVerification) {
      els.authTitle.textContent = "Proton yêu cầu xác minh người dùng";
      els.authDescription.textContent = pendingVerificationLogin
        ? "Hoàn tất xác minh trong cửa sổ Proton. Mật khẩu đang được giữ tạm trong tab này và sẽ tự gửi lại sau khi xác minh."
        : "Hoàn tất xác minh trong cửa sổ Proton đã mở. Cửa sổ sẽ tự đóng khi extension nhận được kết quả.";
      els.challengeMessage.textContent = verificationTokenCaptured
        ? pendingVerificationLogin
          ? "Đã xác minh. Extension đang gửi lại thông tin đăng nhập đã nhập; bạn không cần nhập mật khẩu lần nữa."
          : "Đã nhận kết quả xác minh. Nhập mật khẩu rồi gửi lại đăng nhập."
          : "Mở cửa sổ challenge Proton, hoàn tất xác minh. Cửa sổ sẽ tự đóng khi extension nhận được kết quả; tab đăng nhập này vẫn giữ nguyên trạng thái.";
      els.openVerification.hidden = verificationTokenCaptured;
      setStatus(verificationTokenCaptured ? "Đã nhận kết quả xác minh Proton." : "Đang chờ xác minh Proton.", verificationTokenCaptured ? "success" : "loading");
    } else if (authenticated) {
      setStatus("Đăng nhập Proton thành công.", "success");
    } else {
      els.authTitle.textContent = "Đăng nhập Proton VPN";
      els.authDescription.textContent = "Đăng nhập SRP trực tiếp với Proton. Nếu cần xác minh, mật khẩu chỉ được giữ tạm trong tab này để tự gửi lại; không ghi vào storage hoặc log.";
      els.openVerification.hidden = true;
      setStatus("Nhập thông tin Proton để tiếp tục.");
    }
  }

  async function submitLogin(event) {
    event.preventDefault();
    if (busy) return;
    const username = els.username.value.trim();
    const password = els.password.value;
    if (!username || !password) {
      setMessage("Nhập username hoặc email và mật khẩu Proton.");
      return;
    }
    await performLogin(username, password);
  }

  function maybeRetryAfterVerification() {
    if (busy || automaticVerificationRetryUsed || !pendingVerificationLogin) return;
    if (!authState.needsHumanVerification || !authState.verificationTokenCaptured) return;
    automaticVerificationRetryUsed = true;
    void performLogin(pendingVerificationLogin.username, pendingVerificationLogin.password, { verificationRetry: true });
  }

  async function performLogin(username, password, { verificationRetry = false } = {}) {
    if (busy) return;
    setBusy(true);
    setMessage("");
    setStatus(verificationRetry ? "Đã xác minh. Đang gửi lại đăng nhập với SRP…" : "Đang xác thực trực tiếp với Proton bằng SRP…", "loading");
    void diagnosticLog("srp_login_submitted", {
      challengePending: authState.needsHumanVerification,
      challengeReady: authState.verificationTokenCaptured,
      verificationRetry,
    });
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_LOGIN", username, password });
      if (!result?.ok) throw new Error(result?.error || "Không đăng nhập được với Proton.");
      if (result.needsHumanVerification) {
        pendingVerificationLogin = { username, password };
        els.username.value = username;
        els.password.value = password;
      } else {
        pendingVerificationLogin = null;
        els.password.value = "";
      }
      await refreshAuthState();
      if (result.needsHumanVerification && !authState.verificationTokenCaptured) setStatus("Proton đang chờ xác minh người dùng.", "loading");
      else if (result.needsHumanVerification) setStatus("Đã xác minh. Đang gửi lại đăng nhập…", "loading");
      else if (result.needsTwoFactor) els.twoFactorCode.focus();
      else if (result.authenticated) setMessage("Đăng nhập Proton thành công.", "success");
    } catch (error) {
      await refreshAuthState().catch(() => undefined);
      if (authState.needsHumanVerification) {
        pendingVerificationLogin = { username, password };
        els.username.value = username;
        els.password.value = password;
      } else {
        pendingVerificationLogin = null;
        els.password.value = "";
      }
      setMessage(error?.message || "Không đăng nhập được với Proton.");
      setStatus(error?.message || "Không đăng nhập được với Proton.", "error");
      void diagnosticLog("srp_login_failed", { errorName: error?.name || "Error" }, "error");
    } finally {
      setBusy(false);
      maybeRetryAfterVerification();
    }
  }

  async function submitTwoFactor(event) {
    event.preventDefault();
    if (busy) return;
    const code = els.twoFactorCode.value.trim();
    if (!code) {
      setMessage("Nhập mã 2FA để tiếp tục.");
      return;
    }
    setBusy(true);
    setMessage("");
    setStatus("Đang xác nhận mã 2FA với Proton…", "loading");
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_COMPLETE_2FA", code });
      els.twoFactorCode.value = "";
      if (!result?.ok) throw new Error(result?.error || "Mã 2FA chưa được chấp nhận.");
      await refreshAuthState();
      if (result.authenticated) setMessage("Đăng nhập Proton thành công.", "success");
    } catch (error) {
      els.twoFactorCode.value = "";
      setMessage(error?.message || "Mã 2FA chưa được chấp nhận.");
      setStatus(error?.message || "Mã 2FA chưa được chấp nhận.", "error");
      void diagnosticLog("srp_two_factor_failed", { errorName: error?.name || "Error" }, "error");
      await refreshAuthState().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }

  async function openVerification() {
    if (busy) return;
    setBusy(true);
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_OPEN_VERIFICATION" });
      if (!result?.ok) throw new Error(result?.error || "Không mở được cửa sổ xác minh Proton.");
      setStatus("Đã mở cửa sổ xác minh Proton. Cửa sổ tự đóng khi xác minh hoàn tất.", "loading");
      void diagnosticLog("open_proton_page_for_verification");
    } catch (error) {
      setMessage(error?.message || "Không mở được cửa sổ xác minh Proton.");
      setStatus(error?.message || "Không mở được cửa sổ xác minh Proton.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function exportDiagnostics() {
    els.exportLogs.disabled = true;
    try {
      await diagnosticLog("diagnostic_export_requested");
      const result = await api.runtime.sendMessage({ type: "FREETON_GET_DIAGNOSTICS" });
      if (!result?.ok) throw new Error(result?.error || "Không đọc được log.");
      const report = {
        format: "Freeton Browser VPN diagnostics",
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        extensionVersion: api.runtime.getManifest().version,
        browserUserAgent: navigator.userAgent,
        privacy: "Không gồm URL đầy đủ, cookie, mật khẩu, tên tài khoản, phiên Proton, access/refresh token hoặc proxy password.",
        logs: result.logs,
      };
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `freeton-debug-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 30000);
      setStatus(`Đã tạo log chẩn đoán (${result.logs.length} sự kiện).`, "success");
    } catch (error) {
      setStatus(error?.message || "Không thể tạo log chẩn đoán.", "error");
    } finally {
      els.exportLogs.disabled = false;
    }
  }

  async function clearDiagnostics() {
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_CLEAR_DIAGNOSTICS" });
      if (!result?.ok) throw new Error(result?.error || "Không xóa được log.");
      setStatus("Đã xóa log chẩn đoán trên trình duyệt này.");
    } catch (error) {
      setStatus(error?.message || "Không thể xóa log chẩn đoán.", "error");
    }
  }

  els.loginForm.addEventListener("submit", submitLogin);
  els.twoFactorForm.addEventListener("submit", submitTwoFactor);
  els.openVerification.addEventListener("click", openVerification);
  api.runtime.onMessage.addListener((message) => {
    if (message?.type === "FREETON_HUMAN_VERIFICATION_UPDATED") {
      void refreshAuthState().catch(() => undefined);
    }
  });
  els.exportLogs.addEventListener("click", exportDiagnostics);
  els.clearLogs.addEventListener("click", clearDiagnostics);
  window.addEventListener("focus", () => { void refreshAuthState().catch(() => undefined); });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) void refreshAuthState().catch(() => undefined);
  });

  void diagnosticLog("login_tab_opened", { extensionVersion: api.runtime.getManifest().version });
  void refreshAuthState().catch(() => undefined);
})();
