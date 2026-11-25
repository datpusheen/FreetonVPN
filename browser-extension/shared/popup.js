(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const diagnosticLog = (event, details = {}, level = "info") =>
    globalThis.FreetonDiagnostics?.log("popup", event, details, level);
  const els = Object.fromEntries([
    "status", "statusText", "refresh", "renew", "disconnect", "logout", "search", "country", "summary", "nodes",
    "empty", "emptyTitle", "emptyMessage", "exportLogs", "clearLogs",
    "authPanel", "authTitle", "authDescription", "authMessage", "openLoginPage",
  ].map((id) => [id, document.getElementById(id)]));

  let allNodes = [];
  let activeConnection = null;
  let busy = false;
  let authenticated = false;
  let needsTwoFactor = false;
  let needsHumanVerification = false;
  let humanVerificationTokenCaptured = false;

  function setStatus(message, kind = "neutral") {
    els.status.dataset.kind = kind;
    els.statusText.textContent = message;
  }

  function displayCountry(code) {
    if (!code) return "Không rõ quốc gia";
    try { return new Intl.DisplayNames(["vi"], { type: "region" }).of(code) || code; }
    catch { return code; }
  }

  function flagEmoji(code) {
    if (!/^[A-Z]{2}$/.test(code || "")) return "🌐";
    return [...code].map((letter) => String.fromCodePoint(letter.charCodeAt(0) + 127397)).join("");
  }

  function setBusy(value) {
    busy = value;
    els.refresh.disabled = value;
    els.renew.disabled = value;
    els.disconnect.disabled = value;
    els.logout.disabled = value;
    els.openLoginPage.disabled = value;
    els.nodes.querySelectorAll(".connect-button").forEach((button) => { button.disabled = value; });
    els.refresh.classList.toggle("spinning", value);
  }

  function updateConnectionControls() {
    const connected = Boolean(activeConnection);
    els.renew.hidden = !connected;
    els.disconnect.hidden = !connected;
    if (allNodes.length) renderNodes();
  }

  function formatExpiry(expiresAt) {
    const remaining = Math.max(0, Number(expiresAt) - Date.now());
    const minutes = Math.ceil(remaining / 60000);
    return minutes ? `token còn khoảng ${minutes} phút` : "token đã hết hạn · hãy gia hạn";
  }

  async function refreshConnectionState() {
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_STATUS" });
      activeConnection = result?.ok && result.connected ? result.connection : null;
      void diagnosticLog("connection_status", { connected: Boolean(activeConnection) });
      updateConnectionControls();
      if (activeConnection) {
        const kind = Date.now() < activeConnection.expiresAt ? "success" : "error";
        setStatus(`${activeConnection.name} · ${formatExpiry(activeConnection.expiresAt)}`, kind);
      }
    } catch (error) {
      void diagnosticLog("connection_status_failed", { error: error?.message || "Unknown error" }, "error");
      activeConnection = null;
      updateConnectionControls();
    }
  }

  async function refreshAuthState() {
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_STATUS" });
      if (!result?.ok) throw new Error(result?.error || "Không đọc được trạng thái đăng nhập Proton.");
      authenticated = Boolean(result.authenticated);
      needsTwoFactor = Boolean(result.needsTwoFactor);
      needsHumanVerification = Boolean(result.needsHumanVerification);
      humanVerificationTokenCaptured = Boolean(result.verificationTokenCaptured);
      void diagnosticLog("auth_session_status", {
        authenticated,
        twoFactorPending: needsTwoFactor,
        challengePending: needsHumanVerification,
        challengeReady: humanVerificationTokenCaptured,
      });
      els.authPanel.hidden = authenticated;
      els.logout.hidden = !authenticated;
      if (needsTwoFactor) {
        els.authTitle.textContent = "Đang chờ xác thực hai bước";
        els.authDescription.textContent = "Hoàn tất mã 2FA trong tab đăng nhập Freeton đang mở. Nếu đã đóng tab, bấm bên dưới để mở lại luồng đăng nhập.";
        els.authMessage.hidden = true;
      } else if (needsHumanVerification) {
        els.authTitle.textContent = "Đang chờ xác minh Proton";
        els.authDescription.textContent = humanVerificationTokenCaptured
          ? "Đã nhận kết quả xác minh. Quay lại tab đăng nhập Freeton, nhập lại mật khẩu rồi tiếp tục."
          : "Hoàn tất challenge Proton trong tab xác minh rồi quay lại tab đăng nhập Freeton.";
        els.authMessage.hidden = true;
      } else {
        els.authTitle.textContent = "Đăng nhập Proton VPN";
        els.authDescription.textContent = "Mở trang đăng nhập riêng để hoàn tất SRP, CAPTCHA hoặc 2FA. Popup này dùng để chọn máy chủ và bật/tắt kết nối sau khi đăng nhập.";
        els.authMessage.hidden = true;
      }
      return authenticated;
    } catch (error) {
      authenticated = false;
      needsTwoFactor = false;
      needsHumanVerification = false;
      humanVerificationTokenCaptured = false;
      els.authPanel.hidden = false;
      els.logout.hidden = true;
      els.authMessage.textContent = error?.message || "Không kiểm tra được phiên đăng nhập.";
      els.authMessage.dataset.kind = "error";
      els.authMessage.hidden = false;
      void diagnosticLog("auth_status_failed", { errorName: error?.name || "Error" }, "error");
      return false;
    }
  }

  async function openLoginPage() {
    if (busy) return;
    setBusy(true);
    void diagnosticLog("open_login_tab_requested");
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_OPEN_LOGIN_PAGE" });
      if (!result?.ok) throw new Error(result?.error || "Không mở được trang đăng nhập riêng.");
      setStatus("Đã mở tab đăng nhập Freeton.", "success");
      return true;
    } catch (error) {
      setStatus(error?.message || "Không mở được trang đăng nhập riêng.", "error");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function logoutProton() {
    if (busy) return;
    setBusy(true);
    setStatus("Đang xóa phiên Proton và ngắt proxy…", "loading");
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_AUTH_LOGOUT" });
      if (!result?.ok) throw new Error(result?.error || "Không thể đăng xuất Proton.");
      activeConnection = null;
      authenticated = false;
      needsTwoFactor = false;
      needsHumanVerification = false;
      humanVerificationTokenCaptured = false;
      els.logout.hidden = true;
      showEmpty("Đã đăng xuất Proton", "Đăng nhập lại bằng SRP để tải danh sách máy chủ.");
      await refreshAuthState();
      setStatus("Đã xóa phiên Proton.", "neutral");
    } catch (error) {
      setStatus(error?.message || "Không thể đăng xuất Proton.", "error");
    } finally {
      setBusy(false);
    }
  }

  function showEmpty(title, message) {
    els.emptyTitle.textContent = title;
    els.emptyMessage.textContent = message;
    els.empty.hidden = false;
    els.summary.hidden = true;
    els.nodes.replaceChildren();
  }

  function updateCountryOptions(nodes) {
    const previous = els.country.value;
    const countries = [...new Set(nodes.map((node) => node.country).filter(Boolean))]
      .sort((a, b) => displayCountry(a).localeCompare(displayCountry(b), "vi"));
    els.country.replaceChildren(new Option("Mọi quốc gia", ""));
    for (const code of countries) els.country.add(new Option(`${flagEmoji(code)} ${displayCountry(code)}`, code));
    if (countries.includes(previous)) els.country.value = previous;
  }

  function makeNodeCard(node, index) {
    const card = document.createElement("article");
    const isConnected = activeConnection?.proxyHost === node.proxyHost;
    card.className = `node-card${index === 0 ? " best" : ""}`;

    const heading = document.createElement("div");
    heading.className = "node-heading";
    const flag = document.createElement("span");
    flag.className = "flag";
    flag.textContent = flagEmoji(node.country);
    flag.setAttribute("aria-hidden", "true");
    const title = document.createElement("strong");
    title.className = "node-title";
    title.textContent = node.name || "Proton Free";
    heading.append(flag, title);
    if (index === 0) {
      const badge = document.createElement("span");
      badge.className = "best-badge";
      badge.textContent = "TẢI THẤP NHẤT";
      heading.append(badge);
    }

    const location = document.createElement("div");
    location.className = "node-location";
    location.textContent = [node.city, displayCountry(node.country)].filter(Boolean).join(" · ");

    const stats = document.createElement("div");
    stats.className = "node-stats";
    const load = Number.isFinite(Number(node.load)) ? Math.max(0, Math.min(100, Number(node.load))) : 0;
    const loadLabel = document.createElement("span");
    loadLabel.className = "load-label";
    loadLabel.append(document.createTextNode(`Tải ${load}%`));
    const track = document.createElement("span");
    track.className = "load-track";
    const fill = document.createElement("span");
    fill.className = `load-fill${load >= 70 ? " high" : load >= 40 ? " medium" : ""}`;
    fill.style.width = `${load}%`;
    track.append(fill);
    loadLabel.append(track);
    const physical = document.createElement("span");
    physical.className = "physical-count";
    physical.textContent = `${node.activePhysicalServers} node hoạt động`;
    stats.append(loadLabel, physical);

    card.append(heading, location, stats);
    if (node.entryIP) {
      const entry = document.createElement("div");
      entry.className = "entry";
      entry.textContent = `Endpoint: ${node.entryIP}`;
      card.append(entry);
    }
    const actions = document.createElement("div");
    actions.className = "node-actions";
    const connect = document.createElement("button");
    connect.type = "button";
    connect.className = `connect-button${isConnected ? " connected" : ""}`;
    connect.textContent = isConnected ? "Đang dùng" : "Kết nối";
    connect.disabled = busy;
    connect.addEventListener("click", () => connectNode(node));
    actions.append(connect);
    card.append(actions);
    return card;
  }

  function renderNodes() {
    const query = els.search.value.trim().toLocaleLowerCase("vi");
    const country = els.country.value;
    const visible = allNodes
      .filter((node) => !country || node.country === country)
      .filter((node) => {
        const haystack = `${node.name} ${node.country} ${displayCountry(node.country)} ${node.city}`.toLocaleLowerCase("vi");
        return !query || haystack.includes(query);
      })
      .sort((a, b) => a.load - b.load || a.name.localeCompare(b.name));

    els.nodes.replaceChildren(...visible.map(makeNodeCard));
    els.empty.hidden = visible.length > 0;
    els.emptyTitle.textContent = "Không tìm thấy node";
    els.emptyMessage.textContent = "Thử từ khóa hoặc quốc gia khác.";
    els.summary.hidden = false;
    els.summary.replaceChildren();
    const strong = document.createElement("strong");
    strong.textContent = `${visible.length} / ${allNodes.length} node`;
    els.summary.append(strong, document.createTextNode(" · xếp theo tải thấp đến cao"));
  }

  async function connectNode(node) {
    if (busy) return;
    setBusy(true);
    setStatus(`Đang xin proxy token và kết nối ${node.name}…`, "loading");
    void diagnosticLog("connect_started", { nodeName: node.name, country: node.country });
    try {
      const response = await api.runtime.sendMessage({ type: "FREETON_GET_PROXY_CREDENTIALS" });
      if (!response?.ok) throw new Error(response?.error || "Không lấy được proxy token từ Proton.");
      const result = await api.runtime.sendMessage({
        type: "FREETON_CONNECT",
        node: { name: node.name, country: node.country, proxyHost: node.proxyHost, proxyPort: node.proxyPort },
        credentials: {
          username: response.username,
          password: response.password,
          expiresAt: response.expiresAt,
        },
      });
      if (!result?.ok) throw new Error(result?.error || "Không thể cấu hình proxy.");
      activeConnection = { ...node, ...result.connection };
      void diagnosticLog("connect_succeeded", {
        nodeName: node.name,
        country: node.country,
        tokenLifetimeMinutes: Math.max(0, Math.ceil((activeConnection.expiresAt - Date.now()) / 60000)),
      });
      updateConnectionControls();
      setStatus(`Đã kết nối browser qua ${node.name} · ${formatExpiry(activeConnection.expiresAt)}`, "success");
    } catch (error) {
      void diagnosticLog("connect_failed", { nodeName: node.name, country: node.country, error: error?.message || "Unknown error" }, "error");
      setStatus(error?.message || "Không thể kết nối máy chủ.", "error");
    } finally {
      setBusy(false);
      renderNodes();
    }
  }

  async function renewConnection() {
    if (!activeConnection || busy) return;
    await connectNode(activeConnection);
  }

  async function disconnect() {
    if (busy) return;
    setBusy(true);
    setStatus("Đang ngắt proxy của trình duyệt…", "loading");
    void diagnosticLog("disconnect_started");
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_DISCONNECT" });
      if (!result?.ok) throw new Error(result?.error || "Không thể ngắt proxy.");
      activeConnection = null;
      void diagnosticLog("disconnect_succeeded");
      updateConnectionControls();
      setStatus("Đã ngắt kết nối trình duyệt.", "neutral");
    } catch (error) {
      void diagnosticLog("disconnect_failed", { error: error?.message || "Unknown error" }, "error");
      setStatus(error?.message || "Không thể ngắt kết nối.", "error");
    } finally {
      setBusy(false);
      renderNodes();
    }
  }

  async function scan(allowBusy = false) {
    if (busy && !allowBusy) return;
    if (!authenticated) {
      els.authPanel.hidden = false;
      showEmpty("Đăng nhập Proton", "Đăng nhập bằng SRP để tải danh sách máy chủ.");
      return;
    }
    setBusy(true);
    setStatus("Đang lấy danh sách máy chủ từ Proton…", "loading");
    void diagnosticLog("node_scan_started");
    els.empty.hidden = true;
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_FETCH_NODES" });
      if (!result?.ok) throw new Error(result?.error || "Không thể tải danh sách máy chủ Proton.");
      allNodes = result.nodes;
      void diagnosticLog("node_scan_succeeded", { nodeCount: allNodes.length });
      updateCountryOptions(allNodes);
      renderNodes();
      const stamp = new Date().toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
      const connectedText = activeConnection ? ` · đang dùng ${activeConnection.name}` : "";
      setStatus(`Đã cập nhật ${allNodes.length} máy chủ lúc ${stamp}${connectedText}.`, "success");
    } catch (error) {
      void diagnosticLog("node_scan_failed", { error: error?.message || "Unknown error" }, "error");
      allNodes = [];
      els.nodes.replaceChildren();
      const message = error?.message || "Không thể tải danh sách máy chủ.";
      setStatus(activeConnection ? `${activeConnection.name} · ${formatExpiry(activeConnection.expiresAt)}` : "Không đọc được dữ liệu Proton.", activeConnection ? "success" : "error");
      showEmpty("Không kết nối được Proton", message);
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
      const manifest = api.runtime.getManifest();
      const report = {
        format: "Freeton Browser VPN diagnostics",
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        extensionVersion: manifest.version,
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
      void diagnosticLog("diagnostic_export_failed", { error: error?.message || "Unknown error" }, "error");
      setStatus(error?.message || "Không thể tạo log chẩn đoán.", "error");
    } finally {
      els.exportLogs.disabled = false;
    }
  }

  async function clearDiagnostics() {
    try {
      const result = await api.runtime.sendMessage({ type: "FREETON_CLEAR_DIAGNOSTICS" });
      if (!result?.ok) throw new Error(result?.error || "Không xóa được log.");
      setStatus("Đã xóa log chẩn đoán trên trình duyệt này.", "neutral");
    } catch (error) {
      setStatus(error?.message || "Không thể xóa log.", "error");
    }
  }

  els.refresh.addEventListener("click", scan);
  els.renew.addEventListener("click", renewConnection);
  els.disconnect.addEventListener("click", disconnect);
  els.logout.addEventListener("click", logoutProton);
  els.openLoginPage.addEventListener("click", openLoginPage);
  els.search.addEventListener("input", renderNodes);
  els.country.addEventListener("change", renderNodes);
  els.exportLogs.addEventListener("click", exportDiagnostics);
  els.clearLogs.addEventListener("click", clearDiagnostics);
  void diagnosticLog("popup_opened", {
    extensionVersion: api.runtime.getManifest().version,
    browser: /Firefox/i.test(navigator.userAgent) ? "firefox" : "chromium",
  });
  void refreshConnectionState();
  refreshAuthState().then(async (hasAuth) => {
    if (hasAuth) return scan();
    showEmpty(needsTwoFactor ? "Cần mã xác thực 2FA" : "Đăng nhập Proton", needsTwoFactor
      ? "Nhập mã 2FA để tiếp tục đăng nhập."
      : "Đăng nhập bằng SRP để tải danh sách máy chủ.");
    setStatus(needsTwoFactor ? "Đang chờ mã 2FA Proton." : "Đăng nhập Proton để bắt đầu.", needsTwoFactor ? "loading" : "neutral");
    if (await openLoginPage()) window.close();
    return undefined;
  });
})();
