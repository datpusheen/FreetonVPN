if (typeof importScripts === "function") importScripts("bcrypt.js", "openpgp.js", "proton-srp.js");

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const STORAGE_KEY = "freetonProxyConnection";
  const DIAGNOSTICS_KEY = "freetonDiagnostics";
  const AUTH_KEY = "freetonProtonAuthSession";
  const PENDING_AUTH_KEY = "freetonProtonPendingAuth";
  const HUMAN_VERIFICATION_KEY = "freetonProtonHumanVerification";
  const LOGIN_PAGE_TAB_KEY = "freetonLoginPageTabId";
  const AUTH_API_BASE = "https://api.protonmail.ch";
  const VPN_API_BASES = [
    "https://account.protonvpn.com/api",
    "https://api.protonmail.ch",
    "https://account.proton.me/api",
  ];
  const PROTON_APP_VERSION = "Other";
  const PROTON_BROWSER_APP_VERSION = "browser-vpn@1.3.6";
  const MAX_DIAGNOSTIC_ENTRIES = 300;
  const usesFirefoxProxyApi = Boolean(api.proxy?.onRequest?.addListener);
  const ACCOUNT_HOSTS = new Set(["account.protonvpn.com", "account.proton.me"]);
  let diagnosticWriteQueue = Promise.resolve();
  let firefoxRouteLogged = false;
  let chromiumAuthLogged = false;

  function cleanDiagnosticValue(value, key = "", depth = 0) {
    if (/(?:url|token|password|secret|cookie|authorization|username|email|uid|credential|headers|body|access.?key)/i.test(key)) return undefined;
    if (typeof value === "string") {
      return value
        .replace(/\b(Bearer|Basic)\s+[^\s,;]+/gi, "$1 [redacted]")
        .replace(/\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b/g, "[token redacted]")
        .replace(/https?:\/\/[^\s"'<>]+/gi, "[url redacted]")
        .replace(/\b[\w.+-]+@[\w.-]+\.[A-Z]{2,}\b/gi, "[email redacted]")
        .replace(/\b(access[_ -]?token|refresh[_ -]?token|auth[_ -]?token|password|token|authorization|cookie|username|uid)\b\s*[:=]\s*[^\s,;]+/gi, "$1=[redacted]")
        .slice(0, 300);
    }
    if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
    if (Array.isArray(value)) return value.slice(0, 12).map((item) => cleanDiagnosticValue(item, "", depth + 1)).filter((item) => item !== undefined);
    if (typeof value !== "object" || depth >= 2) return undefined;
    const clean = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      const item = cleanDiagnosticValue(childValue, childKey, depth + 1);
      if (item !== undefined) clean[childKey.slice(0, 48)] = item;
    }
    return clean;
  }

  function storeDiagnostic(entry) {
    const safeEntry = {
      at: /^\d{4}-\d\d-\d\dT/.test(entry?.at || "") ? entry.at : new Date().toISOString(),
      source: ["popup", "content", "background"].includes(entry?.source) ? entry.source : "unknown",
      level: ["info", "warn", "error"].includes(entry?.level) ? entry.level : "info",
      event: String(entry?.event || "unknown").replace(/[^a-z0-9_.-]/gi, "_").slice(0, 64),
      details: cleanDiagnosticValue(entry?.details || {}) || {},
    };
    diagnosticWriteQueue = diagnosticWriteQueue.then(async () => {
      const stored = await api.storage.local.get(DIAGNOSTICS_KEY);
      const entries = Array.isArray(stored[DIAGNOSTICS_KEY]) ? stored[DIAGNOSTICS_KEY] : [];
      entries.push(safeEntry);
      await api.storage.local.set({ [DIAGNOSTICS_KEY]: entries.slice(-MAX_DIAGNOSTIC_ENTRIES) });
    }).catch(() => undefined);
    return diagnosticWriteQueue;
  }

  function logDiagnostic(event, details = {}, level = "info") {
    return storeDiagnostic({ source: "background", event, level, at: new Date().toISOString(), details });
  }

  function isAllowedProxyHost(host) {
    return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*protonvpn\.(?:net|com)$/i.test(host || "");
  }

  function shouldUseDirect(hostname) {
    const host = (hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
    if (ACCOUNT_HOSTS.has(host) || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
    if (host === "::1" || host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) return true;
    const octets = host.split(".").map(Number);
    if (octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
      const [a, b] = octets;
      return a === 0 || a === 10 || a === 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168;
    }
    return false;
  }

  async function getConnection() {
    const stored = await api.storage.session.get(STORAGE_KEY);
    return stored[STORAGE_KEY] || null;
  }

  async function setConnection(connection) {
    await api.storage.session.set({ [STORAGE_KEY]: connection });
  }

  async function setWebRTCProtection(enabled) {
    const setting = api.privacy?.network?.webRTCIPHandlingPolicy;
    if (!setting) return;
    try {
      if (enabled) await setting.set({ value: "disable_non_proxied_udp", scope: "regular" });
      else await setting.clear({ scope: "regular" });
    } catch {
      // Some managed browsers do not allow extensions to change this setting.
    }
  }

  function clearChromiumProxy() {
    if (usesFirefoxProxyApi || !api.proxy?.settings) return Promise.resolve(true);
    return new Promise((resolve) => {
      api.proxy.settings.clear({ scope: "regular" }, () => resolve(!api.runtime.lastError));
    });
  }

  function setChromiumProxy(connection) {
    const bypassList = [
      "localhost", "*.localhost", "<local>", "127.0.0.1", "[::1]",
      "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
      "account.protonvpn.com", "account.proton.me",
    ];
    return new Promise((resolve, reject) => {
      api.proxy.settings.set({
        value: {
          mode: "fixed_servers",
          rules: {
            singleProxy: { scheme: "https", host: connection.proxyHost, port: connection.proxyPort },
            bypassList,
          },
        },
        scope: "regular",
      }, () => {
        const error = api.runtime.lastError;
        if (error) {
          reject(new Error(error.message || "Trình duyệt không cho phép đổi proxy."));
          return;
        }
        api.proxy.settings.get({ incognito: false }, (details) => {
          if (api.runtime.lastError || details?.levelOfControl !== "controlled_by_this_extension") {
            reject(new Error("Một extension hoặc chính sách khác đang quản lý proxy của trình duyệt."));
            return;
          }
          resolve(true);
        });
      });
    });
  }

  async function connect(message) {
    const node = message?.node || {};
    const credentials = message?.credentials || {};
    const port = Number(node.proxyPort);
    firefoxRouteLogged = false;
    chromiumAuthLogged = false;
    await logDiagnostic("proxy_configuration_started", {
      mode: usesFirefoxProxyApi ? "firefox_proxy_api" : "chromium_proxy_api",
      nodeName: String(node.name || ""),
      country: String(node.country || ""),
      proxyPort: port,
      userFieldPresent: Boolean(credentials.username),
      secretFieldPresent: Boolean(credentials.password),
      expired: Number(credentials.expiresAt) <= Date.now(),
    });
    if (!isAllowedProxyHost(node.proxyHost)) throw new Error("Proxy host không thuộc miền máy chủ Proton VPN.");
    if (!Number.isInteger(port) || !(port === 443 || port >= 4443 && port <= 4454)) {
      throw new Error("Cổng proxy của máy chủ không hợp lệ.");
    }
    if (!credentials.username || !credentials.password || Number(credentials.expiresAt) <= Date.now()) {
      throw new Error("Proxy token thiếu hoặc đã hết hạn. Hãy gia hạn rồi thử lại.");
    }

    const connection = {
      name: String(node.name || "Proton VPN"),
      country: String(node.country || ""),
      proxyHost: String(node.proxyHost),
      proxyPort: port,
      username: String(credentials.username),
      password: String(credentials.password),
      expiresAt: Number(credentials.expiresAt),
      connectedAt: Date.now(),
    };

    await setConnection(connection);
    await setWebRTCProtection(true);
    if (!usesFirefoxProxyApi) {
      try {
        await setChromiumProxy(connection);
      } catch (error) {
        await api.storage.session.remove(STORAGE_KEY);
        await clearChromiumProxy();
        await setWebRTCProtection(false);
        throw error;
      }
    }
    await logDiagnostic("proxy_configuration_succeeded", { mode: usesFirefoxProxyApi ? "firefox_proxy_api" : "chromium_proxy_api", proxyPort: port });
    return { name: connection.name, proxyHost: connection.proxyHost, expiresAt: connection.expiresAt };
  }

  async function disconnect() {
    await logDiagnostic("proxy_disconnect_started");
    await api.storage.session.remove(STORAGE_KEY);
    const cleared = await clearChromiumProxy();
    await setWebRTCProtection(false);
    if (!cleared) throw new Error("Không thể xóa cấu hình proxy của extension.");
    firefoxRouteLogged = false;
    chromiumAuthLogged = false;
    await logDiagnostic("proxy_disconnect_succeeded");
    return true;
  }

  async function status() {
    const connection = await getConnection();
    if (!connection) return { connected: false };
    return {
      connected: true,
      connection: {
        name: connection.name,
        country: connection.country,
        proxyHost: connection.proxyHost,
        proxyPort: connection.proxyPort,
        expiresAt: connection.expiresAt,
      },
    };
  }

  function protonErrorMessage(code, httpStatus, path = "") {
    if (Number(code) === 9001) return "Proton yêu cầu CAPTCHA hoặc xác minh người dùng. Hoàn tất xác minh trên tài khoản Proton rồi thử lại.";
    if (Number(code) === 12087) return "Token xác minh Proton không còn hợp lệ. Hãy mở lại trang challenge rồi thử lại.";
    if (Number(code) === 5003) return "Proton yêu cầu cập nhật phiên bản client (mã 5003). Hãy cập nhật extension Freeton rồi thử lại.";
    if (Number(code) === 8002 && path === "auth") return "Proton không chấp nhận lần đăng nhập SRP (mã 8002). Kiểm tra username/email và mật khẩu; nếu chắc đúng, chờ một lúc rồi thử lại.";
    if (Number(code) === 8002) return "Proton tạm từ chối bước đăng nhập này (mã 8002). Hãy kiểm tra thông tin đăng nhập và thử lại sau.";
    if (httpStatus === 429) return "Proton đang giới hạn số lần đăng nhập. Chờ một lúc rồi thử lại.";
    if (httpStatus === 401) return "Proton từ chối thông tin đăng nhập hoặc mã 2FA.";
    if (Number.isFinite(Number(code)) && Number(code) > 0) return `Proton API trả về mã ${Number(code)} (HTTP ${httpStatus || "?"}).`;
    return `Proton API trả về lỗi HTTP ${httpStatus || "không xác định"}.`;
  }

  async function protonApiRequest(base, path, { method = "GET", body, auth, headers: extraHeaders = {} } = {}) {
    const headers = {
      Accept: "application/vnd.protonmail.v1+json",
      "x-pm-appversion": PROTON_APP_VERSION,
      "x-pm-locale": "en_US",
      ...extraHeaders,
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth?.UID) headers["x-pm-uid"] = auth.UID;
    if (auth?.AccessToken) headers.Authorization = `Bearer ${auth.AccessToken}`;

    let response;
    try {
      response = await fetch(`${base.replace(/\/+$/, "")}/${String(path).replace(/^\/+/, "")}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      });
    } catch (cause) {
      const error = new Error("Không thể kết nối Proton API từ extension.");
      error.network = true;
      error.endpoint = path;
      error.cause = cause;
      throw error;
    }

    let payload = {};
    try { payload = await response.json(); } catch {}
    const code = Number(payload?.Code);
    if (!response.ok || ![1000, 1001].includes(code)) {
      const error = new Error(protonErrorMessage(code, response.status, path));
      error.httpStatus = response.status;
      error.apiCode = code || 0;
      error.endpoint = path;
      error.details = payload?.Details && typeof payload.Details === "object" ? payload.Details : {};
      throw error;
    }
    return payload;
  }

  function canTryAnotherApiHost(error) {
    return Boolean(error?.network || [401, 403, 404, 405, 502, 503].includes(Number(error?.httpStatus)));
  }

  async function refreshProtonAuth(auth) {
    if (!auth?.UID || !auth?.RefreshToken) throw new Error("Phiên Proton hết hạn. Hãy đăng nhập lại.");
    const payload = await protonApiRequest(AUTH_API_BASE, "auth/v4/refresh", {
      method: "POST",
      body: { ResponseType: "token", GrantType: "refresh_token", RefreshToken: auth.RefreshToken },
      auth: { UID: auth.UID },
    });
    if (!payload.AccessToken) throw new Error("Proton không gia hạn được phiên. Hãy đăng nhập lại.");
    const next = {
      ...auth,
      AccessToken: String(payload.AccessToken),
      RefreshToken: String(payload.RefreshToken || auth.RefreshToken),
    };
    await api.storage.session.set({ [AUTH_KEY]: next });
    await logDiagnostic("proton_session_refreshed");
    return next;
  }

  async function getProtonAuth() {
    const stored = await api.storage.session.get(AUTH_KEY);
    return stored[AUTH_KEY] || null;
  }

  function createHumanVerificationUrl(details = {}) {
    let url;
    try {
      if (details.WebUrl) url = new URL(String(details.WebUrl));
      else {
        url = new URL("https://verify.proton.me/");
        const methods = Array.isArray(details.Methods) && details.Methods.length
          ? details.Methods.join(",")
          : "captcha";
        url.searchParams.set("methods", methods);
        if (details.HumanVerificationToken) url.searchParams.set("token", String(details.HumanVerificationToken));
      }
    } catch {
      throw new Error("Proton trả về đường dẫn xác minh không hợp lệ.");
    }
    const allowedHosts = new Set(["verify.proton.me", "account.proton.me", "account.protonvpn.com"]);
    if (url.protocol !== "https:" || !allowedHosts.has(url.hostname.toLowerCase())) {
      throw new Error("Proton trả về trang xác minh không thuộc miền Proton được hỗ trợ.");
    }
    url.searchParams.set("ForceWebMessaging", "1");
    return url.href;
  }

  async function saveHumanVerification(error) {
    const details = error?.details || {};
    const methods = Array.isArray(details.Methods)
      ? details.Methods.filter((method) => typeof method === "string").slice(0, 8)
      : [];
    const verification = {
      url: createHumanVerificationUrl(details),
      methods,
      challengeToken: String(details.HumanVerificationToken || ""),
      solvedToken: "",
      createdAt: Date.now(),
    };
    await api.storage.session.set({ [HUMAN_VERIFICATION_KEY]: verification });
    let host = "";
    try { host = new URL(verification.url).hostname; } catch {}
    void logDiagnostic("proton_human_verification_required", {
      host,
      methods,
      webUrlPresent: Boolean(details.WebUrl),
      challengeTokenPresent: Boolean(verification.challengeToken),
    }, "warn");
    return { authenticated: false, needsHumanVerification: true, verificationTokenCaptured: false };
  }

  async function extensionTabCall(method, ...args) {
    if (globalThis.browser?.tabs?.[method]) return globalThis.browser.tabs[method](...args);
    return new Promise((resolve, reject) => {
      api.tabs[method](...args, (result) => {
        const error = api.runtime.lastError;
        if (error) reject(new Error(error.message || `Không thể thao tác tab (${method}).`));
        else resolve(result);
      });
    });
  }

  async function extensionWindowCall(method, ...args) {
    if (globalThis.browser?.windows?.[method]) return globalThis.browser.windows[method](...args);
    return new Promise((resolve, reject) => {
      api.windows[method](...args, (result) => {
        const error = api.runtime.lastError;
        if (error) reject(new Error(error.message || `Không thể thao tác cửa sổ (${method}).`));
        else resolve(result);
      });
    });
  }

  async function openLoginPage() {
    const url = api.runtime.getURL("login.html");
    const stored = await api.storage.session.get(LOGIN_PAGE_TAB_KEY);
    const previousTabId = stored[LOGIN_PAGE_TAB_KEY];
    if (Number.isInteger(previousTabId)) {
      try {
        const existingTab = await extensionTabCall("get", previousTabId);
        if (existingTab?.url === url) {
          await extensionTabCall("update", previousTabId, { active: true });
          void logDiagnostic("login_tab_reused");
          return { opened: true, reused: true };
        }
      } catch {}
    }
    const tab = await extensionTabCall("create", { url });
    if (!Number.isInteger(tab?.id)) throw new Error("Không lấy được tab đăng nhập vừa mở.");
    await api.storage.session.set({ [LOGIN_PAGE_TAB_KEY]: tab.id });
    void logDiagnostic("login_tab_opened");
    return { opened: true, reused: false };
  }

  async function openHumanVerification() {
    const stored = await api.storage.session.get(HUMAN_VERIFICATION_KEY);
    const verification = stored[HUMAN_VERIFICATION_KEY];
    if (!verification?.url) throw new Error("Chưa có challenge xác minh Proton đang chờ. Hãy thử đăng nhập lại.");

    if (Number.isInteger(verification.windowId)) {
      try {
        await extensionWindowCall("update", verification.windowId, { focused: true });
        await logDiagnostic("proton_human_verification_window_reused");
        return { opened: true, reused: true, verificationTokenCaptured: Boolean(verification.solvedToken), presentation: "popup_window" };
      } catch {
        // The user may have closed the challenge window; create a fresh one below.
      }
    }

    const popup = await extensionWindowCall("create", {
      url: "about:blank",
      type: "popup",
      width: 520,
      height: 720,
      focused: true,
    });
    let tab = popup?.tabs?.[0];
    if (!Number.isInteger(tab?.id) && Number.isInteger(popup?.id)) {
      const tabs = await extensionTabCall("query", { windowId: popup.id });
      tab = tabs?.[0];
    }
    if (!Number.isInteger(tab?.id)) {
      if (Number.isInteger(popup?.id)) await extensionWindowCall("remove", popup.id).catch(() => undefined);
      throw new Error("Không lấy được cửa sổ xác minh Proton vừa mở.");
    }
    await api.storage.session.set({ [HUMAN_VERIFICATION_KEY]: { ...verification, tabId: tab.id, windowId: popup.id } });
    try {
      await extensionTabCall("update", tab.id, { url: verification.url, active: true });
    } catch (error) {
      await extensionWindowCall("remove", popup.id).catch(() => undefined);
      throw error;
    }
    await logDiagnostic("proton_human_verification_window_opened", {
      windowCreated: true,
      tokenAlreadyCaptured: Boolean(verification.solvedToken),
    });
    return { opened: true, verificationTokenCaptured: Boolean(verification.solvedToken), presentation: "popup_window" };
  }

  async function receiveHumanVerificationToken(token, sender) {
    let senderHost = "";
    try { senderHost = new URL(sender?.url || "").hostname.toLowerCase(); } catch {}
    if (senderHost !== "verify.proton.me" && senderHost !== "account.proton.me" && senderHost !== "account.protonvpn.com") {
      throw new Error("Token xác minh chỉ được nhận từ trang Proton đã mở cho challenge này.");
    }
    const value = String(token || "");
    if (value.length < 20 || value.length > 8192 || /^https?:\/\//i.test(value)) {
      throw new Error("Trang xác minh chưa trả về token hợp lệ.");
    }
    const stored = await api.storage.session.get(HUMAN_VERIFICATION_KEY);
    const verification = stored[HUMAN_VERIFICATION_KEY];
    if (!verification?.url) throw new Error("Không có challenge xác minh Proton đang chờ.");
    if (!Number.isInteger(verification.tabId) || sender?.tab?.id !== verification.tabId) {
      throw new Error("Token không đến từ cửa sổ challenge Proton vừa mở.");
    }
    await api.storage.session.set({ [HUMAN_VERIFICATION_KEY]: { ...verification, solvedToken: value } });
    try {
      const notification = api.runtime.sendMessage({ type: "FREETON_HUMAN_VERIFICATION_UPDATED" });
      if (notification?.catch) void notification.catch(() => undefined);
    } catch {}
    await logDiagnostic("proton_human_verification_token_received", {
      senderHost,
      tokenLength: value.length,
    });
    if (Number.isInteger(verification.windowId)) {
      await extensionWindowCall("remove", verification.windowId).catch(() => undefined);
      void logDiagnostic("proton_human_verification_window_closed", { reason: "token_received" });
    } else if (Number.isInteger(verification.tabId)) {
      await extensionTabCall("remove", verification.tabId).catch(() => undefined);
      void logDiagnostic("proton_human_verification_tab_closed", { reason: "token_received" });
    }
    return { received: true };
  }

  async function authenticatedVpnRequest(path, auth, headers = {}) {
    let lastError;
    for (const base of VPN_API_BASES) {
      try {
        return await protonApiRequest(base, path, { auth, headers });
      } catch (error) {
        lastError = error;
        if (!canTryAnotherApiHost(error)) throw error;
      }
    }

    if ([401, 403].includes(Number(lastError?.httpStatus)) && auth?.RefreshToken) {
      const refreshed = await refreshProtonAuth(auth);
      Object.assign(auth, refreshed);
      for (const base of VPN_API_BASES) {
        try {
          return await protonApiRequest(base, path, { auth: refreshed, headers });
        } catch (error) {
          lastError = error;
          if (!canTryAnotherApiHost(error)) throw error;
        }
      }
    }
    throw lastError || new Error("Không thể kết nối Proton VPN API.");
  }

  async function createProtonLogin(username, password) {
    if (!globalThis.FreetonProtonSRP?.createProof) throw new Error("Thư viện SRP Proton chưa được nạp.");
    void logDiagnostic("proton_srp_login_started", { usernamePresent: Boolean(username) });
    const storedVerification = await api.storage.session.get(HUMAN_VERIFICATION_KEY);
    const verification = storedVerification[HUMAN_VERIFICATION_KEY];
    const humanVerificationHeaders = verification?.solvedToken ? {
      "x-pm-human-verification-token": verification.solvedToken,
      "x-pm-human-verification-token-type": verification.methods?.join(",") || "captcha",
    } : {};
    if (verification?.solvedToken) void logDiagnostic("proton_srp_retry_with_human_verification", { challengeHeaderPresent: true });
    try {
      const info = await protonApiRequest(AUTH_API_BASE, "auth/info", {
        method: "POST",
        body: { Username: username },
        headers: humanVerificationHeaders,
      });
      if (!info.SRPSession || !info.ServerEphemeral || !info.Salt || !info.Modulus) {
        throw new Error("Proton chưa trả về đủ thông tin SRP để đăng nhập.");
      }

      const proof = await globalThis.FreetonProtonSRP.createProof(info, username, password);
      const authData = await protonApiRequest(AUTH_API_BASE, "auth", {
        method: "POST",
        body: {
          Username: username,
          ClientEphemeral: proof.ClientEphemeral,
          ClientProof: proof.ClientProof,
          SRPSession: info.SRPSession,
        },
        headers: humanVerificationHeaders,
      });
      if (!globalThis.FreetonProtonSRP.verifyServerProof(proof.expectedServerProof, authData.ServerProof)) {
        void logDiagnostic("proton_srp_server_proof_rejected", {}, "error");
        throw new Error("Không xác minh được phản hồi SRP của Proton. Extension đã từ chối phiên đăng nhập.");
      }
      if (!authData.UID || !authData.AccessToken || !authData.RefreshToken) {
        throw new Error("Proton không trả về đầy đủ thông tin phiên đăng nhập.");
      }

      const auth = {
        UID: String(authData.UID),
        AccessToken: String(authData.AccessToken),
        RefreshToken: String(authData.RefreshToken),
        Scopes: Array.isArray(authData.Scopes) ? authData.Scopes : [],
      };
      const needsTwoFactor = auth.Scopes.includes("twofactor");
      void logDiagnostic("proton_srp_auth_response_received", {
        twoFactorScopeRequired: needsTwoFactor,
        twoFactorMetadataPresent: Boolean(authData["2FA"]),
      });
      if (needsTwoFactor) {
        await api.storage.session.remove(AUTH_KEY);
        await api.storage.session.set({ [PENDING_AUTH_KEY]: auth });
        await api.storage.session.remove(HUMAN_VERIFICATION_KEY);
        void logDiagnostic("proton_srp_two_factor_required");
        return { authenticated: false, needsTwoFactor: true };
      }
      await api.storage.session.set({ [AUTH_KEY]: auth });
      await api.storage.session.remove([PENDING_AUTH_KEY, HUMAN_VERIFICATION_KEY]);
      void logDiagnostic("proton_srp_login_succeeded");
      return { authenticated: true, needsTwoFactor: false };
    } catch (error) {
      if ([9001, 12087].includes(Number(error?.apiCode))) return saveHumanVerification(error);
      if (verification?.solvedToken && Number(error?.apiCode) !== 8002) {
        await api.storage.session.remove(HUMAN_VERIFICATION_KEY);
      }
      throw error;
    }
  }

  async function completeProtonTwoFactor(code) {
    const stored = await api.storage.session.get(PENDING_AUTH_KEY);
    const pending = stored[PENDING_AUTH_KEY];
    if (!pending?.UID || !pending?.AccessToken) throw new Error("Không có phiên 2FA đang chờ. Đăng nhập lại bằng mật khẩu.");
    if (!String(code || "").trim()) throw new Error("Nhập mã 2FA để tiếp tục.");
    const result = await protonApiRequest(AUTH_API_BASE, "auth/2fa", {
      method: "POST",
      body: { TwoFactorCode: String(code).trim() },
      auth: pending,
    });
    if (Number(result.Code) !== 1000) throw new Error("Proton chưa xác nhận mã 2FA.");
    await api.storage.session.set({ [AUTH_KEY]: { ...pending, Scopes: Array.isArray(result.Scopes) ? result.Scopes : pending.Scopes } });
    await api.storage.session.remove(PENDING_AUTH_KEY);
    void logDiagnostic("proton_srp_two_factor_succeeded");
    return { authenticated: true, needsTwoFactor: false };
  }

  async function protonAuthStatus() {
    const stored = await api.storage.session.get([AUTH_KEY, PENDING_AUTH_KEY, HUMAN_VERIFICATION_KEY]);
    const verification = stored[HUMAN_VERIFICATION_KEY];
    return {
      authenticated: Boolean(stored[AUTH_KEY]?.AccessToken),
      needsTwoFactor: Boolean(stored[PENDING_AUTH_KEY]?.AccessToken),
      needsHumanVerification: Boolean(verification?.url),
      verificationTokenCaptured: Boolean(verification?.solvedToken),
    };
  }

  async function protonLogout() {
    await disconnect();
    await api.storage.session.remove([AUTH_KEY, PENDING_AUTH_KEY, HUMAN_VERIFICATION_KEY]);
    void logDiagnostic("proton_session_cleared");
    return { authenticated: false, needsTwoFactor: false };
  }

  async function getTierHeaders(auth) {
    try {
      const profile = await authenticatedVpnRequest("vpn/v2", auth);
      const user = profile?.User || profile;
      const vpn = user?.VPN || {};
      const maxTier = Number.isFinite(Number(vpn.MaxTier)) ? Number(vpn.MaxTier) : 0;
      const groups = Array.isArray(vpn.Groups) ? vpn.Groups : [];
      const headers = { "x-pm-max-tier": String(maxTier) };
      if (groups.length === 1) headers["x-pm-single-group"] = groups.join(",");
      else if (groups.length > 1) headers["x-pm-group-count"] = String(groups.length);
      return headers;
    } catch (error) {
      void logDiagnostic("vpn_profile_lookup_failed", { httpStatus: Number(error?.httpStatus) || 0, apiCode: Number(error?.apiCode) || 0 }, "warn");
      return { "x-pm-max-tier": "0" };
    }
  }

  function isUsablePhysicalServer(server) {
    return Number(server?.Status) === 1 && Number(server?.ServicesDown ?? 0) === 0;
  }

  function toFreeProxyNodes(payload) {
    if (!Array.isArray(payload?.LogicalServers)) throw new Error("Proton chưa trả về danh sách máy chủ hợp lệ.");
    return payload.LogicalServers.flatMap((server) => {
      if (Number(server?.Tier) !== 0 || Number(server?.Status) !== 1) return [];
      const physical = (Array.isArray(server.Servers) ? server.Servers : []).filter(isUsablePhysicalServer);
      const first = physical.find((item) => item?.Domain || server?.Domain);
      if (!first) return [];
      const label = String(first.Label ?? "");
      const proxyPort = 4443 + (/^\d+$/.test(label) ? Number(label) : 0);
      return [{
        name: String(server.Name || "Proton Free"),
        country: String(server.ExitCountry || server.EntryCountry || ""),
        city: String(server.City || ""),
        load: Number.isFinite(Number(server.Load)) ? Number(server.Load) : 0,
        activePhysicalServers: physical.length,
        entryIP: String(first.EntryIP || first.Domain || server.Domain || ""),
        proxyHost: String(first.Domain || server.Domain || ""),
        proxyPort,
      }];
    }).sort((a, b) => a.load - b.load || a.name.localeCompare(b.name));
  }

  async function fetchProtonNodes() {
    const auth = await getProtonAuth();
    if (!auth?.AccessToken) throw new Error("Đăng nhập Proton bằng SRP để tải danh sách máy chủ.");
    const tierHeaders = await getTierHeaders(auth);
    const result = await authenticatedVpnRequest("vpn/v1/logicals?WithIpV6=1", auth, tierHeaders);
    const nodes = toFreeProxyNodes(result);
    void logDiagnostic("proton_nodes_loaded", { nodeCount: nodes.length });
    return { nodes };
  }

  async function fetchProtonProxyCredentials() {
    const auth = await getProtonAuth();
    if (!auth?.AccessToken) throw new Error("Phiên Proton đã hết. Đăng nhập lại rồi thử kết nối.");
    const tierHeaders = await getTierHeaders(auth);
    const proxyTokenHeaders = { ...tierHeaders, "x-pm-appversion": PROTON_BROWSER_APP_VERSION };
    void logDiagnostic("proton_proxy_token_request_started", { appVersion: PROTON_BROWSER_APP_VERSION });
    const credentials = await authenticatedVpnRequest("vpn/v1/browser/token?Duration=1200", auth, proxyTokenHeaders);
    if (Number(credentials?.Code) !== 1000 || !credentials?.Username || !credentials?.Password) {
      throw new Error("Proton không cấp proxy token cho phiên này.");
    }
    const expirySeconds = Number(credentials.Expire);
    const lifetime = Number.isFinite(expirySeconds) && expirySeconds > 0 ? Math.min(expirySeconds, 1200) : 1200;
    void logDiagnostic("proton_proxy_token_received", { lifetimeSeconds: lifetime });
    return {
      username: String(credentials.Username),
      password: String(credentials.Password),
      expiresAt: Date.now() + lifetime * 1000,
    };
  }

  if (usesFirefoxProxyApi) {
    api.proxy.onRequest.addListener(async (request) => {
      const connection = await getConnection();
      if (!connection) return { type: "direct" };
      let hostname;
      try { hostname = new URL(request.url).hostname; } catch { return [{ type: "https", host: connection.proxyHost, port: connection.proxyPort }, null]; }
      if (shouldUseDirect(hostname)) return { type: "direct" };
      if (!firefoxRouteLogged) {
        firefoxRouteLogged = true;
        void logDiagnostic("firefox_proxy_route_selected", { proxyPort: connection.proxyPort });
      }
      const encoded = btoa(String.fromCharCode(...new TextEncoder().encode(`${connection.username}:${connection.password}`)));
      return [{
        type: "https",
        host: connection.proxyHost,
        port: connection.proxyPort,
        proxyAuthorizationHeader: `Basic ${encoded}`,
      }, null];
    }, { urls: ["<all_urls>"] });
  } else if (api.webRequest?.onAuthRequired) {
    api.webRequest.onAuthRequired.addListener((details, callback) => {
      if (!details.isProxy) {
        callback({});
        return;
      }
      api.storage.session.get(STORAGE_KEY).then((stored) => {
        const connection = stored[STORAGE_KEY];
        if (!chromiumAuthLogged) {
          chromiumAuthLogged = true;
          void logDiagnostic("chromium_proxy_auth_challenge", {
            connectionPresent: Boolean(connection),
            challengerMatches: Boolean(connection && details.challenger?.host?.toLowerCase() === connection.proxyHost.toLowerCase()),
            expired: Boolean(connection && Date.now() >= connection.expiresAt),
          }, connection ? "info" : "warn");
        }
        if (!connection || details.challenger?.host?.toLowerCase() !== connection.proxyHost.toLowerCase()) {
          callback({});
          return;
        }
        if (Date.now() >= connection.expiresAt) {
          callback({ cancel: true });
          return;
        }
        callback({ authCredentials: { username: connection.username, password: connection.password } });
      }).catch(() => callback({ cancel: true }));
    }, { urls: ["<all_urls>"] }, ["asyncBlocking"]);
  }

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "FREETON_DIAGNOSTIC_LOG") {
      storeDiagnostic(message.entry).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
      return true;
    }
    if (message?.type === "FREETON_GET_DIAGNOSTICS") {
      diagnosticWriteQueue.then(() => api.storage.local.get(DIAGNOSTICS_KEY)).then((stored) => {
        const logs = Array.isArray(stored[DIAGNOSTICS_KEY]) ? stored[DIAGNOSTICS_KEY] : [];
        sendResponse({ ok: true, logs });
      }).catch(() => sendResponse({ ok: false, error: "Không đọc được log chẩn đoán." }));
      return true;
    }
    if (message?.type === "FREETON_CLEAR_DIAGNOSTICS") {
      diagnosticWriteQueue.then(() => api.storage.local.remove(DIAGNOSTICS_KEY)).then(() => sendResponse({ ok: true }))
        .catch(() => sendResponse({ ok: false, error: "Không xóa được log chẩn đoán." }));
      return true;
    }
    if (message?.type === "FREETON_HUMAN_VERIFICATION_TOKEN") {
      receiveHumanVerificationToken(message.token, sender)
        .then((result) => sendResponse({ ok: true, ...result }))
        .catch((error) => sendResponse({ ok: false, error: error?.message || "Không nhận được token xác minh." }));
      return true;
    }

    let operation;
    if (message?.type === "FREETON_AUTH_STATUS") operation = protonAuthStatus();
    else if (message?.type === "FREETON_AUTH_OPEN_LOGIN_PAGE") operation = openLoginPage();
    else if (message?.type === "FREETON_AUTH_LOGIN") operation = createProtonLogin(String(message.username || "").trim(), String(message.password || ""));
    else if (message?.type === "FREETON_AUTH_COMPLETE_2FA") operation = completeProtonTwoFactor(message.code);
    else if (message?.type === "FREETON_AUTH_OPEN_VERIFICATION") operation = openHumanVerification();
    else if (message?.type === "FREETON_AUTH_LOGOUT") operation = protonLogout();
    else if (message?.type === "FREETON_FETCH_NODES") operation = fetchProtonNodes();
    else if (message?.type === "FREETON_GET_PROXY_CREDENTIALS") operation = fetchProtonProxyCredentials();
    else if (message?.type === "FREETON_CONNECT") operation = connect(message);
    else if (message?.type === "FREETON_DISCONNECT") operation = disconnect().then(() => ({ connected: false }));
    else if (message?.type === "FREETON_STATUS") operation = status();
    else return false;

    operation.then((result) => {
      void logDiagnostic("background_command_succeeded", { command: message.type });
      sendResponse({ ok: true, ...result });
    }).catch((error) => {
      void logDiagnostic("background_command_failed", {
        command: message.type,
        error: error?.message || "Unknown error",
        errorName: error?.name || "Error",
        httpStatus: Number(error?.httpStatus) || 0,
        apiCode: Number(error?.apiCode) || 0,
        endpoint: String(error?.endpoint || "").slice(0, 48),
        network: Boolean(error?.network),
      }, "error");
      sendResponse({ ok: false, error: error?.message || "Không thể thay đổi kết nối." });
    });
    return true;
  });

  api.runtime.onStartup?.addListener(() => {
    void logDiagnostic("browser_startup_cleanup");
    api.storage.session.remove([STORAGE_KEY, AUTH_KEY, PENDING_AUTH_KEY, HUMAN_VERIFICATION_KEY, LOGIN_PAGE_TAB_KEY]);
    clearChromiumProxy();
    setWebRTCProtection(false);
  });

  api.tabs.onRemoved?.addListener((tabId) => {
    api.storage.session.get(LOGIN_PAGE_TAB_KEY).then((stored) => {
      if (stored[LOGIN_PAGE_TAB_KEY] === tabId) return api.storage.session.remove(LOGIN_PAGE_TAB_KEY);
      return undefined;
    }).catch(() => undefined);
  });

  api.runtime.onInstalled?.addListener((details) => {
    void logDiagnostic("extension_installed", { reason: details.reason });
    if (details.reason === "install") clearChromiumProxy();
  });
  void logDiagnostic("background_started", { mode: usesFirefoxProxyApi ? "firefox_proxy_api" : "chromium_proxy_api" });
})();
