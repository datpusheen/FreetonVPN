(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const API_VERSION = "browser-vpn@1.3.6";
  const diagnosticLog = (event, details = {}, level = "info") =>
    globalThis.FreetonDiagnostics?.log("content", event, details, level);
  const INSTALL_FLAG = "__freetonProtonBrowserVpnContent";
  if (globalThis[INSTALL_FLAG]) return;
  globalThis[INSTALL_FLAG] = true;
  const AUTH_BRIDGE_CHANNEL = "freeton-proton-auth-bridge-v1";
  let pageAuthSnapshot = null;
  let pageBridgeStatus = null;
  const authWaiters = new Set();

  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin || event.data?.source !== AUTH_BRIDGE_CHANNEL) return;
    if (event.data.type === "status") {
      pageBridgeStatus = event.data.status || null;
      void diagnosticLog("proton_auth_bridge_status", pageBridgeStatus || {}, "info");
      return;
    }
    if (event.data.type !== "session") return;
    const uid = String(event.data.uid || "");
    const accessToken = String(event.data.accessToken || "");
    if (!uid || !accessToken) return;
    const storageSnapshot = readProtonAuth();
    const changed = !pageAuthSnapshot || pageAuthSnapshot.uid !== uid || pageAuthSnapshot.accessToken !== accessToken;
    pageAuthSnapshot = {
      uid,
      accessToken,
      apiBase: String(event.data.apiBase || `${location.origin}/api`),
      source: "page_network",
      localReadable: storageSnapshot.localReadable,
      sessionReadable: storageSnapshot.sessionReadable,
    };
    if (changed) void diagnosticLog("proton_page_auth_captured", {
      sessionContextFound: true,
      bearerPresent: true,
      authStorage: "page_network",
      localStoreReadable: storageSnapshot.localReadable,
      sessionStoreReadable: storageSnapshot.sessionReadable,
    });
    for (const resolve of [...authWaiters]) resolve(pageAuthSnapshot);
  });

  function readProtonAuth() {
    const result = { uid: "", accessToken: "", source: "none", localReadable: false, sessionReadable: false };
    const stores = [];
    try { stores.push({ name: "localStorage", storage: localStorage }); result.localReadable = true; } catch {}
    try { stores.push({ name: "sessionStorage", storage: sessionStorage }); result.sessionReadable = true; } catch {}

    for (const store of stores) {
      try {
        result.uid ||= store.storage.getItem("UID") || store.storage.getItem("Uid") || "";
      } catch {}
    }
    for (const store of stores) {
      try {
        const keys = result.uid ? [`AUTH-${result.uid}`, "AUTH"] : ["AUTH"];
        for (const key of keys) {
          const raw = store.storage.getItem(key);
          if (!raw) continue;
          try {
            const value = JSON.parse(raw);
            result.uid ||= value?.UID || value?.Uid || value?.uid || "";
            result.accessToken ||= value?.AccessToken || value?.accessToken || value?.access_token || "";
          } catch {
            if (/^[\w.-]+\.[\w.-]+\.[\w.-]+$/.test(raw)) result.accessToken ||= raw;
          }
          if (result.accessToken) result.source = store.name;
        }
      } catch {
        // Same-origin cookies can still authorize the API request.
      }
    }
    return result;
  }

  function protonHeaders(extra = {}, auth = readProtonAuth(), includeBearer = true) {
    const headers = {
      Accept: "application/vnd.protonmail.v1+json",
      "x-pm-appversion": API_VERSION,
      "x-pm-browser-type": /Firefox/i.test(navigator.userAgent) ? "Firefox" : "Chrome",
      "x-pm-locale": "en_US",
      ...extra,
    };
    if (auth.uid) headers["x-pm-uid"] = auth.uid;
    if (includeBearer && auth.accessToken) headers.Authorization = `Bearer ${auth.accessToken}`;
    return headers;
  }

  function getProtonAuth() {
    if (pageAuthSnapshot) return Promise.resolve(pageAuthSnapshot);
    const storedAuth = readProtonAuth();
    if (storedAuth.uid && storedAuth.accessToken) return Promise.resolve(storedAuth);
    return new Promise((resolve) => {
      let settled = false;
      const finish = (auth) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        authWaiters.delete(finish);
        if (!auth) {
          void diagnosticLog(pageBridgeStatus
            ? "proton_auth_bridge_no_session"
            : "proton_auth_bridge_status_missing", pageBridgeStatus || {
              responseReceived: false,
              note: "No response to the page-world auth bridge handshake.",
            }, "warn");
        }
        resolve(auth || readProtonAuth());
      };
      const timeout = setTimeout(() => finish(null), 1200);
      authWaiters.add(finish);
      window.postMessage({ source: AUTH_BRIDGE_CHANNEL, type: "request" }, location.origin);
    });
  }

  async function fetchProtonJSON(path, headers = {}) {
    const endpoint = path.split("?")[0];
    const startedAt = performance.now();
    let httpStatus = 0;
    const auth = await getProtonAuth();
    void diagnosticLog("proton_api_request_started", {
      endpoint,
      host: location.hostname,
      sessionContextFound: Boolean(auth.uid),
      bearerPresent: Boolean(auth.accessToken),
      authStorage: auth.source,
      localStoreReadable: auth.localReadable,
      sessionStoreReadable: auth.sessionReadable,
    });
    try {
      const requestOptions = {
        method: "GET",
        credentials: "include",
        cache: "no-store",
      };
      const apiBase = String(auth.apiBase || `${location.origin}/api`).replace(/\/+$/, "");
      let response = await fetch(`${apiBase}/${path}`, {
        ...requestOptions,
        headers: protonHeaders(headers, auth),
      });
      if (response.status === 401 && auth.accessToken) {
        void diagnosticLog("proton_auth_cookie_fallback_started", { endpoint }, "warn");
        response = await fetch(`${apiBase}/${path}`, {
          ...requestOptions,
          headers: protonHeaders(headers, auth, false),
        });
        void diagnosticLog("proton_auth_cookie_fallback_result", { endpoint, httpStatus: response.status }, response.ok ? "info" : "warn");
      }
      httpStatus = response.status;
      if (response.status === 401 || response.status === 403) {
        throw new Error(auth.uid && auth.accessToken
          ? "Trang Proton đã gửi thông tin phiên nhưng API từ chối. Hãy tải lại tab Proton và thử lại."
          : "Extension chưa đọc được thông tin phiên từ tab Proton. Hãy tải lại tab Proton để extension bắt các request đăng nhập rồi thử lại.");
      }
      if (!response.ok) throw new Error(`Proton API trả về lỗi HTTP ${response.status}.`);
      const payload = await response.json();
      void diagnosticLog("proton_api_request_succeeded", {
        endpoint,
        httpStatus,
        durationMs: Math.round(performance.now() - startedAt),
      });
      return payload;
    } catch (error) {
      void diagnosticLog("proton_api_request_failed", {
        endpoint,
        httpStatus,
        durationMs: Math.round(performance.now() - startedAt),
        error: error?.message || "Unknown error",
        errorName: error?.name || "Error",
      }, "error");
      throw error;
    }
  }

  function isUsablePhysicalServer(server) {
    return Number(server?.Status) === 1 && Number(server?.ServicesDown ?? 0) === 0;
  }

  function toFreeProxyNodes(payload) {
    if (!Array.isArray(payload?.LogicalServers)) {
      throw new Error("Proton chưa trả về danh sách máy chủ hợp lệ. Hãy đăng nhập lại rồi thử.");
    }
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

  async function fetchNodes() {
    // Proton's own browser extension sends the authenticated user's tier/group
    // headers when requesting VPN resources. The profile endpoint supplies them.
    const tierHeaders = await getTierHeaders();
    return toFreeProxyNodes(await fetchProtonJSON("vpn/v1/logicals?WithIpV6=1", tierHeaders));
  }

  async function getTierHeaders() {
    try {
      const profile = await fetchProtonJSON("vpn/v2");
      const user = profile?.User || profile;
      const vpn = user?.VPN || {};
      const maxTier = Number.isFinite(Number(vpn.MaxTier)) ? Number(vpn.MaxTier) : 0;
      const groups = Array.isArray(vpn.Groups) ? vpn.Groups : [];
      const headers = { "x-pm-max-tier": String(maxTier) };
      if (groups.length === 1) headers["x-pm-single-group"] = groups.join(",");
      else if (groups.length > 1) headers["x-pm-group-count"] = String(groups.length);
      return headers;
    } catch {
      // Free accounts have tier 0. The token endpoint remains authoritative if profile lookup fails.
      void diagnosticLog("vpn_profile_fallback", { reason: "Using Free tier headers after profile lookup failed." }, "warn");
      return { "x-pm-max-tier": "0" };
    }
  }

  async function fetchProxyCredentials() {
    void diagnosticLog("proxy_token_request_started");
    const tierHeaders = await getTierHeaders();
    const credentials = await fetchProtonJSON("vpn/v1/browser/token?Duration=1200", tierHeaders);
    if (Number(credentials?.Code) !== 1000 || !credentials?.Username || !credentials?.Password) {
      void diagnosticLog("proxy_token_request_rejected", { apiCode: Number(credentials?.Code) || 0 }, "error");
      throw new Error(credentials?.Error || "Proton không cấp proxy token cho phiên này.");
    }
    const expirySeconds = Number(credentials.Expire);
    const lifetime = Number.isFinite(expirySeconds) && expirySeconds > 0
      ? Math.min(expirySeconds, 1200)
      : 1200;
    const result = {
      username: String(credentials.Username),
      password: String(credentials.Password),
      expiresAt: Date.now() + lifetime * 1000,
    };
    void diagnosticLog("proxy_token_received", { lifetimeSeconds: lifetime });
    return result;
  }

  api.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    let operation;
    if (message?.type === "FREETON_FETCH_NODES") operation = fetchNodes();
    else if (message?.type === "FREETON_GET_PROXY_CREDENTIALS") operation = fetchProxyCredentials();
    else return false;

    void diagnosticLog("proton_message_received", { operation: message.type });
    operation.then((result) => {
      if (Array.isArray(result)) void diagnosticLog("node_data_ready", { nodeCount: result.length });
      sendResponse({ ok: true, ...(Array.isArray(result) ? { nodes: result } : { credentials: result }) });
    }).catch((error) => {
      void diagnosticLog("proton_message_failed", { operation: message.type, error: error?.message || "Unknown error" }, "error");
      sendResponse({ ok: false, error: error?.message || "Không thể kết nối Proton API." });
    });
    return true;
  });
})();
