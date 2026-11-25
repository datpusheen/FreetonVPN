(() => {
  const FLAG = "__freetonProtonAuthBridgeV1";
  const CHANNEL = "freeton-proton-auth-bridge-v1";
  const apiHosts = new Set();
  const metrics = { apiRequestsSeen: 0, bearerRequestsSeen: 0, uidRequestsSeen: 0, authenticatedRequestsSeen: 0 };
  if (window[FLAG]) return;
  Object.defineProperty(window, FLAG, { value: true });

  let latestSession = null;

  function protonApiBase(url) {
    try {
      const parsed = new URL(url, location.href);
      const host = parsed.hostname.toLowerCase();
      const isProtonHost = host === "account.protonvpn.com"
        || host === "proton.me"
        || host.endsWith(".proton.me")
        || host === "protonvpn.ch"
        || host.endsWith(".protonvpn.ch");
      if (parsed.protocol !== "https:" || !isProtonHost) return null;
      if (parsed.pathname === "/api" || parsed.pathname.startsWith("/api/")) return `${parsed.origin}/api`;
      if (parsed.pathname.startsWith("/vpn/")) return parsed.origin;
      return null;
    } catch {
      return null;
    }
  }

  function capture(url, headers) {
    const apiBase = protonApiBase(url);
    if (!apiBase) return;
    metrics.apiRequestsSeen += 1;
    try { apiHosts.add(new URL(url, location.href).hostname.toLowerCase()); } catch {}
    let authorization = "";
    let uid = "";
    try {
      const normalized = headers instanceof Headers ? headers : new Headers(headers);
      authorization = normalized.get("authorization") || "";
      uid = normalized.get("x-pm-uid") || "";
    } catch {
      return;
    }
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    if (match?.[1]) metrics.bearerRequestsSeen += 1;
    if (uid) metrics.uidRequestsSeen += 1;
    if (!uid || !match?.[1]) return;
    metrics.authenticatedRequestsSeen += 1;
    const nextSession = { uid, accessToken: match[1], apiBase };
    const changed = !latestSession || latestSession.uid !== nextSession.uid || latestSession.accessToken !== nextSession.accessToken;
    latestSession = nextSession;
    if (changed) window.postMessage({ source: CHANNEL, type: "session", ...latestSession }, location.origin);
  }

  function requestHeaders(input, init) {
    const headers = new Headers();
    try {
      if (input instanceof Request) new Headers(input.headers).forEach((value, key) => headers.set(key, value));
    } catch {}
    try {
      if (init?.headers) new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    } catch {}
    return headers;
  }

  const nativeFetch = window.fetch;
  if (typeof nativeFetch === "function") {
    metrics.fetchHooked = true;
    window.fetch = function (input, init) {
      try {
        const url = typeof input === "string" || input instanceof URL ? String(input) : input?.url;
        capture(url, requestHeaders(input, init));
      } catch {}
      return Reflect.apply(nativeFetch, this, arguments);
    };
  }

  const xhrState = new WeakMap();
  const xhrPrototype = typeof XMLHttpRequest === "undefined" ? null : XMLHttpRequest.prototype;
  if (xhrPrototype) {
    metrics.xhrHooked = true;
    const nativeOpen = xhrPrototype.open;
    const nativeSetRequestHeader = xhrPrototype.setRequestHeader;
    const nativeSend = xhrPrototype.send;

    xhrPrototype.open = function (method, url) {
      let record = null;
      try {
        if (protonApiBase(url)) record = { url, headers: new Headers() };
      } catch {}
      if (record) xhrState.set(this, record);
      else xhrState.delete(this);
      return Reflect.apply(nativeOpen, this, arguments);
    };

    xhrPrototype.setRequestHeader = function (name, value) {
      const record = xhrState.get(this);
      if (record) {
        try { record.headers.set(name, value); } catch {}
      }
      return Reflect.apply(nativeSetRequestHeader, this, arguments);
    };

    xhrPrototype.send = function () {
      const record = xhrState.get(this);
      if (record) capture(record.url, record.headers);
      return Reflect.apply(nativeSend, this, arguments);
    };
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin || event.data?.source !== CHANNEL) return;
    if (event.data.type === "request") {
      window.postMessage({
        source: CHANNEL,
        type: "status",
        status: {
          bridgeInstalled: true,
          fetchHooked: Boolean(metrics.fetchHooked),
          xhrHooked: Boolean(metrics.xhrHooked),
          apiRequestsSeen: metrics.apiRequestsSeen,
          bearerRequestsSeen: metrics.bearerRequestsSeen,
          uidRequestsSeen: metrics.uidRequestsSeen,
          authenticatedRequestsSeen: metrics.authenticatedRequestsSeen,
          apiHostsSeen: [...apiHosts].slice(0, 5),
          sessionReady: Boolean(latestSession),
        },
      }, location.origin);
      if (latestSession) window.postMessage({ source: CHANNEL, type: "session", ...latestSession }, location.origin);
    }
  });
})();
