(() => {
  const api = globalThis.browser ?? globalThis.chrome;

  globalThis.FreetonDiagnostics = Object.freeze({
    log(source, event, details = {}, level = "info") {
      try {
        return api.runtime.sendMessage({
          type: "FREETON_DIAGNOSTIC_LOG",
          entry: { source, event, level, at: new Date().toISOString(), details },
        }).catch(() => undefined);
      } catch {
        return Promise.resolve();
      }
    },
  });
})();
