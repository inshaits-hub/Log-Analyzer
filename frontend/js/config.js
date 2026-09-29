/*
 * App-wide configuration. Loaded first, before every other module.
 *
 * Deployment note: the API base URL and the mock switch are resolved at
 * runtime, not hardcoded, so the same files work locally, behind the nginx
 * reverse proxy (docker compose) and on a split-origin host.
 *
 * Resolution order (first match wins):
 *   1. window.__LOG_ANALYZER_CONFIG__   inline script / generated env.js
 *   2. <meta name="api-base-url">       per-deployment meta tag
 *   3. default: "/api/v1"               same-origin behind the proxy
 *
 * Mock data is OFF by default. It is a frontend-only demo switch:
 *   ?mock=1            normal fixture data
 *   ?mock=empty        empty-state fixture
 *   ?mock=error        error-state fixture
 * A <meta name="api-use-mock" content="true"> tag also forces it on.
 * Leaving mock on in production would make the dashboard show invented
 * data while looking healthy, so it must be requested explicitly.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};

  function metaContent(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute("content") : null;
  }

  var override = window.__LOG_ANALYZER_CONFIG__ || {};

  var metaBase = metaContent("api-base-url");
  var BASE_URL = override.baseUrl || (metaBase && metaBase.trim()) || "/api/v1";
  // Drop a trailing slash so callers can always do BASE_URL + "/summary".
  BASE_URL = BASE_URL.replace(/\/+$/, "");

  var metaMock = metaContent("api-use-mock");
  var USE_MOCK;
  if (typeof override.useMock === "boolean") {
    USE_MOCK = override.useMock;
  } else if (metaMock !== null) {
    USE_MOCK = metaMock.trim().toLowerCase() === "true";
  } else {
    // `?mock` present at all (including `?mock=empty`) turns mock mode on.
    USE_MOCK = new URLSearchParams(window.location.search).has("mock");
  }

  window.LogAnalyzer.config = {
    BASE_URL: BASE_URL,
    USE_MOCK: USE_MOCK,
    LAST_UPLOAD_STORAGE_KEY: "logAnalyzerLastUpload",

    // Risk-score scale, kept here so the UI cannot drift from the backend.
    // backend/src/threat_detector.py clamps every score to 0-100
    // (threat_detector.py:425) and backend/src/alert_manager.py flags
    // CRITICAL at score >= 80 (alert_manager.py:70).
    RISK_SCORE_MAX: 100,
    CRITICAL_SCORE_THRESHOLD: 80,
    // Separate, lower bar for the "Malicious Host" tag on the detail
    // panel: it marks a host worth acting on before it reaches CRITICAL.
    MALICIOUS_SCORE_THRESHOLD: 70,

    // The "mock" URL query parameter (?mock=empty / ?mock=error) is a
    // frontend testing switch only, not an API feature.
    getMockScenario: function () {
      var params = new URLSearchParams(window.location.search);
      return params.get("mock");
    }
  };
})();
