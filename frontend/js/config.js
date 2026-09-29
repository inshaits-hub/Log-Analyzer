/*
 * App-wide configuration. Loaded first, before every other module.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};

  window.LogAnalyzer.config = {
    BASE_URL: "http://127.0.0.1:5000/api/v1",
    USE_MOCK: true,
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
