/*
 * App-wide configuration. Loaded first, before every other module.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};

  window.LogAnalyzer.config = {
    BASE_URL: "http://127.0.0.1:5000/api/v1",
    USE_MOCK: true,
    LAST_UPLOAD_STORAGE_KEY: "logAnalyzerLastUpload",

    // The "mock" URL query parameter (?mock=empty / ?mock=error) is a
    // frontend testing switch only, not an API feature.
    getMockScenario: function () {
      var params = new URLSearchParams(window.location.search);
      return params.get("mock");
    }
  };
})();
