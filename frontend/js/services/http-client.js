/*
 * Thin fetch wrapper used by the real (non-mock) API calls.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.services = window.LogAnalyzer.services || {};

  var BASE_URL = window.LogAnalyzer.config.BASE_URL;

  function request(path, options) {
    return fetch(BASE_URL + path, options).then(function (response) {
      if (!response.ok) {
        throw new Error("Request to " + path + " failed with HTTP status " + response.status);
      }
      return response.json();
    });
  }

  function buildQueryString(params) {
    if (!params) {
      return "";
    }
    var keys = Object.keys(params);
    if (keys.length === 0) {
      return "";
    }
    var parts = keys.map(function (key) {
      return encodeURIComponent(key) + "=" + encodeURIComponent(params[key]);
    });
    return "?" + parts.join("&");
  }

  window.LogAnalyzer.services.http = {
    BASE_URL: BASE_URL,
    request: request,
    buildQueryString: buildQueryString
  };
})();
