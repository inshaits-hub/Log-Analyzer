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

  // Null/undefined/empty values are dropped rather than stringified. The
  // backend guards optional filters with `if ip:` / `if severity:`, so
  // sending "null" would be worse than sending nothing: it both escapes
  // the guard and changes the response versus omitting the parameter.
  function buildQueryString(params) {
    if (!params) {
      return "";
    }
    var parts = Object.keys(params)
      .filter(function (key) {
        var value = params[key];
        return value !== null && value !== undefined && value !== "";
      })
      .map(function (key) {
        return encodeURIComponent(key) + "=" + encodeURIComponent(params[key]);
      });
    return parts.length === 0 ? "" : "?" + parts.join("&");
  }

  window.LogAnalyzer.services.http = {
    BASE_URL: BASE_URL,
    request: request,
    buildQueryString: buildQueryString
  };
})();
