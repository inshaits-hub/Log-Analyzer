/*
 * Backend API reference (confirmed by reading backend/src/app.py,
 * database.py and alert_manager.py directly - not guessed from docs)
 *
 * GET /summary
 *   Live cumulative aggregate across every upload ever made (not scoped to
 *   a single file - there is no per-upload "results" endpoint).
 *   Fields: total_events, total_threats, critical_threats, unique_ips.
 *
 * GET /stats
 *   Fields: severity_counts ({CRITICAL,HIGH,MEDIUM,LOW} -> count),
 *   top_risk_ips ([{ip, risk_score, threat_count}]), recent_summaries
 *   (per-upload snapshots: {id, total_events, total_threats,
 *   critical_threats, unique_ips, created_at}).
 *
 * GET /threats?ip=&severity=&limit=
 *   Items: {id, type, ip, severity, badge, title, details, timestamp,
 *   risk_score}. There is no attempts/target/first_seen/last_seen field:
 *   alert_manager.py computes those in-memory right after an upload, but
 *   database.py's THREAT_COLUMNS never persists them, so GET /threats can
 *   never return them. "type" is the raw rule key (e.g. SSH_BRUTE_FORCE);
 *   "title" is the ready-made human label for it. "timestamp" is a naive
 *   "YYYY-MM-DD HH:MM:SS" string (space separator, no T, no timezone) that
 *   is already UTC - always read it through LogAnalyzer.core.format.parseTimestamp(),
 *   never with a bare `new Date(...)`, or browsers will parse it as local time.
 *
 * POST /upload (multipart field name: "file")
 *   Response: {status, filename, parsed_events, threats_detected,
 *   severity_counts, high_risk_accounts, riskiest_ip, message}.
 *   Validation errors are {status:"error", message}; 413 for oversize
 *   uploads (cap is MAX_UPLOAD_MB, default 16).
 *
 * GET /events?ip=&limit= (default limit 200, no enforced maximum)
 *   Response: {count, events}, events ordered newest first by id. Each
 *   item: {id, timestamp, ip, user, action, log_type, raw_line}. "action"
 *   is one of ssh_login_success, ssh_login_failure, ssh_invalid_user,
 *   ssh_auth_failure, ssh_session_opened, ssh_disconnect, syslog_event,
 *   firewall_block, http_request. "log_type" is "auth", "web", or
 *   "syslog". "timestamp" here is a RAW, UN-NORMALIZED string whose shape
 *   depends on log_type - "Sep 27 02:14:05" (auth/syslog, a literal
 *   prefix of raw_line) or "27/Sep/2026:02:14:05 +0000" (web, embedded
 *   inside raw_line after the IP) - never pass this to parseTimestamp(),
 *   which only understands the threats endpoint's normalized form.
 *
 * GET /export/report?format=html|json (default html)
 *   Always exports every stored threat and the cumulative summary counts -
 *   it takes no ip/severity/type filter parameters, so a "current filters"
 *   UI control cannot be honored server-side. Responds with a file
 *   (Content-Disposition: attachment; text/html or application/json body).
 *   The browser's fetch() does not expose that header cross-origin, so the
 *   frontend names the downloaded file itself. Invalid format -> 400 JSON
 *   {status, message}.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};

  var config = window.LogAnalyzer.config;
  var http = window.LogAnalyzer.services.http;
  var mockApi = window.LogAnalyzer.services.mockApi;
  var download = window.LogAnalyzer.services.download;

  function getSummary() {
    return config.USE_MOCK ? mockApi.getSummary() : http.request("/summary");
  }

  function getStats() {
    return config.USE_MOCK ? mockApi.getStats() : http.request("/stats");
  }

  function getThreats(params) {
    return config.USE_MOCK ? mockApi.getThreats(params) : http.request("/threats" + http.buildQueryString(params));
  }

  function getEvents(params) {
    return config.USE_MOCK ? mockApi.getEvents(params) : http.request("/events" + http.buildQueryString(params));
  }

  function uploadLogFile(file, options) {
    options = options || {};

    if (config.USE_MOCK) {
      return mockApi.uploadLogFile(file, options);
    }

    var formData = new FormData();
    formData.append("file", file);

    return fetch(http.BASE_URL + "/upload", {
      method: "POST",
      body: formData,
      signal: options.signal
    }).then(function (response) {
      if (!response.ok) {
        throw new Error("Request to /upload failed with HTTP status " + response.status);
      }
      return response.json();
    });
  }

  function exportReport(format) {
    if (config.USE_MOCK) {
      return mockApi.exportReport(format);
    }

    var fileStamp = download.formatFileStamp(new Date());
    var filename = "report_" + fileStamp + "." + format;

    return fetch(http.BASE_URL + "/export/report?format=" + encodeURIComponent(format)).then(function (response) {
      if (!response.ok) {
        return response
          .json()
          .catch(function () {
            return null;
          })
          .then(function (body) {
            var message = "Request to /export/report failed with HTTP status " + response.status;
            if (body && body.message) {
              message += ": " + body.message;
            }
            throw new Error(message);
          });
      }
      return response.blob().then(function (blob) {
        download.triggerBlobDownload(blob, filename);
      });
    });
  }

  window.LogAnalyzer.Api = {
    BASE_URL: http.BASE_URL,
    USE_MOCK: config.USE_MOCK,
    getSummary: getSummary,
    getStats: getStats,
    getThreats: getThreats,
    getEvents: getEvents,
    uploadLogFile: uploadLogFile,
    exportReport: exportReport
  };
})();
