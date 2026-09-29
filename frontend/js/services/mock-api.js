/*
 * Mock implementations of every endpoint LogAnalyzer.Api exposes. Used
 * in place of the real fetch calls whenever LogAnalyzer.config.USE_MOCK
 * is true. Honors the "mock" URL query param (?mock=empty / ?mock=error)
 * as a frontend testing switch - it has no effect on the real API.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.services = window.LogAnalyzer.services || {};

  var config = window.LogAnalyzer.config;
  var mockData = window.LogAnalyzer.services.mockData;
  var reportBuilder = window.LogAnalyzer.services.reportBuilder;
  var download = window.LogAnalyzer.services.download;

  function mockResponse(data, delayMs) {
    var delay = typeof delayMs === "number" ? delayMs : 300;
    return new Promise(function (resolve) {
      setTimeout(function () {
        resolve(data);
      }, delay);
    });
  }

  function mockError() {
    return new Promise(function (resolve, reject) {
      setTimeout(function () {
        reject(new Error("Mock network error"));
      }, 300);
    });
  }

  function getSummary() {
    var scenario = config.getMockScenario();
    if (scenario === "error") {
      return mockError();
    }
    if (scenario === "empty") {
      return mockResponse({
        total_events: 0,
        total_threats: 0,
        critical_threats: 0,
        unique_ips: 0
      });
    }
    return mockResponse(mockData.SUMMARY);
  }

  function getStats() {
    var scenario = config.getMockScenario();
    if (scenario === "error") {
      return mockError();
    }
    if (scenario === "empty") {
      return mockResponse({
        severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        top_risk_ips: [],
        recent_summaries: []
      });
    }
    return mockResponse(mockData.STATS);
  }

  function getThreats(params) {
    var scenario = config.getMockScenario();
    if (scenario === "error") {
      return mockError();
    }
    if (scenario === "empty") {
      return mockResponse([]);
    }
    var severity = params && params.severity;
    var ip = params && params.ip;
    var limit = params && params.limit;
    var results = mockData.THREATS.filter(function (item) {
      if (severity && item.severity !== severity) {
        return false;
      }
      if (ip && item.ip !== ip) {
        return false;
      }
      return true;
    });
    if (limit) {
      results = results.slice(0, limit);
    }
    return mockResponse(results.slice());
  }

  function getEvents(params) {
    var scenario = config.getMockScenario();
    if (scenario === "error") {
      return mockError();
    }
    if (scenario === "empty") {
      return mockResponse({ count: 0, events: [] });
    }
    var ip = params && params.ip;
    var limit = (params && params.limit) || 200;
    var results = mockData.EVENTS.filter(function (item) {
      if (ip && item.ip !== ip) {
        return false;
      }
      return true;
    });
    if (limit) {
      results = results.slice(0, limit);
    }
    return mockResponse({ count: results.length, events: results.slice() });
  }

  function uploadLogFile(file, options) {
    options = options || {};
    var onProgress = options.onProgress;

    if (config.getMockScenario() === "error") {
      return new Promise(function (resolve, reject) {
        var cancelled = false;
        var failTimer = null;

        var tickTimer = setTimeout(function () {
          if (cancelled) {
            return;
          }
          if (typeof onProgress === "function") {
            onProgress(20);
          }
          failTimer = setTimeout(function () {
            if (cancelled) {
              return;
            }
            reject(new Error("Mock network error"));
          }, 300);
        }, 300);

        if (options.signal) {
          options.signal.addEventListener("abort", function () {
            cancelled = true;
            clearTimeout(tickTimer);
            if (failTimer) {
              clearTimeout(failTimer);
            }
            reject(new Error("Upload cancelled"));
          });
        }
      });
    }

    return new Promise(function (resolve, reject) {
      var percent = 0;
      var cancelled = false;

      var timer = setInterval(function () {
        if (cancelled) {
          return;
        }
        percent = Math.min(percent + 20, 100);
        if (typeof onProgress === "function") {
          onProgress(percent);
        }
        if (percent >= 100) {
          clearInterval(timer);
          resolve({
            status: "success",
            filename: file.name,
            parsed_events: 1418,
            threats_detected: 12,
            severity_counts: { CRITICAL: 2, HIGH: 6, MEDIUM: 4, LOW: 0 },
            high_risk_accounts: ["root", "admin"],
            riskiest_ip: { ip: "203.0.113.45", risk_score: 92, threat_count: 2 },
            message: "Analyzed 1418 events, 12 alerts."
          });
        }
      }, 300);

      if (options.signal) {
        options.signal.addEventListener("abort", function () {
          cancelled = true;
          clearInterval(timer);
          reject(new Error("Upload cancelled"));
        });
      }
    });
  }

  function exportReport(format) {
    var now = new Date();
    var fileStamp = download.formatFileStamp(now);

    var scenario = config.getMockScenario();
    if (scenario === "error") {
      return mockError();
    }
    var threats = scenario === "empty" ? [] : mockData.THREATS.slice();
    var summary = scenario === "empty"
      ? { total_events: 0, total_threats: 0, critical_threats: 0, unique_ips: 0 }
      : mockData.SUMMARY;
    var stats = scenario === "empty"
      ? { severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }, top_risk_ips: [], recent_summaries: [] }
      : mockData.STATS;
    var generatedAt = download.formatReportTimestamp(now);
    var filename = "report_" + fileStamp + "_mock." + format;

    return new Promise(function (resolve) {
      setTimeout(function () {
        var blob = format === "json"
          ? new Blob([reportBuilder.buildJsonReport(generatedAt, summary, stats, threats)], { type: "application/json" })
          : new Blob([reportBuilder.buildHtmlReport(generatedAt, summary, threats)], { type: "text/html" });
        download.triggerBlobDownload(blob, filename);
        resolve();
      }, 300);
    });
  }

  window.LogAnalyzer.services.mockApi = {
    getSummary: getSummary,
    getStats: getStats,
    getThreats: getThreats,
    getEvents: getEvents,
    uploadLogFile: uploadLogFile,
    exportReport: exportReport
  };
})();
