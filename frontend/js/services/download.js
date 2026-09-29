/*
 * File-download helpers used by exportReport() (both mock and real).
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.services = window.LogAnalyzer.services || {};

  function pad2(value) {
    return value < 10 ? "0" + value : String(value);
  }

  function triggerBlobDownload(blob, filename) {
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  // "20260927_021451" - safe for use in a filename.
  function formatFileStamp(date) {
    return (
      date.getUTCFullYear() +
      pad2(date.getUTCMonth() + 1) +
      pad2(date.getUTCDate()) +
      "_" +
      pad2(date.getUTCHours()) +
      pad2(date.getUTCMinutes()) +
      pad2(date.getUTCSeconds())
    );
  }

  // "2026-09-27 02:14:51" - for the report's "Generated:" line.
  function formatReportTimestamp(date) {
    return (
      date.getUTCFullYear() +
      "-" +
      pad2(date.getUTCMonth() + 1) +
      "-" +
      pad2(date.getUTCDate()) +
      " " +
      pad2(date.getUTCHours()) +
      ":" +
      pad2(date.getUTCMinutes()) +
      ":" +
      pad2(date.getUTCSeconds())
    );
  }

  window.LogAnalyzer.services.download = {
    triggerBlobDownload: triggerBlobDownload,
    formatFileStamp: formatFileStamp,
    formatReportTimestamp: formatReportTimestamp
  };
})();
