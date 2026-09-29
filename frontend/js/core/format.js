/*
 * Number and timestamp formatting shared by every page.
 *
 * parseTimestamp() is the one place that knows the /threats and /stats
 * endpoints return naive "YYYY-MM-DD HH:MM:SS" strings that are already
 * UTC - always read a threat/summary timestamp through it, never with a
 * bare `new Date(...)`, or browsers will parse it as local time.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.core = window.LogAnalyzer.core || {};

  var MONTHS = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  ];

  function pad2(value) {
    return value < 10 ? "0" + value : String(value);
  }

  function formatNumber(number) {
    return number.toLocaleString("en-US");
  }

  function parseTimestamp(value) {
    if (typeof value === "string" && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)) {
      return new Date(value.replace(" ", "T") + "Z");
    }
    return new Date(value);
  }

  // "27 Sep 02:14:05"
  function shortDateTime(timestampValue) {
    var d = parseTimestamp(timestampValue);
    var day = d.getUTCDate();
    var month = MONTHS[d.getUTCMonth()];
    var hours = pad2(d.getUTCHours());
    var minutes = pad2(d.getUTCMinutes());
    var seconds = pad2(d.getUTCSeconds());
    return day + " " + month + " " + hours + ":" + minutes + ":" + seconds;
  }

  // "2026-09-27 02:14:05"
  function isoDateTime(timestampValue) {
    var d = parseTimestamp(timestampValue);
    return (
      d.getUTCFullYear() +
      "-" +
      pad2(d.getUTCMonth() + 1) +
      "-" +
      pad2(d.getUTCDate()) +
      " " +
      pad2(d.getUTCHours()) +
      ":" +
      pad2(d.getUTCMinutes()) +
      ":" +
      pad2(d.getUTCSeconds())
    );
  }

  // "27 Sep 2026 at 03:15" - takes a real ISO datetime (e.g. Date#toISOString()),
  // unlike shortDateTime/isoDateTime which take the backend's naive threat timestamps.
  function analyzedAt(isoString) {
    var d = new Date(isoString);
    var day = d.getUTCDate();
    var month = MONTHS[d.getUTCMonth()];
    var year = d.getUTCFullYear();
    var hours = pad2(d.getUTCHours());
    var minutes = pad2(d.getUTCMinutes());
    return day + " " + month + " " + year + " at " + hours + ":" + minutes;
  }

  function fileSize(bytes) {
    var mb = bytes / (1024 * 1024);
    return mb.toFixed(1) + " MB";
  }

  window.LogAnalyzer.core.format = {
    MONTHS: MONTHS,
    pad2: pad2,
    formatNumber: formatNumber,
    parseTimestamp: parseTimestamp,
    shortDateTime: shortDateTime,
    isoDateTime: isoDateTime,
    analyzedAt: analyzedAt,
    fileSize: fileSize
  };
})();
