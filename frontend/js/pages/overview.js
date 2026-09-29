(function () {
  var api = window.LogAnalyzer.Api;
  var format = window.LogAnalyzer.core.format;
  var config = window.LogAnalyzer.config;

  var SEVERITY_SEGMENTS = [
    { key: "CRITICAL", label: "Critical", elementId: "overview-severity-critical" },
    { key: "HIGH", label: "High", elementId: "overview-severity-high" },
    { key: "MEDIUM", label: "Medium", elementId: "overview-severity-medium" },
    { key: "LOW", label: "Low", elementId: "overview-severity-low" }
  ];

  var LEGEND_IDS = {
    CRITICAL: "overview-legend-critical",
    HIGH: "overview-legend-high",
    MEDIUM: "overview-legend-medium",
    LOW: "overview-legend-low"
  };

  // Bars sit in a rounded, gap-separated track so the chart reads as a
  // dashboard widget rather than a raw Figma export. The peak bar keeps the
  // primary colour so the eye lands on the busiest hour first.
  var NORMAL_BAR_WRAPPER_CLASS = "flex-1 h-full flex flex-col justify-end items-center group min-w-0";
  var NORMAL_BAR_FILL_CLASS =
    "w-full rounded-t-[3px] bg-surface-container-highest group-hover:bg-primary/40 transition-colors";
  var PEAK_BAR_WRAPPER_CLASS = "flex-1 h-full flex flex-col justify-end items-center group min-w-0 relative";
  var PEAK_BAR_FILL_CLASS = "w-full rounded-t-[3px] bg-primary transition-colors";

  var YAXIS_ROW_CLASS = "w-full flex items-center justify-end";
  var YAXIS_GRID_CLASS = "border-b border-dashed border-surface-container-highest";
  var YAXIS_LABEL_CLASS = "text-[10px] mono text-outline pr-2 -mt-1.5";

  function hourLabel(hourIndex) {
    return format.pad2(hourIndex) + ":00";
  }

  function threatWord(count) {
    return count === 1 ? "threat" : "threats";
  }

  function computeHourlyCounts(threats) {
    var counts = new Array(24).fill(0);
    threats.forEach(function (item) {
      var date = format.parseTimestamp(item.timestamp);
      if (isNaN(date.getTime())) {
        return;
      }
      var hour = date.getUTCHours();
      counts[hour] += 1;
    });
    return counts;
  }

  function fillChart(hourlyCounts) {
    var maxCount = Math.max.apply(null, hourlyCounts);
    var scaleMax = Math.max(4, Math.ceil(maxCount / 4) * 4);

    var yAxisContainer = document.getElementById("overview-chart-yaxis");
    var step = scaleMax / 4;
    for (var i = 4; i >= 0; i--) {
      var row = document.createElement("div");
      // Skip the rule on the bottom row so the baseline stays clean.
      row.className = YAXIS_ROW_CLASS + (i > 0 ? " " + YAXIS_GRID_CLASS : "");
      var label = document.createElement("span");
      label.className = YAXIS_LABEL_CLASS;
      label.textContent = String(step * i);
      row.appendChild(label);
      yAxisContainer.appendChild(row);
    }

    var peakIndex = 0;
    for (var h = 1; h < hourlyCounts.length; h++) {
      if (hourlyCounts[h] > hourlyCounts[peakIndex]) {
        peakIndex = h;
      }
    }
    var hasPeak = hourlyCounts[peakIndex] > 0;

    var barsContainer = document.getElementById("overview-chart-bars");
    for (var hour = 0; hour < hourlyCounts.length; hour++) {
      var count = hourlyCounts[hour];
      // Give non-zero hours a visible stub so a single threat is not an
      // invisible 0%-tall bar.
      var heightPercent = count > 0 ? Math.max(4, Math.round((count / scaleMax) * 100)) : 0;
      var isPeak = hasPeak && hour === peakIndex;

      var wrapper = document.createElement("div");
      wrapper.className = isPeak ? PEAK_BAR_WRAPPER_CLASS : NORMAL_BAR_WRAPPER_CLASS;

      var fill = document.createElement("div");
      fill.className = isPeak ? PEAK_BAR_FILL_CLASS : NORMAL_BAR_FILL_CLASS;
      fill.style.height = heightPercent + "%";

      var title = isPeak
        ? hourLabel(hour) + " (Peak) - " + count + " " + threatWord(count)
        : hourLabel(hour) + " - " + count + " " + threatWord(count);
      fill.setAttribute("title", title);

      wrapper.appendChild(fill);
      barsContainer.appendChild(wrapper);
    }
  }

  function fillLastUpload() {
    var container = document.getElementById("overview-last-upload");
    var raw;
    try {
      raw = sessionStorage.getItem(config.LAST_UPLOAD_STORAGE_KEY);
    } catch (storageError) {
      return;
    }
    if (!raw) {
      return;
    }
    var parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseError) {
      return;
    }
    if (!parsed || !parsed.filename || !parsed.uploadedAt) {
      return;
    }
    document.getElementById("overview-filename").textContent = parsed.filename;
    document.getElementById("overview-analyzed-at").textContent = format.analyzedAt(parsed.uploadedAt);
    container.classList.remove("hidden");
  }

  function fillThresholdLabel() {
    var el = document.getElementById("overview-critical-threshold");
    if (el) {
      el.textContent = "Severity: Score >= " + config.CRITICAL_SCORE_THRESHOLD;
    }
  }

  function fillMetrics(summary) {
    document.getElementById("overview-metric-events").textContent = format.formatNumber(summary.total_events);
    document.getElementById("overview-metric-threats").textContent = format.formatNumber(summary.total_threats);
    document.getElementById("overview-metric-critical").textContent = format.formatNumber(summary.critical_threats);
    document.getElementById("overview-metric-ips").textContent = format.formatNumber(summary.unique_ips);
  }

  function fillSeverityBar(stats) {
    var counts = stats.severity_counts;
    var total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;

    SEVERITY_SEGMENTS.forEach(function (segment) {
      var count = counts[segment.key];
      var percent = total > 0 ? Math.round((count / total) * 1000) / 10 : 0;
      var el = document.getElementById(segment.elementId);
      el.style.width = percent + "%";
      el.setAttribute("title", segment.label + ": " + count + " (" + percent + "%)");

      var legendEl = document.getElementById(LEGEND_IDS[segment.key]);
      legendEl.textContent = format.formatNumber(count);
    });
  }

  function fillCriticalThreatsTable(summary, threats) {
    var sorted = threats.slice().sort(function (a, b) {
      return format.parseTimestamp(b.timestamp) - format.parseTimestamp(a.timestamp);
    });
    var rows = sorted.slice(0, 5);

    var tbody = document.getElementById("overview-critical-tbody");
    rows.forEach(function (row) {
      var tr = document.createElement("tr");

      var typeTd = document.createElement("td");
      typeTd.className = "font-medium text-on-surface";
      typeTd.textContent = row.title;
      tr.appendChild(typeTd);

      var ipTd = document.createElement("td");
      ipTd.className = "mono text-secondary";
      ipTd.textContent = row.ip;
      tr.appendChild(ipTd);

      var detailsTd = document.createElement("td");
      detailsTd.className = "mono text-secondary max-w-[16rem] truncate";
      detailsTd.setAttribute("title", row.details);
      detailsTd.textContent = row.details;
      tr.appendChild(detailsTd);

      var riskTd = document.createElement("td");
      riskTd.className = "num";
      riskTd.textContent = format.formatNumber(row.risk_score);
      tr.appendChild(riskTd);

      var timestampTd = document.createElement("td");
      timestampTd.className = "num mono text-secondary";
      timestampTd.textContent = format.shortDateTime(row.timestamp);
      tr.appendChild(timestampTd);

      tbody.appendChild(tr);
    });

    document.getElementById("overview-critical-badge").textContent =
      format.formatNumber(summary.critical_threats) + " active";

    var viewAll = document.getElementById("overview-view-all-link");
    viewAll.textContent = "View all " + format.formatNumber(summary.total_threats) + " threats";
    viewAll.insertAdjacentHTML(
      "beforeend",
      '<span class="material-symbols-outlined" data-icon="arrow_forward">arrow_forward</span>'
    );
  }

  var errorBanner = document.getElementById("overview-error-banner");
  var placeholderMetrics = document.getElementById("overview-placeholder-metrics");
  var emptyState = document.getElementById("overview-empty-state");
  var contentWrapper = document.getElementById("overview-content");
  var retryButton = document.getElementById("overview-retry-button");
  var emptyUploadButton = document.getElementById("overview-empty-upload-button");

  function showState(state) {
    var showError = state === "error";
    var showEmpty = state === "empty";
    var showData = state === "data";

    errorBanner.classList.toggle("hidden", !showError);
    placeholderMetrics.classList.toggle("hidden", !(showEmpty || showError));
    emptyState.classList.toggle("hidden", !(showEmpty || showError));
    contentWrapper.classList.toggle("hidden", !showData);
  }

  retryButton.addEventListener("click", function () {
    window.location.reload();
  });

  emptyUploadButton.addEventListener("click", function () {
    window.location.href = "upload.html";
  });

  Promise.all([
    api.getSummary(),
    api.getStats(),
    api.getThreats({ severity: "CRITICAL" }),
    api.getThreats()
  ])
    .then(function (results) {
      var summary = results[0];
      var stats = results[1];
      var threats = results[2];
      var allThreats = results[3];

      if (summary.total_events === 0) {
        showState("empty");
        return;
      }

      fillLastUpload();
      fillThresholdLabel();
      fillMetrics(summary);
      fillSeverityBar(stats);
      fillChart(computeHourlyCounts(allThreats));
      fillCriticalThreatsTable(summary, threats);
      showState("data");
    })
    .catch(function (error) {
      console.error(error);
      showState("error");
    });
})();
