/*
 * Single source of truth for severity appearance, and small DOM builders for
 * the ways severity shows up across pages (a pill in the threats table, a
 * pill in the threat-detail table, and the header meta for the detail panel).
 *
 * Colours come from the .sev-* classes in css/style.css rather than inline
 * hex, so the overview meter, the table pills, the chart and the detail panel
 * can never drift apart. The raw hexes are still exported because a couple of
 * call sites set them on a canvas / inline style.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.ui = window.LogAnalyzer.ui || {};

  var ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  var LABELS = {
    CRITICAL: "Critical",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low"
  };

  // Mirrors the --sev-* values in css/style.css. Keep in sync.
  var DOT_HEX = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#ca8a04",
    LOW: "#64748b"
  };

  // Class suffix used for the pill styling in css/style.css.
  var CSS_CLASS = {
    CRITICAL: "sev-critical",
    HIGH: "sev-high",
    MEDIUM: "sev-medium",
    LOW: "sev-low"
  };

  function buildDot(severity, sizeClass) {
    var dot = document.createElement("span");
    dot.className = "sev-dot " + (sizeClass || "w-2 h-2");
    dot.style.backgroundColor = DOT_HEX[severity];
    return dot;
  }

  // Pill used by the threats table and the threat-detail table.
  function buildPill(severity) {
    var pill = document.createElement("span");
    pill.className = "badge " + (CSS_CLASS[severity] || "sev-neutral");

    var dot = document.createElement("span");
    dot.className = "sev-dot w-1.5 h-1.5";
    dot.style.backgroundColor = DOT_HEX[severity];
    pill.appendChild(dot);

    pill.appendChild(document.createTextNode(LABELS[severity] || severity));
    return pill;
  }

  // Dot + label used by the threats table's Severity column.
  function buildTableIndicator(severity) {
    var wrap = document.createElement("div");
    wrap.className = "flex items-center gap-2";

    var dot = buildDot(severity, "w-2 h-2");
    dot.setAttribute("aria-label", LABELS[severity] + " indicator");
    wrap.appendChild(dot);

    var label = document.createElement("span");
    label.className = "text-[12.5px] text-secondary";
    label.textContent = LABELS[severity];
    wrap.appendChild(label);

    return wrap;
  }

  // Data for the threat-detail right panel's header.
  function getPanelHeaderMeta(severity) {
    var suffix = CSS_CLASS[severity] || "sev-neutral";
    return {
      label: LABELS[severity] || severity,
      dotHex: DOT_HEX[severity],
      // Uses the darkened *-text shade so the label clears 4.5:1 on white,
      // which the bar/dot colour does not.
      textClass: "text-" + suffix + "-text",
      pillClass: "badge " + suffix
    };
  }

  window.LogAnalyzer.ui.severity = {
    ORDER: ORDER,
    LABELS: LABELS,
    DOT_HEX: DOT_HEX,
    CSS_CLASS: CSS_CLASS,
    buildDot: buildDot,
    buildTableIndicator: buildTableIndicator,
    buildPill: buildPill,
    getPanelHeaderMeta: getPanelHeaderMeta
  };
})();
