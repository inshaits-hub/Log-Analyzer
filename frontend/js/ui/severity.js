/*
 * Single source of truth for severity colors/labels, and small DOM
 * builders for the ways severity shows up across pages (a dot + label in
 * the threats table, a bordered pill in the threat-detail table, and the
 * dot + label pairing in the threat-detail panel header).
 *
 * MEDIUM intentionally has two hexes: DOT_HEX (#f1c21b) is the raw
 * yellow used for small indicators (matches the overview severity bar),
 * while TEXT_HEX (#b28600) is a darker shade used wherever that yellow
 * would otherwise sit on a light background as text.
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

  var DOT_HEX = {
    CRITICAL: "#da1e28",
    HIGH: "#ff832b",
    MEDIUM: "#f1c21b",
    LOW: "#8d8d8d"
  };

  var TEXT_HEX = {
    CRITICAL: "#da1e28",
    HIGH: "#ff832b",
    MEDIUM: "#b28600",
    LOW: null // uses the theme's text-secondary class instead of a raw hex
  };

  var PILL_CLASSES = {
    CRITICAL: "inline-flex items-center px-1.5 py-0.5 text-label-sm font-label-sm bg-[#fff1f1] text-[#da1e28] border border-[#ffb3b8]",
    HIGH: "inline-flex items-center px-1.5 py-0.5 text-label-sm font-label-sm bg-[#fff2e8] text-[#ff832b] border border-[#ffb784]",
    MEDIUM: "inline-flex items-center px-1.5 py-0.5 text-label-sm font-label-sm bg-[#fcf4d6] text-[#b28600] border border-[#f1c21b]",
    LOW: "inline-flex items-center px-1.5 py-0.5 text-label-sm font-label-sm bg-surface-container text-secondary border border-outline-variant"
  };

  function buildDot(severity, sizeClass) {
    var dot = document.createElement("span");
    dot.className = (sizeClass || "w-2 h-2") + " inline-block shrink-0";
    dot.style.backgroundColor = DOT_HEX[severity];
    return dot;
  }

  // Dot + label used by the threats table's Severity column.
  function buildTableIndicator(severity) {
    var wrap = document.createElement("div");
    wrap.className = "flex items-center space-x-2";

    var dot = buildDot(severity, "w-2 h-2");
    dot.setAttribute("aria-label", LABELS[severity] + " indicator");
    wrap.appendChild(dot);

    var label = document.createElement("span");
    label.className = "font-body-sm text-body-sm text-on-surface";
    label.textContent = LABELS[severity];
    wrap.appendChild(label);

    return wrap;
  }

  // Bordered pill used by the threat-detail table's Severity column.
  function buildPill(severity) {
    var pill = document.createElement("span");
    pill.className = PILL_CLASSES[severity];

    var dot = document.createElement("span");
    dot.className = "w-1.5 h-1.5 mr-1 inline-block";
    dot.style.backgroundColor = DOT_HEX[severity];
    pill.appendChild(dot);

    pill.appendChild(document.createTextNode(LABELS[severity]));
    return pill;
  }

  // Data for the threat-detail right panel's header (dot + uppercase label).
  function getPanelHeaderMeta(severity) {
    var textHex = TEXT_HEX[severity];
    return {
      label: LABELS[severity],
      dotHex: DOT_HEX[severity],
      textClass: textHex ? "text-[" + textHex + "]" : "text-secondary"
    };
  }

  window.LogAnalyzer.ui.severity = {
    ORDER: ORDER,
    LABELS: LABELS,
    DOT_HEX: DOT_HEX,
    TEXT_HEX: TEXT_HEX,
    buildDot: buildDot,
    buildTableIndicator: buildTableIndicator,
    buildPill: buildPill,
    getPanelHeaderMeta: getPanelHeaderMeta
  };
})();
