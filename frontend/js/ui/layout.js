/*
 * Renders the shared header + nav shell into #app-shell. Self-contained
 * (no dependency on config/core/services), so it can load and run before
 * the rest of the app scripts - keeps the nav visible as early as possible.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.ui = window.LogAnalyzer.ui || {};

  var ACTIVE_TAB_CLASSES = "text-on-surface font-semibold border-b-[3px] border-primary-container h-full flex items-center px-4 font-label-md text-label-md transition-colors";
  var INACTIVE_TAB_CLASSES = "text-secondary font-normal hover:text-on-surface h-full flex items-center px-4 font-label-md text-label-md transition-colors";

  var TABS = [
    { label: "Overview", href: "index.html", key: "overview" },
    { label: "Upload", href: "upload.html", key: "upload" },
    { label: "Threats", href: "threats.html", key: "threats" },
    { label: "Log events", href: "log-events.html", key: "log-events" }
  ];

  var ACTIVE_TAB_BY_PAGE = {
    overview: "overview",
    upload: "upload",
    threats: "threats",
    "threat-detail": "threats",
    "log-events": "log-events"
  };

  var HEADER_HTML =
    '<header class="bg-inverse-surface w-full h-12 flex justify-between items-center px-4 border-b border-outline select-none z-50">' +
    '<div class="flex items-center">' +
    '<span class="font-headline-sm text-headline-sm font-semibold text-surface-container-lowest tracking-normal">Log Analyzer</span>' +
    '</div>' +
    '<div class="flex items-center space-x-2">' +
    '<button aria-label="Notifications" class="p-1.5 text-surface-variant hover:text-surface-container-lowest hover:bg-surface-container-highest/20 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-container" type="button">' +
    '<span class="material-symbols-outlined text-[18px] leading-none block" data-icon="notifications">notifications</span>' +
    '</button>' +
    '<button aria-label="Help" class="p-1.5 text-surface-variant hover:text-surface-container-lowest hover:bg-surface-container-highest/20 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-container" type="button">' +
    '<span class="material-symbols-outlined text-[18px] leading-none block" data-icon="help">help</span>' +
    '</button>' +
    '<button aria-label="Settings" class="p-1.5 text-surface-variant hover:text-surface-container-lowest hover:bg-surface-container-highest/20 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-container" type="button">' +
    '<span class="material-symbols-outlined text-[18px] leading-none block" data-icon="settings">settings</span>' +
    '</button>' +
    '<div class="h-4 w-px bg-outline mx-1"></div>' +
    '<div class="flex items-center ml-1">' +
    '<div class="w-6 h-6 bg-secondary text-surface-container-lowest flex items-center justify-center font-label-sm text-label-sm font-semibold text-[10px]" title="User operator profile">' +
    "          OP" +
    "        </div>" +
    "</div>" +
    "</div>" +
    "</header>";

  var UPLOAD_BUTTON_HTML =
    '<button class="bg-primary-container hover:bg-primary text-on-primary text-body-md font-body-md font-medium px-4 h-8 inline-flex items-center justify-center border border-primary-container focus:outline-none focus:ring-2 focus:ring-primary-container focus:ring-offset-2 transition-colors" type="button">' +
    "        Upload log file" +
    "      </button>";

  var UPLOAD_BUTTON_PLACEHOLDER_HTML = '<div class="flex items-center"></div>';

  function buildTabHtml(tab, activeKey) {
    var isActive = tab.key === activeKey;
    var classes = isActive ? ACTIVE_TAB_CLASSES : INACTIVE_TAB_CLASSES;
    var ariaCurrent = isActive ? ' aria-current="page"' : "";
    return (
      "<a" +
      ariaCurrent +
      ' class="' +
      classes +
      '" href="' +
      tab.href +
      '">' +
      "        " +
      tab.label +
      "      </a>"
    );
  }

  function buildNavHtml(dataPage, activeKey) {
    var tabsHtml = TABS.map(function (tab) {
      return buildTabHtml(tab, activeKey);
    }).join("");

    var trailingHtml =
      dataPage === "upload" ? UPLOAD_BUTTON_PLACEHOLDER_HTML : UPLOAD_BUTTON_HTML;

    return (
      '<div class="bg-surface-container-lowest border-b border-surface-container-highest w-full px-6 flex justify-between items-stretch h-11 select-none">' +
      '<nav aria-label="Main Navigation" class="flex items-stretch h-full space-x-0">' +
      tabsHtml +
      "</nav>" +
      '<div class="flex items-center py-1.5">' +
      trailingHtml +
      "</div>" +
      "</div>"
    );
  }

  function render() {
    var placeholder = document.getElementById("app-shell");
    if (!placeholder) {
      return;
    }

    var dataPage = document.body.getAttribute("data-page");
    var activeKey = ACTIVE_TAB_BY_PAGE[dataPage];

    placeholder.innerHTML = HEADER_HTML + buildNavHtml(dataPage, activeKey);

    if (dataPage !== "upload") {
      var uploadButton = placeholder.querySelector("nav + div button");
      if (uploadButton) {
        uploadButton.addEventListener("click", function () {
          window.location.href = "upload.html";
        });
      }
    }
  }

  window.LogAnalyzer.ui.layout = {
    render: render
  };

  render();
})();
