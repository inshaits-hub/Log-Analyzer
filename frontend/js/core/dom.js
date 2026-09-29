/*
 * Small DOM helpers shared by every page. No app knowledge lives here.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.core = window.LogAnalyzer.core || {};

  function clear(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function appendMessageRow(tbody, options) {
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    td.setAttribute("colspan", String(options.colspan));
    td.className = options.className || "px-4 py-6 text-center text-secondary font-body-sm text-body-sm";
    td.textContent = options.message;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return tr;
  }

  function setDisabled(button, disabled) {
    if (disabled) {
      button.setAttribute("disabled", "");
    } else {
      button.removeAttribute("disabled");
    }
  }

  window.LogAnalyzer.core.dom = {
    clear: clear,
    appendMessageRow: appendMessageRow,
    setDisabled: setDisabled
  };
})();
