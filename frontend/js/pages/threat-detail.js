(function () {
  var api = window.LogAnalyzer.Api;
  var format = window.LogAnalyzer.core.format;
  var dom = window.LogAnalyzer.core.dom;
  var severity = window.LogAnalyzer.ui.severity;

  var MALICIOUS_THRESHOLD = 70;

  var searchInput = document.getElementById("detail-search");
  var severitySelect = document.getElementById("detail-filter-severity");
  var countText = document.getElementById("detail-count-text");
  var tbody = document.getElementById("detail-tbody");
  var statusLeft = document.getElementById("detail-status-left");
  var statusRight = document.getElementById("detail-status-right");

  var emptyBlock = document.getElementById("detail-empty");
  var headerEl = document.getElementById("detail-header");
  var fieldsEl = document.getElementById("detail-fields");
  var footerEl = document.getElementById("detail-footer");

  var severityDot = document.getElementById("detail-severity-dot");
  var severityLabel = document.getElementById("detail-severity-label");
  var titleEl = document.getElementById("detail-title");
  var closeButton = document.getElementById("detail-close-button");

  var ipEl = document.getElementById("detail-ip");
  var copyIconButton = document.getElementById("detail-copy-icon-button");
  var targetAccountsEl = document.getElementById("detail-target-accounts");
  var detectedAtEl = document.getElementById("detail-detected-at");
  var ruleEl = document.getElementById("detail-rule");
  var detailsEl = document.getElementById("detail-details");
  var riskScoreEl = document.getElementById("detail-risk-score");
  var maliciousTag = document.getElementById("detail-malicious-tag");

  var copyButton = document.getElementById("detail-copy-button");
  var exportButton = document.getElementById("detail-export-button");

  var logLinesSection = document.getElementById("detail-log-lines-section");
  var logLinesTitle = document.getElementById("detail-log-lines-title");
  var logLinesShowing = document.getElementById("detail-log-lines-showing");
  var logLinesBox = document.getElementById("detail-log-lines-box");
  var logLinesShowAll = document.getElementById("detail-log-lines-show-all");

  var MAX_LOG_LINES_SHOWN = 6;
  var MAX_TARGET_ACCOUNTS_SHOWN = 5;

  var allThreats = [];
  var selectedId = null;
  var currentSelectedItem = null;
  var loadFailed = false;

  function getFilteredThreats() {
    var searchTerm = searchInput.value.trim().toLowerCase();
    var severityFilter = severitySelect.value;

    return allThreats
      .filter(function (item) {
        if (searchTerm) {
          var haystack = (item.ip + " " + item.title + " " + item.type + " " + item.details).toLowerCase();
          if (haystack.indexOf(searchTerm) === -1) {
            return false;
          }
        }
        if (severityFilter && item.severity !== severityFilter) {
          return false;
        }
        return true;
      })
      .sort(function (a, b) {
        return format.parseTimestamp(b.timestamp) - format.parseTimestamp(a.timestamp);
      });
  }

  function updateCountText(count) {
    countText.textContent =
      count === 0 ? "Displaying 0 of 0 threats" : "Displaying 1-" + count + " of " + count + " threats";
  }

  function buildTableRow(item, isSelected) {
    var tr = document.createElement("tr");
    tr.className = isSelected
      ? "bg-primary-fixed/20 border-l-[3px] border-l-primary-container cursor-pointer"
      : "bg-surface-container-lowest hover:bg-surface-container-low cursor-pointer transition-colors";

    var chevronTd = document.createElement("td");
    if (isSelected) {
      chevronTd.className = "px-3 py-2 text-center text-primary";
      var chevron = document.createElement("span");
      chevron.className = "material-symbols-outlined";
      chevron.setAttribute("data-icon", "chevron_right");
      chevron.textContent = "chevron_right";
      chevronTd.appendChild(chevron);
    } else {
      chevronTd.className = "px-3 py-2 text-center text-outline";
    }
    tr.appendChild(chevronTd);

    var nameTd = document.createElement("td");
    nameTd.className = "px-3 py-2";
    var nameLine1 = document.createElement("div");
    nameLine1.className = "font-label-md text-label-md text-on-surface";
    nameLine1.textContent = item.title;
    var nameLine2 = document.createElement("div");
    nameLine2.className = "text-secondary font-code-sm text-code-sm";
    nameLine2.textContent = "rule: " + item.type;
    nameTd.appendChild(nameLine1);
    nameTd.appendChild(nameLine2);
    tr.appendChild(nameTd);

    var ipTd = document.createElement("td");
    ipTd.className = isSelected
      ? "px-3 py-2 font-code-md text-code-md font-medium text-on-surface"
      : "px-3 py-2 font-code-md text-code-md text-on-surface";
    ipTd.textContent = item.ip;
    tr.appendChild(ipTd);

    var severityTd = document.createElement("td");
    severityTd.className = "px-3 py-2";
    severityTd.appendChild(severity.buildPill(item.severity));
    tr.appendChild(severityTd);

    var riskTd = document.createElement("td");
    riskTd.className = isSelected
      ? "px-3 py-2 text-right font-code-md text-code-md font-medium text-on-surface"
      : "px-3 py-2 text-right font-code-md text-code-md text-on-surface";
    riskTd.textContent = format.formatNumber(item.risk_score);
    tr.appendChild(riskTd);

    var timestampTd = document.createElement("td");
    timestampTd.className = "px-3 py-2 font-code-sm text-code-sm text-secondary";
    timestampTd.textContent = format.shortDateTime(item.timestamp);
    tr.appendChild(timestampTd);

    var actionTd = document.createElement("td");
    actionTd.className = "px-3 py-2";
    var actionSpan = document.createElement("span");
    if (isSelected) {
      actionSpan.className = "text-primary-container font-label-sm text-label-sm hover:underline";
      actionSpan.textContent = "Active";
    } else {
      actionSpan.className = "text-secondary hover:text-on-surface font-label-sm text-label-sm";
      actionSpan.textContent = "Inspect";
    }
    actionTd.appendChild(actionSpan);
    tr.appendChild(actionTd);

    tr.addEventListener("click", function () {
      selectThreat(item.id);
    });

    return tr;
  }

  function showEmptyPanel() {
    emptyBlock.classList.remove("hidden");
    headerEl.classList.add("hidden");
    fieldsEl.classList.add("hidden");
    footerEl.classList.add("hidden");
    logLinesSection.classList.add("hidden");
    currentSelectedItem = null;
  }

  function isIpMatchStandalone(text, matchIndex, matchLength) {
    var before = matchIndex > 0 ? text.charAt(matchIndex - 1) : "";
    if (before && /[0-9A-Za-z.]/.test(before)) {
      return false;
    }
    var afterIndex = matchIndex + matchLength;
    var after = afterIndex < text.length ? text.charAt(afterIndex) : "";
    if (after) {
      if (/[0-9A-Za-z]/.test(after)) {
        return false;
      }
      if (after === "." && /[0-9]/.test(text.charAt(afterIndex + 1))) {
        return false;
      }
    }
    return true;
  }

  function appendTextWithIpHighlight(container, text, ip) {
    if (!ip) {
      container.appendChild(document.createTextNode(text));
      return;
    }
    var cursor = 0;
    var searchFrom = 0;
    var matchIndex;
    while ((matchIndex = text.indexOf(ip, searchFrom)) !== -1) {
      if (isIpMatchStandalone(text, matchIndex, ip.length)) {
        if (matchIndex > cursor) {
          container.appendChild(document.createTextNode(text.slice(cursor, matchIndex)));
        }
        var ipSpan = document.createElement("span");
        ipSpan.className = "text-error font-medium";
        ipSpan.textContent = ip;
        container.appendChild(ipSpan);
        cursor = matchIndex + ip.length;
        searchFrom = cursor;
      } else {
        searchFrom = matchIndex + 1;
      }
    }
    if (cursor < text.length) {
      container.appendChild(document.createTextNode(text.slice(cursor)));
    }
  }

  function buildLogLineDiv(event, ip) {
    var div = document.createElement("div");
    var rest = event.raw_line;

    if (
      (event.log_type === "auth" || event.log_type === "syslog") &&
      event.raw_line.indexOf(event.timestamp) === 0
    ) {
      var tsSpan = document.createElement("span");
      tsSpan.className = "text-secondary";
      tsSpan.textContent = event.timestamp;
      div.appendChild(tsSpan);
      rest = event.raw_line.slice(event.timestamp.length);
    }

    appendTextWithIpHighlight(div, rest, ip);
    return div;
  }

  function fillTargetAccounts(events) {
    var seen = [];
    events.forEach(function (event) {
      if (event.user && seen.indexOf(event.user) === -1) {
        seen.push(event.user);
      }
    });
    if (seen.length === 0) {
      targetAccountsEl.textContent = "-";
      return;
    }
    var shown = seen.slice(0, MAX_TARGET_ACCOUNTS_SHOWN);
    var text = shown.join(", ");
    if (seen.length > MAX_TARGET_ACCOUNTS_SHOWN) {
      text += " +" + (seen.length - MAX_TARGET_ACCOUNTS_SHOWN) + " more";
    }
    targetAccountsEl.textContent = text;
  }

  function fillLogLines(events, ip) {
    var count = events.length;
    logLinesSection.classList.remove("hidden");
    dom.clear(logLinesBox);

    if (count === 0) {
      logLinesTitle.textContent = "Matching log lines (0)";
      logLinesShowing.textContent = "";
      logLinesShowAll.classList.add("hidden");
      var noneDiv = document.createElement("div");
      noneDiv.className = "text-secondary";
      noneDiv.textContent = "No log lines found for this IP.";
      logLinesBox.appendChild(noneDiv);
      return;
    }

    logLinesTitle.textContent = "Matching log lines (" + format.formatNumber(count) + ")";
    var shownCount = Math.min(MAX_LOG_LINES_SHOWN, count);
    logLinesShowing.textContent = "Showing " + shownCount + " latest";
    logLinesShowAll.classList.remove("hidden");
    logLinesShowAll.href = "log-events.html?ip=" + encodeURIComponent(ip);

    events.slice(0, shownCount).forEach(function (event) {
      logLinesBox.appendChild(buildLogLineDiv(event, ip));
    });
  }

  function showLogLinesFailure() {
    logLinesSection.classList.remove("hidden");
    logLinesTitle.textContent = "Matching log lines";
    logLinesShowing.textContent = "";
    logLinesShowAll.classList.add("hidden");
    dom.clear(logLinesBox);
    var failDiv = document.createElement("div");
    failDiv.className = "text-secondary";
    failDiv.textContent = "Couldn't load log lines.";
    logLinesBox.appendChild(failDiv);
  }

  function loadEventsForThreat(item) {
    var requestedId = item.id;
    api
      .getEvents({ ip: item.ip, limit: 200 })
      .then(function (data) {
        if (selectedId !== requestedId) {
          return;
        }
        fillTargetAccounts(data.events);
        fillLogLines(data.events, item.ip);
      })
      .catch(function (error) {
        if (selectedId !== requestedId) {
          return;
        }
        console.error(error);
        targetAccountsEl.textContent = "-";
        showLogLinesFailure();
      });
  }

  function showFilledPanel(item) {
    emptyBlock.classList.add("hidden");
    headerEl.classList.remove("hidden");
    fieldsEl.classList.remove("hidden");
    footerEl.classList.remove("hidden");

    var meta = severity.getPanelHeaderMeta(item.severity);
    severityDot.className = "inline-block w-2 h-2";
    severityDot.style.backgroundColor = meta.dotHex;
    severityLabel.className = "font-label-sm text-label-sm " + meta.textClass + " font-semibold uppercase tracking-wider";
    severityLabel.textContent = meta.label;
    titleEl.textContent = item.title;

    ipEl.textContent = item.ip;
    detectedAtEl.textContent = format.isoDateTime(item.timestamp);
    ruleEl.textContent = item.title + " (" + item.type + ")";
    detailsEl.textContent = item.details;
    riskScoreEl.textContent = item.risk_score + " / 100";
    maliciousTag.classList.toggle("hidden", item.risk_score < MALICIOUS_THRESHOLD);

    currentSelectedItem = item;

    targetAccountsEl.textContent = "-";
    logLinesSection.classList.add("hidden");
    loadEventsForThreat(item);
  }

  function renderPanel() {
    if (loadFailed || allThreats.length === 0) {
      showEmptyPanel();
      return;
    }
    var selected = allThreats.filter(function (t) {
      return t.id === selectedId;
    })[0];
    if (!selected) {
      showEmptyPanel();
      return;
    }
    showFilledPanel(selected);
  }

  function render() {
    dom.clear(tbody);

    if (loadFailed) {
      dom.appendMessageRow(tbody, { colspan: 7, message: "Couldn't load threats. Check that the backend is running." });
      countText.textContent = "Displaying 0 of 0 threats";
      renderPanel();
      return;
    }

    if (allThreats.length === 0) {
      dom.appendMessageRow(tbody, { colspan: 7, message: "No threats found." });
      countText.textContent = "Displaying 0 of 0 threats";
      renderPanel();
      return;
    }

    var filtered = getFilteredThreats();
    if (filtered.length === 0) {
      dom.appendMessageRow(tbody, { colspan: 7, message: "No threats match the current filters." });
      countText.textContent = "Displaying 0 of 0 threats";
      renderPanel();
      return;
    }

    filtered.forEach(function (item) {
      tbody.appendChild(buildTableRow(item, item.id === selectedId));
    });
    updateCountText(filtered.length);
    renderPanel();
  }

  function selectThreat(id) {
    selectedId = id;
    history.replaceState(null, "", "threat-detail.html?id=" + id);
    render();
  }

  function resolveInitialSelection() {
    var params = new URLSearchParams(window.location.search);
    var idParam = params.get("id");
    if (idParam !== null) {
      var numericId = Number(idParam);
      var match = allThreats.filter(function (t) {
        return t.id === numericId;
      })[0];
      if (match) {
        selectedId = match.id;
        return;
      }
    }
    var filtered = getFilteredThreats();
    selectedId = filtered.length > 0 ? filtered[0].id : null;
  }

  function updateStatusBar() {
    statusLeft.textContent = api.USE_MOCK ? "Data source: mock" : "Data source: " + api.BASE_URL;
    statusRight.textContent = "Threats loaded: " + allThreats.length;
  }

  function handleCopyIp() {
    if (!currentSelectedItem) {
      return;
    }
    navigator.clipboard
      .writeText(currentSelectedItem.ip)
      .then(function () {
        copyButton.textContent = "Copied";
        setTimeout(function () {
          copyButton.textContent = "Copy IP";
        }, 1500);
      })
      .catch(function (error) {
        console.error(error);
      });
  }

  function handleExportJson() {
    if (!currentSelectedItem) {
      return;
    }
    var json = JSON.stringify(currentSelectedItem, null, 2);
    var blob = new Blob([json], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = "threat-" + currentSelectedItem.id + ".json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  searchInput.addEventListener("input", render);
  severitySelect.addEventListener("change", render);

  copyIconButton.addEventListener("click", handleCopyIp);
  copyButton.addEventListener("click", handleCopyIp);
  exportButton.addEventListener("click", handleExportJson);

  closeButton.addEventListener("click", function () {
    window.location.href = "threats.html";
  });

  api
    .getThreats()
    .then(function (data) {
      allThreats = data;
      resolveInitialSelection();
      render();
      updateStatusBar();
    })
    .catch(function (error) {
      console.error(error);
      loadFailed = true;
      render();
      updateStatusBar();
    });
})();
