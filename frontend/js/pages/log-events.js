(function () {
  var api = window.LogAnalyzer.Api;
  var format = window.LogAnalyzer.core.format;
  var dom = window.LogAnalyzer.core.dom;
  var pagination = window.LogAnalyzer.core.pagination;

  var COLLAPSED_ROW_CLASS = "row-link";
  var EXPANDED_PARENT_ROW_CLASS = "bg-surface-container-low/60";
  var TD_TIME_CLASS = "mono";
  var TD_SOURCE_CLASS = "";
  var TD_IP_CLASS = "mono";
  var TD_ACTION_CLASS = "";
  var TD_USERPATH_CLASS = "mono text-secondary max-w-[18rem] truncate";
  var TD_STATUS_CLASS = "mono text-secondary";

  var EXPANSION_TD_CLASS = "px-4 py-4 bg-surface-container-lowest border-y border-surface-container";
  var RAW_LINE_BLOCK_CLASS =
    "bg-surface-container rounded-lg border border-outline-variant p-3 mono text-on-surface mb-4 overflow-x-auto custom-scroll select-all";
  var PARSED_BOX_CLASS = "border border-outline-variant bg-white rounded-lg overflow-hidden";
  var PARSED_ROW_CLASS = "grid grid-cols-[132px_1fr] border-b border-surface-container text-[12.5px]";
  var PARSED_ROW_LAST_CLASS = "grid grid-cols-[132px_1fr] text-[12.5px]";
  var PARSED_LABEL_CLASS = "bg-surface-container-low px-3 py-2 text-secondary border-r border-surface-container";
  var PARSED_VALUE_CLASS = "px-3 py-2 mono text-on-surface";

  var ACTION_LABELS = {
    http_request: "HTTP Request",
    ssh_login_failure: "Failed Login",
    ssh_invalid_user: "Failed Login",
    ssh_auth_failure: "Failed Login",
    firewall_block: "Blocked Drop",
    ssh_login_success: "Successful Login",
    ssh_session_opened: "Session Opened",
    ssh_disconnect: "Disconnect",
    syslog_event: "System Event"
  };

  var WEB_LOG_RE = /"(\S+)\s+(\S+)\s+([^"]+)"\s+(\d{3})\s+\S+\s+"[^"]*"\s+"([^"]*)"/;

  var countEl = document.getElementById("log-events-count");
  var showingNoteEl = document.getElementById("log-events-showing-note");
  var searchInput = document.getElementById("log-events-search");
  var sourceSelect = document.getElementById("log-events-filter-source");
  var actionSelect = document.getElementById("log-events-filter-action");
  var threatCheckbox = document.getElementById("log-events-filter-threat");
  var tbody = document.getElementById("log-events-tbody");
  var rangeEl = document.getElementById("log-events-range");
  var pageSizeSelect = document.getElementById("log-events-page-size");
  var prevButton = document.getElementById("log-events-prev-button");
  var nextButton = document.getElementById("log-events-next-button");

  var allEvents = [];
  var expandedEventId = null;
  var state = {
    search: "",
    source: "",
    action: "",
    onlyThreat: false,
    page: 1,
    pageSize: 25
  };

  function computeTime(item) {
    var raw = item.timestamp || "";
    if (!raw) {
      return "-";
    }
    if (item.log_type === "web") {
      var colonIndex = raw.indexOf(":");
      var after = colonIndex === -1 ? "" : raw.slice(colonIndex + 1);
      var webMatch = after.match(/\d{2}:\d{2}:\d{2}/);
      return webMatch ? webMatch[0] : raw;
    }
    var matches = raw.match(/\d{2}:\d{2}:\d{2}/g);
    return matches ? matches[matches.length - 1] : raw;
  }

  function computeSourceLabel(item) {
    if (item.log_type === "auth") {
      return "SSH";
    }
    if (item.log_type === "web") {
      return "Nginx";
    }
    return item.action === "firewall_block" ? "Firewall" : "Syslog";
  }

  function computeActionLabel(item) {
    return ACTION_LABELS[item.action] || item.action;
  }

  function parseWebRawLine(rawLine) {
    var match = WEB_LOG_RE.exec(rawLine || "");
    if (!match) {
      return { method: "", path: "", protocol: "", status: "", user_agent: "" };
    }
    return {
      method: match[1] || "",
      path: match[2] || "",
      protocol: match[3] || "",
      status: match[4] || "",
      user_agent: match[5] || ""
    };
  }

  function parseFirewallDstPort(rawLine) {
    var match = /DPT=(\d+)/.exec(rawLine || "");
    return match ? match[1] : "";
  }

  function computeUserOrPath(item, parsedWeb, dstPort) {
    if (item.log_type === "auth") {
      return item.user || "-";
    }
    if (item.log_type === "web") {
      return parsedWeb.path || "-";
    }
    if (item.action === "firewall_block") {
      return dstPort ? "DPT=" + dstPort : "-";
    }
    return "-";
  }

  function computeStatus(item, parsedWeb) {
    if (item.log_type === "web") {
      return parsedWeb.status || "-";
    }
    return "-";
  }

  function computeLinkedToThreat(item, threatIpMap) {
    return !!(item.ip && threatIpMap[item.ip]);
  }

  function buildDerived(item, threatIpMap) {
    var parsedWeb = item.log_type === "web" ? parseWebRawLine(item.raw_line) : null;
    var dstPort = item.action === "firewall_block" ? parseFirewallDstPort(item.raw_line) : "";
    return {
      time: computeTime(item),
      sourceLabel: computeSourceLabel(item),
      actionLabel: computeActionLabel(item),
      parsedWeb: parsedWeb,
      dstPort: dstPort,
      userOrPath: computeUserOrPath(item, parsedWeb || {}, dstPort),
      status: computeStatus(item, parsedWeb || {}),
      linkedToThreat: computeLinkedToThreat(item, threatIpMap)
    };
  }

  function matchesSource(item, sourceFilter) {
    if (!sourceFilter) {
      return true;
    }
    if (sourceFilter === "ssh") {
      return item.log_type === "auth";
    }
    if (sourceFilter === "nginx") {
      return item.log_type === "web";
    }
    if (sourceFilter === "firewall") {
      return item.action === "firewall_block";
    }
    return true;
  }

  function matchesAction(item, actionFilter) {
    if (!actionFilter) {
      return true;
    }
    if (actionFilter === "http") {
      return item.action === "http_request";
    }
    if (actionFilter === "failed") {
      return item.action === "ssh_login_failure" || item.action === "ssh_invalid_user" || item.action === "ssh_auth_failure";
    }
    if (actionFilter === "blocked") {
      return item.action === "firewall_block";
    }
    if (actionFilter === "success") {
      return item.action === "ssh_login_success";
    }
    return true;
  }

  function applyFilters() {
    var searchTerm = state.search.trim().toLowerCase();
    return allEvents.filter(function (item) {
      if (searchTerm) {
        var haystack = [
          item.ip || "",
          item.user || "",
          item._derived.actionLabel,
          item._derived.sourceLabel,
          item.raw_line || ""
        ].join(" ").toLowerCase();
        if (haystack.indexOf(searchTerm) === -1) {
          return false;
        }
      }
      if (!matchesSource(item, state.source)) {
        return false;
      }
      if (!matchesAction(item, state.action)) {
        return false;
      }
      if (state.onlyThreat && !item._derived.linkedToThreat) {
        return false;
      }
      return true;
    });
  }

  function buildParsedFields(item) {
    var d = item._derived;
    var fields = [];
    fields.push(["timestamp", item.timestamp]);
    fields.push(["ip", item.ip]);
    fields.push(["log_type", item.log_type]);
    fields.push(["action", item.action]);
    fields.push(["user", item.user]);
    if (item.log_type === "web" && d.parsedWeb) {
      fields.push(["method", d.parsedWeb.method]);
      fields.push(["path", d.parsedWeb.path]);
      fields.push(["protocol", d.parsedWeb.protocol]);
      fields.push(["status", d.parsedWeb.status]);
      fields.push(["user_agent", d.parsedWeb.user_agent]);
    } else if (item.action === "firewall_block") {
      fields.push(["dst_port", d.dstPort]);
    }
    return fields.filter(function (pair) {
      return pair[1] !== null && pair[1] !== undefined && pair[1] !== "";
    });
  }

  function buildExpansionRow(item) {
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    td.className = EXPANSION_TD_CLASS;
    td.setAttribute("colspan", "7");

    var wrapper = document.createElement("div");
    wrapper.className = "flex flex-col";

    var rawLineBlock = document.createElement("div");
    rawLineBlock.className = RAW_LINE_BLOCK_CLASS;
    rawLineBlock.textContent = item.raw_line;
    wrapper.appendChild(rawLineBlock);

    var parsedBox = document.createElement("div");
    parsedBox.className = PARSED_BOX_CLASS;

    var fields = buildParsedFields(item);
    fields.forEach(function (pair, index) {
      var isLast = index === fields.length - 1;
      var row = document.createElement("div");
      row.className = isLast ? PARSED_ROW_LAST_CLASS : PARSED_ROW_CLASS;

      var label = document.createElement("div");
      label.className = PARSED_LABEL_CLASS;
      label.textContent = pair[0];
      row.appendChild(label);

      var value = document.createElement("div");
      value.className = PARSED_VALUE_CLASS;
      value.textContent = pair[1];
      row.appendChild(value);

      parsedBox.appendChild(row);
    });

    wrapper.appendChild(parsedBox);
    td.appendChild(wrapper);
    tr.appendChild(td);
    return tr;
  }

  function buildRow(item) {
    var d = item._derived;
    var isExpanded = expandedEventId === item.id;

    var tr = document.createElement("tr");
    tr.className = isExpanded ? EXPANDED_PARENT_ROW_CLASS : COLLAPSED_ROW_CLASS;
    tr.setAttribute("aria-expanded", isExpanded ? "true" : "false");
    tr.addEventListener("click", function () {
      expandedEventId = isExpanded ? null : item.id;
      render();
    });

    var timeTd = document.createElement("td");
    timeTd.className = TD_TIME_CLASS;
    timeTd.textContent = d.time;
    tr.appendChild(timeTd);

    var sourceTd = document.createElement("td");
    sourceTd.className = TD_SOURCE_CLASS;
    sourceTd.textContent = d.sourceLabel;
    tr.appendChild(sourceTd);

    var ipTd = document.createElement("td");
    ipTd.className = TD_IP_CLASS;
    ipTd.textContent = item.ip || "-";
    tr.appendChild(ipTd);

    var actionTd = document.createElement("td");
    actionTd.className = TD_ACTION_CLASS;
    actionTd.textContent = d.actionLabel;
    tr.appendChild(actionTd);

    var userPathTd = document.createElement("td");
    userPathTd.className = TD_USERPATH_CLASS;
    userPathTd.textContent = d.userOrPath;
    tr.appendChild(userPathTd);

    var statusTd = document.createElement("td");
    statusTd.className = TD_STATUS_CLASS;
    statusTd.textContent = d.status;
    tr.appendChild(statusTd);

    var threatTd = document.createElement("td");
    if (d.linkedToThreat) {
      // A real badge rather than a bare red word, and the row links through
      // to the log filtered by this event's IP.
      var flag = document.createElement("span");
      flag.className = "badge sev-critical";
      flag.appendChild(document.createTextNode("Flagged"));
      threatTd.appendChild(flag);
    }
    tr.appendChild(threatTd);

    return tr;
  }

  function render() {
    dom.clear(tbody);

    var filtered = applyFilters();
    var result = pagination.paginate(filtered, state.page, state.pageSize);
    state.page = result.page;

    if (allEvents.length === 0) {
      dom.appendMessageRow(tbody, { colspan: 7, message: "No events found." });
    } else if (result.total === 0) {
      dom.appendMessageRow(tbody, { colspan: 7, message: "No events match the current filters." });
    } else {
      result.pageItems.forEach(function (item) {
        tbody.appendChild(buildRow(item));
        if (expandedEventId === item.id) {
          tbody.appendChild(buildExpansionRow(item));
        }
      });
    }

    rangeEl.textContent = result.rangeText;

    dom.setDisabled(prevButton, result.page <= 1 || result.total === 0);
    dom.setDisabled(nextButton, result.page >= result.totalPages || result.total === 0);
  }

  function renderLoadFailure() {
    dom.clear(tbody);
    dom.appendMessageRow(tbody, { colspan: 7, message: "Couldn't load log events. Check that the backend is running." });
    rangeEl.textContent = "0 of 0";
    dom.setDisabled(prevButton, true);
    dom.setDisabled(nextButton, true);
  }

  searchInput.addEventListener("input", function () {
    state.search = searchInput.value;
    state.page = 1;
    expandedEventId = null;
    render();
  });

  sourceSelect.addEventListener("change", function () {
    state.source = sourceSelect.value;
    state.page = 1;
    expandedEventId = null;
    render();
  });

  actionSelect.addEventListener("change", function () {
    state.action = actionSelect.value;
    state.page = 1;
    expandedEventId = null;
    render();
  });

  threatCheckbox.addEventListener("change", function () {
    state.onlyThreat = threatCheckbox.checked;
    state.page = 1;
    expandedEventId = null;
    render();
  });

  pageSizeSelect.addEventListener("change", function () {
    state.pageSize = Number(pageSizeSelect.value);
    state.page = 1;
    expandedEventId = null;
    render();
  });

  prevButton.addEventListener("click", function () {
    if (state.page > 1) {
      state.page -= 1;
      expandedEventId = null;
      render();
    }
  });

  nextButton.addEventListener("click", function () {
    var totalPages = Math.max(1, Math.ceil(applyFilters().length / state.pageSize));
    if (state.page < totalPages) {
      state.page += 1;
      expandedEventId = null;
      render();
    }
  });

  function getIpFromUrl() {
    var params = new URLSearchParams(window.location.search);
    return params.get("ip");
  }

  var ipParam = getIpFromUrl();
  if (ipParam) {
    searchInput.value = ipParam;
    state.search = ipParam;
  }

  Promise.all([
    api.getEvents({ limit: 500 }),
    api.getThreats().catch(function () {
      return [];
    }),
    api.getSummary().catch(function () {
      return null;
    })
  ])
    .then(function (results) {
      var eventsData = results[0];
      var threatsData = results[1];
      var summaryData = results[2];

      allEvents = eventsData.events;

      var threatIpMap = {};
      threatsData.forEach(function (threat) {
        if (threat.ip) {
          threatIpMap[threat.ip] = true;
        }
      });

      allEvents.forEach(function (item) {
        item._derived = buildDerived(item, threatIpMap);
      });

      var totalEvents = summaryData ? summaryData.total_events : allEvents.length;
      countEl.textContent = format.formatNumber(totalEvents);
      if (allEvents.length < totalEvents) {
        showingNoteEl.textContent = "Showing latest " + format.formatNumber(allEvents.length);
        showingNoteEl.classList.remove("hidden");
      } else {
        showingNoteEl.classList.add("hidden");
      }

      render();
    })
    .catch(function (error) {
      console.error(error);
      countEl.textContent = "-";
      renderLoadFailure();
    });
})();
