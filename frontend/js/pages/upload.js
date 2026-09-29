(function () {
  var api = window.LogAnalyzer.Api;
  var format = window.LogAnalyzer.core.format;
  var config = window.LogAnalyzer.config;

  var MAX_FILE_SIZE_BYTES = 16 * 1024 * 1024;
  var ALLOWED_EXTENSIONS = [".log", ".txt"];

  var dropzone = document.getElementById("upload-dropzone");
  var fileInput = document.getElementById("upload-file-input");
  var errorBlock = document.getElementById("upload-error");
  var errorText = document.getElementById("upload-error-text");
  var progressPanel = document.getElementById("upload-progress-panel");
  var progressFilename = document.getElementById("upload-progress-filename");
  var progressFilesize = document.getElementById("upload-progress-filesize");
  var progressType = document.getElementById("upload-progress-type");
  var progressBar = document.getElementById("upload-progress-bar");
  var progressStatus = document.getElementById("upload-progress-status");
  var cancelButton = document.getElementById("upload-cancel-button");
  var finishedPanel = document.getElementById("upload-finished-panel");
  var finishedText = document.getElementById("upload-finished-text");

  var currentAbortController = null;

  function hasAllowedExtension(filename) {
    var lower = filename.toLowerCase();
    return ALLOWED_EXTENSIONS.some(function (ext) {
      return lower.slice(-ext.length) === ext;
    });
  }

  function detectLogType(filename) {
    var lower = filename.toLowerCase();
    if (lower.indexOf("access") !== -1) {
      return "Nginx access log";
    }
    if (lower.indexOf("auth") !== -1) {
      return "SSH auth log";
    }
    if (lower.indexOf("ufw") !== -1 || lower.indexOf("firewall") !== -1) {
      return "UFW firewall log";
    }
    return "Log file";
  }

  function hidePanels() {
    errorBlock.classList.add("hidden");
    progressPanel.classList.add("hidden");
    finishedPanel.classList.add("hidden");
  }

  function showError(message) {
    errorText.textContent = message;
    hidePanels();
    errorBlock.classList.remove("hidden");
  }

  function handleFile(file) {
    if (!hasAllowedExtension(file.name)) {
      showError(file.name + " can't be analyzed. Only .log and .txt files are supported.");
      return;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      showError(file.name + " is too large. Files must be 16 MB or smaller.");
      return;
    }

    hidePanels();
    progressFilename.textContent = file.name;
    progressFilesize.textContent = format.fileSize(file.size);
    progressType.textContent = detectLogType(file.name);
    progressBar.style.width = "0%";
    progressStatus.textContent = "Uploading...";
    progressPanel.classList.remove("hidden");

    currentAbortController =
      typeof AbortController !== "undefined" ? new AbortController() : null;

    api
      .uploadLogFile(file, {
        signal: currentAbortController ? currentAbortController.signal : undefined,
        onProgress: function (percent) {
          progressBar.style.width = percent + "%";
          progressStatus.textContent = "Detecting threats: " + percent + "%";
        }
      })
      .then(function (result) {
        progressPanel.classList.add("hidden");
        var criticalCount = result.severity_counts && result.severity_counts.CRITICAL;
        var criticalClause =
          typeof criticalCount === "number" ? " (" + format.formatNumber(criticalCount) + " critical)" : "";
        finishedText.textContent =
          "Done. " +
          format.formatNumber(result.parsed_events) +
          " events parsed, " +
          format.formatNumber(result.threats_detected) +
          " threats found" +
          criticalClause +
          ".";
        finishedPanel.classList.remove("hidden");

        try {
          sessionStorage.setItem(
            config.LAST_UPLOAD_STORAGE_KEY,
            JSON.stringify({ filename: result.filename, uploadedAt: new Date().toISOString() })
          );
        } catch (storageError) {
          // sessionStorage unavailable (private browsing, etc.) - Overview just won't show a last-upload line.
        }
      })
      .catch(function (error) {
        progressPanel.classList.add("hidden");
        // Detect a cancel by error.name. Matching on the message text only
        // worked for the mock; a real AbortController abort surfaces as a
        // DOMException named "AbortError", so the user used to be told the
        // upload had FAILED right after they deliberately cancelled it.
        if (error && (error.name === "AbortError" || error.message === "Upload cancelled")) {
          // User-initiated cancel: return to the idle dropzone silently
          // rather than showing an error they did not cause.
          currentAbortController = null;
          return;
        }
        showError("Upload failed: " + (error && error.message ? error.message : "unknown error"));
      });
  }

  fileInput.addEventListener("change", function () {
    var file = fileInput.files && fileInput.files[0];
    // Clear the selection immediately so re-picking the SAME path always
    // fires a fresh `change` event. Without this, a user who rejected a
    // file, fixed it, and re-selected it got no event and no feedback.
    fileInput.value = "";
    if (file) {
      handleFile(file);
    }
  });

  // dragenter/dragleave fire for every child element the cursor crosses,
  // so a plain toggle flickers. Track a depth counter instead.
  var dragDepth = 0;

  function setDragActive(active) {
    // Toggles one dedicated class (styled in css/style.css) rather than
    // swapping two competing Tailwind border-colour utilities, which would
    // resolve by stylesheet order instead of by what we asked for.
    dropzone.classList.toggle("is-dragging", active);
  }

  ["dragenter", "dragover"].forEach(function (type) {
    dropzone.addEventListener(type, function (event) {
      event.preventDefault();
      if (event.dataTransfer) {
        event.dataTransfer.dropEffect = "copy";
      }
      if (type === "dragenter") {
        dragDepth += 1;
        setDragActive(true);
      }
    });
  });

  dropzone.addEventListener("dragleave", function (event) {
    event.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) {
      setDragActive(false);
    }
  });

  // If the user drops the file anywhere outside the zone the drag never
  // ends with a dragleave, which would leave the highlight stuck on.
  window.addEventListener("dragend", function () {
    dragDepth = 0;
    setDragActive(false);
  });

  dropzone.addEventListener("drop", function (event) {
    event.preventDefault();
    dragDepth = 0;
    setDragActive(false);
    var file =
      event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) {
      handleFile(file);
    }
  });

  cancelButton.addEventListener("click", function () {
    if (currentAbortController) {
      currentAbortController.abort();
    }
    progressPanel.classList.add("hidden");
  });
})();
