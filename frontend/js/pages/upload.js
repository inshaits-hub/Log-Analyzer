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
        if (error && error.message === "Upload cancelled") {
          return;
        }
        showError("Upload failed: " + (error && error.message ? error.message : "unknown error"));
      });
  }

  fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files[0]) {
      handleFile(fileInput.files[0]);
    }
  });

  dropzone.addEventListener("dragover", function (event) {
    event.preventDefault();
  });

  dropzone.addEventListener("drop", function (event) {
    event.preventDefault();
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
