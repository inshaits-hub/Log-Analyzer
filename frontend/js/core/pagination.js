/*
 * Pure client-side pagination math, shared by the threats and log-events
 * tables. Owns none of the DOM - callers render `pageItems` and wire up
 * their own prev/next/page-size controls using the returned totals.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.core = window.LogAnalyzer.core || {};

  function paginate(items, page, pageSize) {
    var total = items.length;
    var totalPages = Math.max(1, Math.ceil(total / pageSize));
    var clampedPage = page;
    if (clampedPage > totalPages) {
      clampedPage = totalPages;
    }
    if (clampedPage < 1) {
      clampedPage = 1;
    }

    var startIndex = (clampedPage - 1) * pageSize;
    var endIndex = Math.min(startIndex + pageSize, total);

    return {
      page: clampedPage,
      totalPages: totalPages,
      total: total,
      startIndex: startIndex,
      endIndex: endIndex,
      pageItems: items.slice(startIndex, endIndex),
      rangeText: total === 0 ? "0 of 0" : (startIndex + 1) + "-" + endIndex + " of " + total
    };
  }

  window.LogAnalyzer.core.pagination = {
    paginate: paginate
  };
})();
