(function () {
  "use strict";

  var filterButtons = document.querySelectorAll(".cve-filter-btn");
  var cards = document.querySelectorAll(".cve-card");
  var emptyState = document.querySelector(".cve-empty-state");
  var exposureChecks = document.querySelectorAll(".cve-exposure-check");

  var activeFilter = "all";
  var exposedProducts = new Set();

  function applyView() {
    var visibleCount = 0;
    cards.forEach(function (card) {
      var matchesSeverity = activeFilter === "all" || card.getAttribute("data-severity") === activeFilter;
      card.classList.toggle("cve-hidden", !matchesSeverity);
      if (matchesSeverity) visibleCount += 1;

      var isExposed = exposedProducts.has(card.getAttribute("data-product"));
      card.classList.toggle("cve-exposed", isExposed);
    });
    if (emptyState) emptyState.classList.toggle("d-none", visibleCount > 0);
  }

  filterButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      filterButtons.forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      activeFilter = btn.getAttribute("data-filter");
      applyView();
    });
  });

  exposureChecks.forEach(function (check) {
    check.addEventListener("change", function () {
      var product = check.getAttribute("data-product");
      var item = check.closest(".cve-exposure-item");
      if (check.checked) {
        exposedProducts.add(product);
        if (item) item.classList.add("cve-exposure-active");
      } else {
        exposedProducts.delete(product);
        if (item) item.classList.remove("cve-exposure-active");
      }
      applyView();
    });
  });

  applyView();
})();