(function () {
  "use strict";

  // ---- Count-up animation for hero stats + sector percentages ----
  function animateCount(el) {
    var target = parseInt(el.getAttribute("data-count"), 10) || 0;
    var suffix = el.textContent.indexOf("%") !== -1 ? "%" : "";
    var duration = 900;
    var start = null;

    function step(ts) {
      if (!start) start = ts;
      var progress = Math.min((ts - start) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(eased * target) + suffix;
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---- Sophistication / sector bar fill ----
  function fillBar(el) {
    var level = el.getAttribute("data-level");
    var pct = el.getAttribute("data-pct");
    if (level !== null) {
      el.style.width = (parseInt(level, 10) / 5) * 100 + "%";
    } else if (pct !== null) {
      el.style.width = pct + "%";
    }
  }

  // ---- Scroll reveal via IntersectionObserver ----
  var revealTargets = document.querySelectorAll(".ta-reveal, .ta-timeline-item");
  var countTargets = document.querySelectorAll("[data-count]");
  var barTargets = document.querySelectorAll(".ta-sophistication-fill, .ta-sector-fill");

  if ("IntersectionObserver" in window) {
    var revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("ta-visible");
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );
    revealTargets.forEach(function (el) { revealObserver.observe(el); });

    var countObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            animateCount(entry.target);
            countObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.5 }
    );
    countTargets.forEach(function (el) { countObserver.observe(el); });

    var barObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            fillBar(entry.target);
            barObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.3 }
    );
    barTargets.forEach(function (el) { barObserver.observe(el); });
  } else {
    // Fallback: no IntersectionObserver support — show everything immediately
    revealTargets.forEach(function (el) { el.classList.add("ta-visible"); });
    countTargets.forEach(animateCount);
    barTargets.forEach(fillBar);
  }

  // ---- Accordion expand/collapse for actor detail panels ----
  document.querySelectorAll(".ta-expand-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var targetId = btn.getAttribute("data-toggle");
      var panel = document.getElementById(targetId);
      if (!panel) return;
      var isOpen = panel.classList.toggle("ta-open");
      btn.classList.toggle("ta-open", isOpen);
      // Re-trigger chip pop-in animation each time it opens
      if (isOpen) {
        panel.querySelectorAll(".ta-chip").forEach(function (chip) {
          chip.style.animation = "none";
          void chip.offsetWidth; // reflow
          chip.style.animation = "";
        });
      }
    });
  });
})();