/* ============================================================
   TIP — Global Animation Engine
   Runs on every page (loaded from base.html). Auto-tags common
   elements for scroll-reveal, adds a scroll progress bar, a
   back-to-top button, button ripples, stat count-up, and a
   subtle landing-page parallax. No per-template markup required.
   ============================================================ */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- Scroll progress bar ---------- */
  var progress = document.createElement("div");
  progress.className = "scroll-progress";
  document.body.appendChild(progress);

  /* The app scrolls the document itself (sidebar is fixed, topbar is
     sticky) — not an inner container — so always measure window scroll. */
  var scrollTarget = window;

  function updateProgress() {
    var scrollTop = window.scrollY || document.documentElement.scrollTop;
    var scrollHeight = document.documentElement.scrollHeight;
    var clientHeight = window.innerHeight;
    var max = Math.max(scrollHeight - clientHeight, 1);
    var pct = Math.min(100, Math.max(0, (scrollTop / max) * 100));
    progress.style.width = pct + "%";

    var topbar = document.querySelector(".topbar");
    if (topbar) topbar.classList.toggle("is-scrolled", scrollTop > 4);

    backToTop.classList.toggle("is-visible", scrollTop > 320);
  }

  /* ---------- Back to top ---------- */
  var backToTop = document.createElement("button");
  backToTop.type = "button";
  backToTop.className = "back-to-top";
  backToTop.setAttribute("aria-label", (window.I18N && window.I18N.backToTop) || "Back to top");
  backToTop.innerHTML = '<i class="bi bi-arrow-up"></i>';
  backToTop.addEventListener("click", function () {
    window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
  });
  document.body.appendChild(backToTop);

  scrollTarget.addEventListener("scroll", updateProgress, { passive: true });
  window.addEventListener("resize", updateProgress);
  updateProgress();

  /* ---------- Scroll-reveal auto-tagging ---------- */
  var revealSelectors = [
    ".panel-card", ".stat-card", ".feature-card", ".twofa-step",
    ".profile-link-card", ".twofa-code-chip", ".landing-features .feature-card"
  ];
  var seen = new Set();
  revealSelectors.forEach(function (sel) {
    document.querySelectorAll(sel).forEach(function (el) {
      if (seen.has(el) || el.hasAttribute("data-reveal")) return;
      seen.add(el);
      var parent = el.parentElement;
      if (!parent.__revealCount) parent.__revealCount = 0;
      var idx = parent.__revealCount++;
      el.setAttribute("data-reveal", "up");
      el.style.setProperty("--reveal-delay", (Math.min(idx, 8) * 0.07) + "s");
    });
  });

  var revealEls = document.querySelectorAll("[data-reveal]");
  if (reduceMotion || !("IntersectionObserver" in window)) {
    revealEls.forEach(function (el) { el.classList.add("is-visible"); });
  } else {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
    );
    revealEls.forEach(function (el) { io.observe(el); });
  }

  /* ---------- Table row stagger index ---------- */
  document.querySelectorAll("table tbody").forEach(function (tbody) {
    Array.prototype.forEach.call(tbody.children, function (row, i) {
      row.style.setProperty("--row-i", i);
    });
  });

  /* ---------- Button ripple ---------- */
  if (!reduceMotion) {
    document.addEventListener("click", function (e) {
      var btn = e.target.closest ? e.target.closest(".btn") : null;
      if (!btn) return;
      var rect = btn.getBoundingClientRect();
      var size = Math.max(rect.width, rect.height);
      var ripple = document.createElement("span");
      ripple.className = "ripple";
      ripple.style.width = ripple.style.height = size + "px";
      ripple.style.left = (e.clientX - rect.left - size / 2) + "px";
      ripple.style.top = (e.clientY - rect.top - size / 2) + "px";
      btn.appendChild(ripple);
      ripple.addEventListener("animationend", function () { ripple.remove(); });
    });
  }

  /* ---------- Stat value count-up ---------- */
  if (!reduceMotion) {
    document.querySelectorAll(".stat-value").forEach(function (el) {
      var raw = el.textContent.trim();
      var match = raw.match(/^(-?\d[\d,]*)(.*)$/);
      if (!match) return;
      var target = parseInt(match[1].replace(/,/g, ""), 10);
      if (isNaN(target)) return;
      var suffix = match[2] || "";
      var duration = 900;
      var startTime = null;
      el.textContent = "0" + suffix;
      function tick(ts) {
        if (startTime === null) startTime = ts;
        var p = Math.min((ts - startTime) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(target * eased).toLocaleString() + suffix;
        if (p < 1) requestAnimationFrame(tick);
        else el.textContent = raw;
      }
      requestAnimationFrame(tick);
    });
  }

  /* ---------- Landing hero parallax ---------- */
  var heroContent = document.querySelector(".landing-hero-content");
  if (heroContent && !reduceMotion) {
    document.querySelector(".landing-hero").addEventListener("mousemove", function (e) {
      var rect = this.getBoundingClientRect();
      var x = ((e.clientX - rect.left) / rect.width - 0.5) * 10;
      var y = ((e.clientY - rect.top) / rect.height - 0.5) * 10;
      heroContent.style.transform = "translate(" + x + "px, " + y + "px)";
    });
    document.querySelector(".landing-hero").addEventListener("mouseleave", function () {
      heroContent.style.transform = "translate(0, 0)";
    });
  }
})();