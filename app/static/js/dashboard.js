function initRiskChart() {
  const el = document.getElementById("riskChart");
  if (!el || typeof Chart === "undefined") return;
  const safe = Number(el.dataset.safe || 0);
  const suspicious = Number(el.dataset.suspicious || 0);
  const malicious = Number(el.dataset.malicious || 0);
  new Chart(el, {
    type: "doughnut",
    data: {
      labels: [
        el.dataset.labelSafe || "Safe",
        el.dataset.labelSuspicious || "Suspicious",
        el.dataset.labelMalicious || "Malicious",
      ],
      datasets: [{
        data: [safe, suspicious, malicious],
        backgroundColor: ["#22c55e", "#f59e0b", "#ef4444"],
        borderWidth: 0,
      }],
    },
    options: {
      plugins: { legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 12, padding: 12 } } },
      cutout: "68%",
    },
  });
}

async function fetchSummary(days) {
  try {
    const res = await fetch(`/api/dashboard/summary?days=${days}`);
    return await res.json();
  } catch (_) {
    return null;
  }
}

async function initCategoryChart(summary) {
  const el = document.getElementById("categoryChart");
  if (!el || typeof Chart === "undefined") return;
  const riskEl = document.getElementById("riskChart");
  const countLabel = riskEl?.dataset.labelCount || "Count";
  let labels = ["Phishing", "Malware", "Botnet"];
  let values = [0, 0, 0];
  if (summary?.top_categories?.length) {
    labels = summary.top_categories.map((c) => c.name);
    values = summary.top_categories.map((c) => c.count);
  }
  new Chart(el, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: countLabel,
        data: values,
        backgroundColor: "#2563eb",
        borderRadius: 6,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
        y: { ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#1e293b" } },
      },
    },
  });
}

function initCountryChart(summary) {
  const el = document.getElementById("countryChart");
  if (!el || typeof Chart === "undefined") return;
  const rows = summary?.country_distribution || [];
  const palette = ["#2563eb", "#0ea5e9", "#22c55e", "#f59e0b", "#a855f7"];
  new Chart(el, {
    type: "doughnut",
    data: {
      labels: rows.length ? rows.map((r) => r.name) : ["—"],
      datasets: [{
        data: rows.length ? rows.map((r) => r.count) : [1],
        backgroundColor: rows.length ? palette : ["#1e293b"],
        borderWidth: 0,
      }],
    },
    options: {
      plugins: { legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 12, padding: 12 } } },
      cutout: "68%",
    },
  });
}

function initActivityChart(summary) {
  const el = document.getElementById("activityChart");
  if (!el || typeof Chart === "undefined") return;
  const activity = summary?.daily_activity;
  const labels = activity?.labels || [];
  const mkDataset = (key, color, label) => ({
    label,
    data: activity ? activity[key] : [],
    borderColor: color,
    backgroundColor: color + "33",
    fill: true,
    tension: 0.35,
    pointRadius: 0,
  });
  new Chart(el, {
    type: "line",
    data: {
      labels,
      datasets: [
        mkDataset("safe", "#22c55e", el.dataset.labelSafe || "Safe"),
        mkDataset("suspicious", "#f59e0b", el.dataset.labelSuspicious || "Suspicious"),
        mkDataset("malicious", "#ef4444", el.dataset.labelMalicious || "Malicious"),
      ],
    },
    options: {
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 12, padding: 12 } } },
      scales: {
        x: { stacked: true, ticks: { color: "#94a3b8", maxTicksLimit: 8 }, grid: { display: false } },
        y: { stacked: true, ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#1e293b" } },
      },
    },
  });
}

function initTableFilter() {
  const input = document.getElementById("tableSearchInput");
  const table = document.getElementById("recentSearchesTable");
  if (!input || !table) return;
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    table.querySelectorAll("tbody tr[data-target]").forEach((row) => {
      row.style.display = row.dataset.target.includes(q) ? "" : "none";
    });
  });
}

function initToolbarActions() {
  const rangeSelect = document.getElementById("rangeSelect");
  if (rangeSelect) {
    rangeSelect.addEventListener("change", () => {
      const url = new URL(window.location.href);
      url.searchParams.set("days", rangeSelect.value);
      window.location.href = url.toString();
    });
  }
  const refreshBtn = document.getElementById("refreshDashboardBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => window.location.reload());
  }
}

(async function initDashboard() {
  initRiskChart();
  initTableFilter();
  initToolbarActions();

  const params = new URLSearchParams(window.location.search);
  const days = params.get("days") || "14";
  const summary = await fetchSummary(days);

  initCategoryChart(summary);
  initCountryChart(summary);
  initActivityChart(summary);
})();