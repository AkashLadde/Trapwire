// Sidebar nav switching
const crumbTab = document.getElementById("crumbTab");
const tabLabels = {
  orders: "Orders & Customers", security: "Security Center",
  projects: "Projects", leaderboard: "Leaderboard",
  administration: "Administration", library: "Library",
  maps: "Maps", support: "Support & Help",
};
document.querySelectorAll(".side-link").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".side-link").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.remove("hidden");
    if (crumbTab) crumbTab.textContent = tabLabels[btn.dataset.tab] || btn.dataset.tab;
    if (btn.dataset.tab === "security") {
      const dot = document.getElementById("alertDot");
      if (dot) dot.classList.remove("show");
    }
  });
});
// orders tab visible by default
const ordersTab = document.getElementById("tab-orders");
if (ordersTab) ordersTab.classList.remove("hidden");

// ---- Orders table: search + status filter + value sort ----
const ordersTable = document.getElementById("ordersTable");
if (ordersTable) {
  const rows = Array.from(ordersTable.querySelectorAll("tbody tr"));
  const tableSearch = document.getElementById("tableSearch");
  const statusChips = document.querySelectorAll("#statusChips .filter-chip");
  const tableCount = document.getElementById("tableCount");
  const noResultsMsg = document.getElementById("noResultsMsg");
  let activeStatus = "all";

  function applyFilters() {
    const q = (tableSearch?.value || "").trim().toLowerCase();
    let visible = 0;
    rows.forEach(row => {
      const matchesStatus = activeStatus === "all" || row.dataset.status === activeStatus;
      const matchesSearch = !q || row.dataset.search.includes(q);
      const show = matchesStatus && matchesSearch;
      row.style.display = show ? "" : "none";
      if (show) visible += 1;
    });
    if (tableCount) tableCount.textContent = `${visible} of ${rows.length} records`;
    if (noResultsMsg) noResultsMsg.style.display = visible === 0 ? "block" : "none";
  }

  tableSearch?.addEventListener("input", applyFilters);

  const globalSearch = document.getElementById("globalSearch");
  globalSearch?.addEventListener("input", () => {
    if (tableSearch) tableSearch.value = globalSearch.value;
    applyFilters();
  });

  statusChips.forEach(chip => {
    chip.addEventListener("click", () => {
      statusChips.forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      activeStatus = chip.dataset.status;
      applyFilters();
    });
  });

  let valueSortAsc = false;
  document.getElementById("sortValue")?.addEventListener("click", () => {
    valueSortAsc = !valueSortAsc;
    const tbody = ordersTable.querySelector("tbody");
    const sorted = rows.slice().sort((a, b) => {
      const av = parseFloat(a.dataset.value), bv = parseFloat(b.dataset.value);
      return valueSortAsc ? av - bv : bv - av;
    });
    sorted.forEach(r => tbody.appendChild(r));
  });
}

// ---- Notification bell + profile dropdown ----
function setupDropdown(btnId, menuId) {
  const btn = document.getElementById(btnId);
  const menu = document.getElementById(menuId);
  if (!btn || !menu) return;
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const willOpen = menu.classList.contains("hidden");
    document.querySelectorAll(".dropdown-menu").forEach(m => m.classList.add("hidden"));
    if (willOpen) menu.classList.remove("hidden");
  });
}
setupDropdown("notifBellBtn", "notifPanel");
setupDropdown("profileChipBtn", "profileMenu");
document.addEventListener("click", () => {
  document.querySelectorAll(".dropdown-menu").forEach(m => m.classList.add("hidden"));
});

document.getElementById("notifViewAll")?.addEventListener("click", (e) => {
  e.preventDefault();
  document.querySelector('.side-link[data-tab="security"]')?.click();
  document.getElementById("notifPanel")?.classList.add("hidden");
});

function bumpNotifBadge() {
  const badge = document.getElementById("notifBadge");
  if (!badge) return;
  const current = parseInt(badge.textContent || "0", 10) || 0;
  badge.textContent = String(current + 1);
  badge.classList.add("show");
}

function pushNotifPanelItem(a) {
  const list = document.getElementById("notifList");
  if (!list) return;
  const empty = list.querySelector(".notif-empty");
  if (empty) empty.remove();
  const t = new Date(a.timestamp * 1000).toLocaleTimeString();
  const div = document.createElement("div");
  div.className = "alert-item alert-" + a.level;
  div.style.margin = "8px";
  div.innerHTML = `<span class="alert-body"><span class="alert-time">${t}</span> ${a.message}</span>`;
  list.prepend(div);
}

// Export button
const exportBtn = document.getElementById("exportBtn");
if (exportBtn) {
  exportBtn.addEventListener("click", async () => {
    const res = await fetch("/api/export");
    const payload = await res.json();
    const blob = new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "customer_export.json";
    a.click();

    if (window.SUSPICIOUS) {
      // Simulate the attacker previewing/opening the exfiltrated file,
      // which is what actually triggers the canary phone-home.
      const dataEl = document.getElementById("recordsData");
      const records = dataEl ? JSON.parse(dataEl.textContent) : [];
      const trackingUrl = records[0] && records[0]._tracking_invoice_url;
      if (trackingUrl) {
        setTimeout(() => {
          const iframe = document.createElement("iframe");
          iframe.style.display = "none";
          iframe.src = trackingUrl;
          document.body.appendChild(iframe);
          exportBtn.insertAdjacentHTML("afterend",
            '<p class="msg">File downloaded. (Opening it just triggered a tracking beacon back to the server.)</p>');
        }, 800);
      }
    }
  });
}

// Report generation
const reportBtn = document.getElementById("reportBtn");
if (reportBtn) {
  reportBtn.addEventListener("click", async () => {
    const res = await fetch("/api/report", {method: "POST"});
    const msg = document.getElementById("reportMsg");
    if (res.ok) {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "DPDP_Breach_Report.pdf";
      a.click();
      msg.textContent = "Report generated and downloaded.";
      msg.className = "msg";
    } else {
      const j = await res.json();
      msg.textContent = j.error || "No incident to report yet.";
      msg.className = "msg error";
    }
  });
}

// Threat activity graph
let threatChart = null;
function initThreatChart(initialAlerts) {
  const canvas = document.getElementById("threatChart");
  if (!canvas || typeof Chart === "undefined") return;

  // initialAlerts is chronological (oldest first); build a running
  // cumulative count of "threat-worthy" (critical) events over time.
  let count = 0;
  const labels = [];
  const points = [];
  initialAlerts.forEach(a => {
    if (a.level === "critical") {
      count += 1;
      labels.push(new Date(a.timestamp * 1000).toLocaleTimeString());
      points.push(count);
    }
  });

  threatChart = new Chart(canvas.getContext("2d"), {
    type: "line",
    data: {
      labels: labels,
      datasets: [{
        label: "Threats Detected (cumulative)",
        data: points,
        borderColor: "#DC2626",
        backgroundColor: "rgba(220,38,38,0.08)",
        fill: true,
        tension: 0.3,
        pointRadius: 3,
        pointBackgroundColor: "#DC2626",
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { font: { family: "JetBrains Mono", size: 10 } } },
        y: { beginAtZero: true, ticks: { precision: 0 } }
      }
    }
  });
}

function pushThreatPoint(alert) {
  if (!threatChart || alert.level !== "critical") return;
  const prevCount = threatChart.data.datasets[0].data.slice(-1)[0] || 0;
  threatChart.data.labels.push(new Date(alert.timestamp * 1000).toLocaleTimeString());
  threatChart.data.datasets[0].data.push(prevCount + 1);
  threatChart.update();
}

// Live alert feed
const alertFeed = document.getElementById("alertFeed");
const submittedReportsBox = document.getElementById("submittedReports");

function renderSubmittedReports() {
  if (!submittedReportsBox) return;
  fetch("/api/submitted-reports").then(r => r.json()).then(list => {
    submittedReportsBox.innerHTML = "";
    if (list.length === 0) {
      submittedReportsBox.innerHTML = '<p class="muted small">No reports submitted yet.</p>';
      return;
    }
    list.forEach(r => {
      const t = new Date(r.submitted_at * 1000).toLocaleString();
      const div = document.createElement("div");
      div.className = "alert-item";
      div.innerHTML = `<span class="alert-time">${t}</span>
        <b>${r.stage.toUpperCase()}</b> report — ${r.incident_id}
        &nbsp;<a href="/api/submitted-reports/${r.filename}" target="_blank">Download</a>
        &nbsp;·&nbsp;<a href="/dpb/submission/${r.ack_number}" target="_blank">View DPB Acknowledgement (${r.ack_number})</a>`;
      submittedReportsBox.appendChild(div);
    });
  });
}

if (alertFeed && !window.SUSPICIOUS) {
  const ICONS = {
    critical: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  };
  function renderAlert(a) {
    const div = document.createElement("div");
    div.className = "alert-item alert-" + a.level;
    const t = new Date(a.timestamp * 1000).toLocaleTimeString();
    div.innerHTML = `<span class="alert-ico">${ICONS[a.level] || ICONS.info}</span>
      <span class="alert-body"><span class="alert-time">${t}</span> ${a.message}</span>`;
    alertFeed.prepend(div);
    if (a.message.includes("submitted to the Data Protection Board")) {
      renderSubmittedReports();
    }
  }

  fetch("/api/alerts").then(r => r.json()).then(list => {
    list.forEach(renderAlert);
    // /api/alerts returns newest-first; reverse for chronological chart init
    initThreatChart(list.slice().reverse());
  });
  renderSubmittedReports();

  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/alerts`);
  ws.onmessage = (evt) => {
    const a = JSON.parse(evt.data);
    renderAlert(a);
    pushThreatPoint(a);
    pushNotifPanelItem(a);
    bumpNotifBadge();
    const securityTab = document.getElementById("tab-security");
    const dot = document.getElementById("alertDot");
    if (dot && securityTab && securityTab.classList.contains("hidden")) {
      dot.classList.add("show");
    }
  };
}
