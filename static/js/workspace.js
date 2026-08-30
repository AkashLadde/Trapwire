// ===================================================================
// Workspace extension JS — Projects, Leaderboard, Administration,
// Library, Maps, Support tabs. Purely front-end (localStorage-backed);
// none of this touches the Orders/Security data model or backend.
// ===================================================================

function showToast(message) {
  const toast = document.getElementById("workspaceToast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.add("hidden"), 3200);
}

function openModal(id) { document.getElementById(id)?.classList.remove("hidden"); }
function closeModal(id) { document.getElementById(id)?.classList.add("hidden"); }

// ---------------------------------------------------------------
// PROJECTS TAB
// ---------------------------------------------------------------
const FINANCE_LABELS = ["Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "Jan", "Feb", "Mar"];
const FINANCE_ACTUAL = [42, 46, 44, 51, 55, 58, null, null, null, null, null, null]; // in lakhs, actuals so far
const FINANCE_PROJECTED = [null, null, null, null, null, 58, 63, 67, 72, 76, 81, 88];

let financeChart = null;
function initFinanceChart() {
  const canvas = document.getElementById("financeChart");
  if (!canvas || typeof Chart === "undefined") return;
  financeChart = new Chart(canvas.getContext("2d"), {
    type: "line",
    data: {
      labels: FINANCE_LABELS,
      datasets: [
        {
          label: "Actual Revenue (₹L)",
          data: FINANCE_ACTUAL,
          borderColor: "#0F6CBD",
          backgroundColor: "rgba(15,108,189,0.10)",
          fill: true, tension: 0.35, pointRadius: 3, pointBackgroundColor: "#0F6CBD",
        },
        {
          label: "Projected Revenue (₹L)",
          data: FINANCE_PROJECTED,
          borderColor: "#D97706",
          backgroundColor: "rgba(217,119,6,0.08)",
          borderDash: [6, 4],
          fill: true, tension: 0.35, pointRadius: 3, pointBackgroundColor: "#D97706",
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
      scales: {
        x: { ticks: { font: { family: "JetBrains Mono", size: 10 } } },
        y: { beginAtZero: false, ticks: { callback: (v) => "₹" + v + "L" } },
      },
    },
  });
}

function loadCustomProjects() {
  try { return JSON.parse(localStorage.getItem("trapwire_custom_projects") || "[]"); }
  catch (e) { return []; }
}
function saveCustomProjects(list) {
  localStorage.setItem("trapwire_custom_projects", JSON.stringify(list));
}

function projectRowHtml(p) {
  const initial = (p.owner || "?").trim()[0]?.toUpperCase() || "?";
  const budgetFmt = "₹" + Number(p.budget).toLocaleString("en-IN");
  return `<tr data-custom="1">
    <td><b>${p.name}</b></td><td>${p.client}</td>
    <td><div class="cust-cell"><span class="cust-avatar">${initial}</span>${p.owner}</div></td>
    <td class="mono">${p.deadline}</td><td class="mono">${budgetFmt}</td>
    <td><div class="progress-track"><div class="progress-fill" style="width:5%;"></div></div></td>
    <td><span class="status-pill status-pending">Planning</span></td>
  </tr>`;
}

function renderCustomProjects() {
  const tbody = document.getElementById("projectsTableBody");
  if (!tbody) return;
  tbody.querySelectorAll('tr[data-custom="1"]').forEach((r) => r.remove());
  loadCustomProjects().forEach((p) => tbody.insertAdjacentHTML("beforeend", projectRowHtml(p)));
  const total = tbody.querySelectorAll("tr").length;
  const countEl = document.getElementById("projTableCount");
  if (countEl) countEl.textContent = `${total} project${total === 1 ? "" : "s"}`;
  const activeEl = document.getElementById("statActiveProjects");
  if (activeEl) activeEl.textContent = String(6 + loadCustomProjects().length);
}

function addProjectNotification(text) {
  const feed = document.getElementById("projectNotifFeed");
  if (!feed) return;
  const row = document.createElement("div");
  row.className = "notif-row";
  row.innerHTML = `<span class="notif-dot dot-indigo"></span>
    <div><b>New project created</b><p>${text}</p><span class="notif-when">Just now</span></div>`;
  feed.prepend(row);
  const countEl = document.getElementById("projNotifCount");
  if (countEl) countEl.textContent = (parseInt(countEl.textContent, 10) + 1) + " new";
}

document.getElementById("newProjectBtn")?.addEventListener("click", () => openModal("newProjectModal"));
document.getElementById("closeProjectModal")?.addEventListener("click", () => closeModal("newProjectModal"));
document.getElementById("newProjectForm")?.addEventListener("submit", (e) => {
  e.preventDefault();
  const p = {
    name: document.getElementById("npName").value.trim(),
    client: document.getElementById("npClient").value.trim(),
    owner: document.getElementById("npOwner").value.trim(),
    deadline: document.getElementById("npDeadline").value,
    budget: document.getElementById("npBudget").value,
  };
  if (!p.name || !p.client || !p.owner || !p.deadline || !p.budget) return;
  const list = loadCustomProjects();
  list.push(p);
  saveCustomProjects(list);
  renderCustomProjects();
  addProjectNotification(`"${p.name}" for ${p.client}, owned by ${p.owner}.`);
  e.target.reset();
  closeModal("newProjectModal");
  showToast(`Project "${p.name}" created.`);
});

// ---------------------------------------------------------------
// LEADERBOARD TAB (decorative period filter)
// ---------------------------------------------------------------
document.querySelectorAll("#lbChips .filter-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    document.querySelectorAll("#lbChips .filter-chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
  });
});

// ---------------------------------------------------------------
// ADMINISTRATION TAB
// ---------------------------------------------------------------
function loadCustomUsers() {
  try { return JSON.parse(localStorage.getItem("trapwire_custom_users") || "[]"); }
  catch (e) { return []; }
}
function saveCustomUsers(list) { localStorage.setItem("trapwire_custom_users", JSON.stringify(list)); }

function userRowHtml(u) {
  const initial = (u.name || "?").trim()[0]?.toUpperCase() || "?";
  return `<tr data-custom="1">
    <td><div class="cust-cell"><span class="cust-avatar">${initial}</span>${u.name}</div></td>
    <td class="mono">${u.email}</td><td>${u.role}</td>
    <td><span class="status-pill status-processing">Invited</span></td><td class="mono">—</td>
  </tr>`;
}

function renderCustomUsers() {
  const tbody = document.getElementById("adminUsersTableBody");
  if (!tbody) return;
  tbody.querySelectorAll('tr[data-custom="1"]').forEach((r) => r.remove());
  loadCustomUsers().forEach((u) => tbody.insertAdjacentHTML("beforeend", userRowHtml(u)));
  const total = tbody.querySelectorAll("tr").length;
  const countEl = document.getElementById("adminTableCount");
  if (countEl) countEl.textContent = `${total} user${total === 1 ? "" : "s"}`;
  const totalUsersEl = document.getElementById("statTotalUsers");
  if (totalUsersEl) totalUsersEl.textContent = String(6 + loadCustomUsers().length);
}

document.getElementById("inviteUserBtn")?.addEventListener("click", () => openModal("inviteUserModal"));
document.getElementById("closeInviteModal")?.addEventListener("click", () => closeModal("inviteUserModal"));
document.getElementById("inviteUserForm")?.addEventListener("submit", (e) => {
  e.preventDefault();
  const u = {
    name: document.getElementById("iuName").value.trim(),
    email: document.getElementById("iuEmail").value.trim(),
    role: document.getElementById("iuRole").value,
  };
  if (!u.name || !u.email) return;
  const list = loadCustomUsers();
  list.push(u);
  saveCustomUsers(list);
  renderCustomUsers();
  e.target.reset();
  closeModal("inviteUserModal");
  showToast(`Invitation sent to ${u.name}.`);
});

// ---------------------------------------------------------------
// LIBRARY TAB
// ---------------------------------------------------------------
const LIBRARY_DOCS = [
  { title: "Data Protection & Privacy Policy", cat: "Policy", type: "pdf", size: "412 KB", updated: "12 Aug 2026" },
  { title: "Incident Response Playbook", cat: "Policy", type: "pdf", size: "780 KB", updated: "03 Aug 2026" },
  { title: "New Project Charter Template", cat: "Template", type: "docx", size: "58 KB", updated: "20 Jul 2026" },
  { title: "Weekly Status Report Template", cat: "Template", type: "xlsx", size: "34 KB", updated: "01 Aug 2026" },
  { title: "Q2 FY26 Financial Report", cat: "Report", type: "xlsx", size: "1.1 MB", updated: "15 Jul 2026" },
  { title: "DPDP Compliance Audit Report", cat: "Report", type: "pdf", size: "960 KB", updated: "28 Aug 2026" },
  { title: "Security Awareness Training Deck", cat: "Training", type: "ppt", size: "3.2 MB", updated: "10 Jun 2026" },
  { title: "New Hire Onboarding Guide", cat: "Training", type: "pdf", size: "540 KB", updated: "22 May 2026" },
  { title: "Client Proposal Template", cat: "Template", type: "docx", size: "76 KB", updated: "05 Aug 2026" },
  { title: "Vendor Code of Conduct", cat: "Policy", type: "pdf", size: "300 KB", updated: "18 Apr 2026" },
];

function docCardHtml(d) {
  return `<div class="doc-card" data-cat="${d.cat}" data-search="${d.title.toLowerCase()}">
    <div class="doc-icon ${d.type}">${d.type.toUpperCase()}</div>
    <div class="doc-cat-tag">${d.cat}</div>
    <div class="doc-title">${d.title}</div>
    <div class="doc-meta">${d.size} · Updated ${d.updated}</div>
    <div class="doc-foot"><a href="#" onclick="event.preventDefault(); showToast('Demo file — nothing to download.');">Download</a></div>
  </div>`;
}

function renderLibrary() {
  const grid = document.getElementById("docGrid");
  if (!grid) return;
  grid.innerHTML = LIBRARY_DOCS.map(docCardHtml).join("");
}
renderLibrary();

document.querySelectorAll("#libChips .filter-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    document.querySelectorAll("#libChips .filter-chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    applyLibraryFilter();
  });
});
document.getElementById("libSearch")?.addEventListener("input", applyLibraryFilter);

function applyLibraryFilter() {
  const activeCat = document.querySelector("#libChips .filter-chip.active")?.dataset.cat || "all";
  const q = (document.getElementById("libSearch")?.value || "").trim().toLowerCase();
  document.querySelectorAll("#docGrid .doc-card").forEach((card) => {
    const matchesCat = activeCat === "all" || card.dataset.cat === activeCat;
    const matchesSearch = !q || card.dataset.search.includes(q);
    card.style.display = matchesCat && matchesSearch ? "" : "none";
  });
}

// ---------------------------------------------------------------
// SUPPORT TAB
// ---------------------------------------------------------------
document.getElementById("supportForm")?.addEventListener("submit", (e) => {
  e.preventDefault();
  const msg = document.getElementById("supportMsg");
  const ticketId = "TCK-" + Math.random().toString(36).slice(2, 8).toUpperCase();
  msg.textContent = `Ticket ${ticketId} submitted. Our team will reach out via support@trapwire.co.in or +91 74836 55370.`;
  msg.className = "msg";
  e.target.reset();
  showToast(`Support ticket ${ticketId} created.`);
});

document.querySelectorAll(".faq-q").forEach((btn) => {
  btn.addEventListener("click", () => {
    btn.parentElement.classList.toggle("open");
  });
});

// ---------------------------------------------------------------
// Modal overlay click-outside-to-close
// ---------------------------------------------------------------
document.querySelectorAll(".modal-overlay").forEach((overlay) => {
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.classList.add("hidden");
  });
});

// ---------------------------------------------------------------
// Init on load
// ---------------------------------------------------------------
initFinanceChart();
renderCustomProjects();
renderCustomUsers();
