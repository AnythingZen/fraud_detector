const API = "http://localhost:8000";

let allRows = [];
let currentFilter = "all";

// ============================================================
// Each function talks to a different backend endpoint.
// ============================================================

async function fetchSignups() {
  // GET /signups → returns an array of scored user objects
  //
  // Steps:
  //   1. const res = await fetch(`${API}/signups`)
  //   2. if (!res.ok) throw new Error(`HTTP ${res.status}`)
  //   3. return await res.json()
  throw new Error("fetchSignups not implemented");
}

async function fetchStats() {
  // GET /stats → returns { total, flagged, blocked, fraud_rate }
  //
  // Same 3-step pattern as fetchSignups, different URL.
  throw new Error("fetchStats not implemented");
}

async function reviewUser(userId, decision) {
  // POST /review/{userId} with body { decision: "block" | "approve" }
  //
  // Steps:
  //   1. const res = await fetch(`${API}/review/${userId}`, {
  //        method: "POST",
  //        headers: { "Content-Type": "application/json" },
  //        body: JSON.stringify({ decision })
  //      })
  //   2. if (!res.ok) throw new Error(`HTTP ${res.status}`)
  //   (no return value needed — caller just awaits it)
  throw new Error("reviewUser not implemented");
}

async function explainUser(userId) {
  // POST /agent/explain/{userId} → returns { explanation: "..." }
  //
  // Same POST shape as reviewUser but:
  //   - different URL
  //   - no body needed
  //   - return await res.json()
  throw new Error("explainUser not implemented");
}

// ============================================================
// Rendering helpers (written for you — read through these)
// ============================================================

function scoreClass(score) {
  const n = parseInt(score) || 0;
  if (n >= 4) return "score-high";
  if (n >= 2) return "score-2";
  if (n === 1) return "score-1";
  return "score-0";
}

function renderStats(stats) {
  document.querySelector("#stat-total .value").textContent = stats.total;
  document.querySelector("#stat-flagged .value").textContent = stats.flagged;
  document.querySelector("#stat-blocked .value").textContent = stats.blocked;
  document.querySelector("#stat-fraud-rate .value").textContent =
    (stats.fraud_rate * 100).toFixed(1) + "%";
}

function renderTable(rows) {
  const filtered = currentFilter === "all"
    ? rows
    : rows.filter(r => r.status === currentFilter);

  const tbody = document.getElementById("table-body");

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="loading">No rows match this filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(row => {
    const uid = row["User ID"] ?? "";
    const email = (row.email ?? "—").replace(/'/g, "\\'");
    return `
      <tr>
        <td>${row.email ?? "—"}</td>
        <td>${row["IP Address"] ?? "—"}</td>
        <td>${row.Country ?? "—"}</td>
        <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${row["OS Name and Version"] ?? ""}">${row["OS Name and Version"] ?? "—"}</td>
        <td><span class="score ${scoreClass(row.score)}">${row.score}</span></td>
        <td><span class="badge badge-${row.status}">${row.status}</span></td>
        <td>
          <div class="actions">
            <button class="btn btn-block"
              onclick="handleReview('${uid}', 'block', this)">Block</button>
            <button class="btn btn-approve"
              onclick="handleReview('${uid}', 'approve', this)">Approve</button>
            <button class="btn btn-explain"
              onclick="handleExplain('${uid}', '${email}', ${JSON.stringify(row.triggers ?? [])})">Explain</button>
          </div>
        </td>
      </tr>`;
  }).join("");
}

// ============================================================
// Event handlers (written for you)
// ============================================================

async function handleReview(userId, decision, btn) {
  btn.disabled = true;
  try {
    await reviewUser(userId, decision);
    // Disable both block + approve for this row to signal decision saved
    const tr = btn.closest("tr");
    tr.querySelectorAll(".btn-block, .btn-approve").forEach(b => b.disabled = true);
  } catch (e) {
    alert("Failed to save decision: " + e.message);
    btn.disabled = false;
  }
}

async function handleExplain(userId, email, triggers) {
  const panel   = document.getElementById("explain-panel");
  const content = document.getElementById("panel-content");

  panel.classList.remove("hidden");
  content.innerHTML = `
    <div class="panel-meta">User: <strong>${email}</strong></div>
    <p class="panel-loading">Asking Gemini...</p>`;

  try {
    const data = await explainUser(userId);
    const triggerTags = triggers.length
      ? triggers.map(t => `<span class="trigger-tag">${t}</span>`).join("")
      : "<em>none</em>";

    content.innerHTML = `
      <div class="panel-meta">User: <strong>${email}</strong></div>
      <p class="panel-explanation">${data.explanation}</p>
      <div class="triggers-section">
        <h4>Triggered Rules</h4>
        ${triggerTags}
      </div>`;
  } catch (e) {
    content.innerHTML = `<p style="color:#ef4444">Error: ${e.message}</p>`;
  }
}

// Filter buttons
document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    currentFilter = btn.dataset.filter;
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    renderTable(allRows);
  });
});

// Close side panel
document.getElementById("close-panel").addEventListener("click", () => {
  document.getElementById("explain-panel").classList.add("hidden");
});

// ============================================================
// Boot
// ============================================================

async function init() {
  try {
    // Fire both requests in parallel — no reason to wait on one before the other
    const [stats, signups] = await Promise.all([fetchStats(), fetchSignups()]);
    allRows = signups;
    renderStats(stats);
    renderTable(allRows);
  } catch (e) {
    document.getElementById("table-body").innerHTML =
      `<tr><td colspan="7" class="loading" style="color:#ef4444">
        Backend unreachable — is uvicorn running?<br><small>${e.message}</small>
      </td></tr>`;
  }
}

init();
