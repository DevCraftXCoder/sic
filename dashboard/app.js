"use strict";

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch { return iso; }
}

async function fetchJson(url, opts) {
  const r = await fetch(url, Object.assign({ credentials: "include" }, opts || {}));
  if (!r.ok) {
    const err = new Error("HTTP " + r.status);
    err.status = r.status;
    try { err.body = await r.json(); } catch { err.body = null; }
    throw err;
  }
  return r.json();
}

async function authCheck() {
  try {
    return await fetchJson("/auth/me");
  } catch (e) {
    if (e.status === 401) {
      window.location.href = "/dashboard/login.html";
    }
    return null;
  }
}

async function loadStats() {
  const el = document.getElementById("panel-stats");
  try {
    const { scans } = await fetchJson("/api/scans?limit=100");
    const counts = { total: scans.length, completed: 0, failed: 0, running: 0, killed: 0 };
    for (const s of scans) counts[s.status] = (counts[s.status] || 0) + 1;
    el.innerHTML = `
      <div class="sic-stat"><div class="sic-stat__num">${counts.total}</div><div class="sic-stat__label">Total</div></div>
      <div class="sic-stat"><div class="sic-stat__num">${counts.completed}</div><div class="sic-stat__label">Completed</div></div>
      <div class="sic-stat"><div class="sic-stat__num">${counts.failed}</div><div class="sic-stat__label">Failed</div></div>
      <div class="sic-stat"><div class="sic-stat__num">${counts.running}</div><div class="sic-stat__label">Running</div></div>
    `;
  } catch (e) {
    el.innerHTML = `<div class="sic-error">Failed to load stats (${escapeHtml(e.message)})</div>`;
  }
}

async function loadRecent() {
  const el = document.getElementById("panel-recent");
  try {
    const { scans } = await fetchJson("/api/scans?limit=10");
    if (!scans || scans.length === 0) {
      el.innerHTML = `<div class="sic-empty">No scans recorded yet.</div>`;
      return;
    }
    const rows = scans.map(s => `
      <tr>
        <td>${fmtDate(s.started_at)}</td>
        <td>${escapeHtml(s.scan_type)}</td>
        <td>${escapeHtml(s.target || "—")}</td>
        <td><span class="sic-status sic-status--${escapeHtml(s.status)}">${escapeHtml(s.status)}</span></td>
        <td>${s.findings_count || 0}</td>
      </tr>
    `).join("");
    el.innerHTML = `
      <table class="sic-table">
        <thead><tr><th>Started</th><th>Type</th><th>Target</th><th>Status</th><th>Findings</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  } catch (e) {
    el.innerHTML = `<div class="sic-error">Failed to load recent scans (${escapeHtml(e.message)})</div>`;
  }
}

async function loadHealth() {
  const el = document.getElementById("panel-health");
  try {
    const data = await fetchJson("/health");
    el.innerHTML = `<pre class="sic-health">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  } catch (e) {
    el.innerHTML = `<div class="sic-error">Health endpoint unreachable (${escapeHtml(e.message)})</div>`;
  }
}

async function logout() {
  try { await fetch("/auth/logout", { method: "POST", credentials: "include" }); } catch {}
  window.location.href = "/dashboard/login.html";
}

async function initDashboard() {
  const me = await authCheck();
  if (!me) return;
  document.getElementById("user-email").textContent = me.email;
  document.getElementById("logout-btn").addEventListener("click", logout);
  loadStats();
  loadRecent();
  loadHealth();
}

function initLogin() {
  const form = document.getElementById("login-form");
  const msg = document.getElementById("login-msg");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    msg.innerHTML = "";
    const email = form.email.value.trim();
    if (!email) return;
    try {
      const data = await fetchJson("/auth/request-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const expires = data.expires_at ? new Date(data.expires_at * 1000).toLocaleTimeString() : "—";
      let html = `<div class="sic-success">Magic link sent. Expires at ${escapeHtml(expires)}.</div>`;
      if (data.link) {
        html += `<div class="sic-stat__label" style="margin-top:8px">Dev mode link:</div><a class="sic-link" href="${escapeHtml(data.link)}">${escapeHtml(data.link)}</a>`;
      }
      msg.innerHTML = html;
    } catch (e) {
      const reason = (e.body && e.body.error) || e.message;
      msg.innerHTML = `<div class="sic-error">${escapeHtml(reason)}</div>`;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("login-form")) {
    initLogin();
  } else if (document.getElementById("user-email")) {
    initDashboard();
  }
});
