// ============================================================
// IoV Wi-Fi Security Testing Platform - frontend controller
// ============================================================

const socket = io();
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ---- connection status ----------------------------------------------------
socket.on("connect", () => {
  $("#conn-dot").classList.add("ok");
  $("#conn-text").textContent = "connected";
});
socket.on("disconnect", () => {
  $("#conn-dot").classList.remove("ok");
  $("#conn-text").textContent = "disconnected";
});

// ---- tabs -----------------------------------------------------------------
$$(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach(b => b.classList.remove("active"));
    $$(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    $("#tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ---- load interfaces into dropdown ----------------------------------------
async function loadInterfaces() {
  try {
    const r = await fetch("/api/interfaces");
    const d = await r.json();
    const sel = $("#scan-iface");
    sel.innerHTML = "";
    d.interfaces.forEach(i => {
      const o = document.createElement("option");
      o.value = i; o.textContent = i;
      sel.appendChild(o);
    });
  } catch (e) { console.error(e); }
}
loadInterfaces();

// ---- SCAN -----------------------------------------------------------------
$("#scan-btn").addEventListener("click", async () => {
  const iface = $("#scan-iface").value;
  const duration = parseInt($("#scan-duration").value, 10);
  const tbody = $("#scan-tbody");
  tbody.innerHTML = `<tr><td colspan="8" class="empty">Scanning on ${iface}…</td></tr>`;
  try {
    const r = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ interface: iface, duration }),
    });
    const d = await r.json();
    if (!d.ok) throw new Error(d.error);
    renderScan(d.networks);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">Error: ${e.message}</td></tr>`;
  }
});

function renderScan(nets) {
  const tbody = $("#scan-tbody");
  if (!nets.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">No networks found.</td></tr>`;
    return;
  }
  tbody.innerHTML = nets.map(n => `
    <tr>
      <td><code>${n.bssid}</code></td>
      <td>${escapeHtml(n.ssid || "<hidden>")}</td>
      <td>${n.channel ?? "-"}</td>
      <td>${n.signal ?? "-"}</td>
      <td><span class="chip ${encChip(n.encryption)}">${n.encryption}</span></td>
      <td>${n.wps ? '<span class="chip fail">ON</span>' : '<span class="chip ok">off</span>'}</td>
      <td>${pmfChip(n.pmf)}</td>
      <td>
        <button data-bssid="${n.bssid}" data-ch="${n.channel}" class="use-btn">Use</button>
      </td>
    </tr>`).join("");
  $$(".use-btn").forEach(b => b.addEventListener("click", () => {
    const params = new URLSearchParams({
      bssid: b.dataset.bssid,
      iface: $("#scan-iface").value,
    });
    if (b.dataset.ch && b.dataset.ch !== "null") params.set("channel", b.dataset.ch);
    window.location.href = `/flow?${params.toString()}`;
  }));
}
function encChip(e) {
  if (e === "WPA3" || e === "WPA2-Enterprise") return "ok";
  if (e === "OPEN" || e === "WPA") return "fail";
  return "warn";
}
function pmfChip(p) {
  if (p === "required") return '<span class="chip ok">required</span>';
  if (p === "capable")  return '<span class="chip warn">capable</span>';
  return '<span class="chip fail">none</span>';
}

// ---- AUDIT ----------------------------------------------------------------
$("#audit-btn").addEventListener("click", async () => {
  const bssid = $("#audit-bssid").value.trim();
  if (!bssid) return alert("Enter BSSID");
  const box = $("#audit-result");
  box.innerHTML = `<p class="empty">Auditing ${bssid}…</p>`;
  const r = await fetch("/api/audit", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ bssid, interface: $("#scan-iface").value }),
  });
  const d = await r.json();
  if (!d.ok) { box.innerHTML = `<p class="empty">Error: ${d.error}</p>`; return; }
  renderAudit(d.report);
});

function renderAudit(rep) {
  if (!rep.target_found) {
    $("#audit-result").innerHTML = `<p class="empty">${rep.summary}</p>`;
    return;
  }
  const rows = rep.checks.map(c => `
    <div class="check">
      <div>
        <div class="name">${c.name}</div>
        <div class="detail">${escapeHtml(c.detail)}</div>
      </div>
      <span class="chip ${statusChip(c.status)}">${c.status}</span>
    </div>`).join("");
  $("#audit-result").innerHTML = `
    <h3 style="margin-top:0">Audit for <code>${rep.bssid}</code></h3>
    <p style="color:var(--muted)">${rep.summary}</p>
    ${rows}`;
}
function statusChip(s) {
  return ({ PASS: "ok", FAIL: "fail", WARN: "warn",
            INFO: "info", MANUAL: "info" })[s] || "info";
}

// ---- ATTACK ---------------------------------------------------------------
let currentJob = null;

$("#atk-start").addEventListener("click", async () => {
  const scenario = $("#scenario-select").value;
  const params = {
    interface: $("#atk-iface").value,
    bssid: $("#atk-bssid").value,
    channel: $("#atk-channel").value,
  };
  const extra = $("#atk-extra").value.trim();
  if (extra) {
    try { Object.assign(params, JSON.parse(extra)); }
    catch { return alert("Extra params must be valid JSON"); }
  }
  const r = await fetch("/api/attack/start", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ scenario, params }),
  });
  const d = await r.json();
  if (!d.ok) return alert("Start failed: " + d.error);
  currentJob = d.job_id;
  $("#current-job").textContent = "job " + currentJob;
  $("#atk-output").textContent = "";
});

$("#atk-stop").addEventListener("click", async () => {
  if (!currentJob) return;
  await fetch("/api/attack/stop", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ job_id: currentJob }),
  });
});

socket.on("job_output", (msg) => {
  if (msg.job_id !== currentJob) return;
  const box = $("#atk-output");
  box.textContent += msg.line + "\n";
  box.scrollTop = box.scrollHeight;
});
socket.on("job_update", (job) => {
  if (job.job_id !== currentJob) return;
  $("#current-job").textContent = `job ${job.job_id} · ${job.status}`;
});

// ---- WIDS -----------------------------------------------------------------
$("#wids-start").addEventListener("click", async () => {
  await fetch("/api/wids/start", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ interface: $("#wids-iface").value }),
  });
});
$("#wids-stop").addEventListener("click", async () => {
  await fetch("/api/wids/stop", { method: "POST" });
});

socket.on("wids_event", (evt) => {
  const box = $("#wids-events");
  const ts = new Date(evt.ts * 1000).toLocaleTimeString();
  const row = document.createElement("div");
  row.className = "event";
  row.innerHTML = `
    <span class="ts">${ts}</span>
    <span class="type">${evt.type}</span>
    <span class="sev-${evt.severity}">${evt.severity.toUpperCase()}</span>
    <span>${escapeHtml(evt.message)}</span>`;
  box.prepend(row);
  while (box.children.length > 200) box.removeChild(box.lastChild);
});

// ---- LOGS -----------------------------------------------------------------
$("#logs-refresh").addEventListener("click", loadLogs);
async function loadLogs() {
  const r = await fetch("/api/logs?limit=300");
  const d = await r.json();
  $("#logs-box").textContent = d.logs.map(l =>
    `[${new Date(l.ts*1000).toLocaleTimeString()}] ${l.level} ${l.category}: ${l.message}`
  ).join("\n") || "(empty)";
}
loadLogs();

// ---- util -----------------------------------------------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  }[c]));
}
