// ============================================================
// IoV Wi-Fi Security Testing — Flow / Pipeline controller
// Runs Scan → Audit → Attack → WIDS sequentially with live UI.
// ============================================================

const socket = io();
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => r.querySelectorAll(s);

// ---- connection status ----------------------------------------------------
socket.on("connect", () => {
  $("#conn-dot").classList.add("ok");
  $("#conn-text").textContent = "connected";
});
socket.on("disconnect", () => {
  $("#conn-dot").classList.remove("ok");
  $("#conn-text").textContent = "disconnected";
});

// ---- stage definitions ----------------------------------------------------
const STAGES = [
  { id: "scan",   icon: "📡", title: "Scan",         desc: "Discover nearby access points",       run: runScan },
  { id: "audit",  icon: "🛡️", title: "Config Audit",  desc: "WPS · WPA3 · PMF · SSID checks",       run: runAudit },
  { id: "attack", icon: "⚔️", title: "Attack",        desc: "Run selected exploit scenario",        run: runAttack },
  { id: "wids",   icon: "📶", title: "WIDS",          desc: "Watch for intrusion events",           run: runWids },
];

// shared state passed between stages
const ctx = { iface: "wlan0", scenario: "pmf_probe", bssid: "", networks: [] };

let running = false;

// ---- build the pipeline DOM ----------------------------------------------
function buildPipeline() {
  const wrap = $("#pipeline");
  wrap.innerHTML = "";
  STAGES.forEach((st, i) => {
    const col = document.createElement("div");
    col.className = "card-col";
    col.innerHTML = `
      <div class="card" id="card-${st.id}" data-state="pending">
        <span class="num">0${i + 1}</span>
        <span class="stage-icon">${st.icon}</span>
        <h3>${st.title}</h3>
        <p class="desc">${st.desc}</p>
        <div class="badge"><span class="spin"></span><span class="btxt">pending</span></div>
        <div class="result"></div>
      </div>
      <div class="err-panel" id="err-${st.id}"></div>`;
    wrap.appendChild(col);

    if (i < STAGES.length - 1) {
      const c = document.createElement("div");
      c.className = "connector";
      c.id = `conn-${i}`;
      c.innerHTML = `<span class="head"></span>`;
      wrap.appendChild(c);
    }
  });
}

// ---- card state helpers ---------------------------------------------------
function setState(id, state, badgeText) {
  const card = $(`#card-${id}`);
  card.dataset.state = state;
  if (badgeText) $(".btxt", card).textContent = badgeText;
}
function setResult(id, text) { $(`#card-${id} .result`).textContent = text || ""; }

function showError(id, title, body, variant = "fail") {
  const p = $(`#err-${id}`);
  p.className = `err-panel show ${variant === "warn" ? "warn" : ""}`;
  const icon = variant === "warn" ? "⚠" : "✕";
  p.innerHTML = `<div class="err-title">${icon} ${escapeHtml(title)}</div>${body}`;
}
function clearError(id) {
  const p = $(`#err-${id}`);
  p.className = "err-panel";
  p.innerHTML = "";
}

function setConnector(i, cls) {
  const c = $(`#conn-${i}`);
  if (!c) return;
  c.classList.remove("flowing", "done");
  if (cls) c.classList.add(cls);
}

// ---- progress + dock status ----------------------------------------------
function setProgress(pct, variant) {
  const fill = $("#progress-fill");
  fill.style.width = pct + "%";
  fill.classList.toggle("idle", pct === 0 && !variant);
  fill.classList.toggle("done", variant === "done");
  fill.classList.toggle("failed", variant === "failed");
  $("#progress-label").textContent = Math.round(pct) + "%";
}
function setDockStat(text, cls) {
  const el = $("#dock-stat");
  el.textContent = text;
  el.className = "dock-stat" + (cls ? " " + cls : "");
}

// ---- logs -----------------------------------------------------------------
let logCount = 0;
function log(message, level = "log") {
  const stream = $("#logstream");
  const empty = $(".log-empty", stream);
  if (empty) empty.remove();
  const ts = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.className = `log-line lv-${level}`;
  line.innerHTML =
    `<span class="lt">${ts}</span>` +
    `<span class="lc">${level}</span>` +
    `<span class="lm">${escapeHtml(message)}</span>`;
  stream.appendChild(line);
  stream.scrollTop = stream.scrollHeight;
  logCount++;
  $("#log-count").textContent = `${logCount} line${logCount === 1 ? "" : "s"}`;
}

// ===========================================================================
//  STAGE IMPLEMENTATIONS  — each returns { ok, warn?, summary, errBody? }
// ===========================================================================

async function runScan() {
  log(`Scanning on ${ctx.iface} …`, "info");
  const d = await postJSON("/api/scan", { interface: ctx.iface, duration: 8 });
  if (!d.ok) return { ok: false, summary: "scan failed", errBody: `<pre>${escapeHtml(d.error || "unknown error")}</pre>` };

  ctx.networks = d.networks || [];
  log(`Found ${ctx.networks.length} network(s).`, "ok");
  ctx.networks.slice(0, 6).forEach(n =>
    log(`  ${n.bssid}  ${n.ssid || "<hidden>"}  ch${n.channel ?? "?"}  ${n.encryption}`, "log"));

  if (!ctx.networks.length)
    return { ok: false, summary: "no networks", errBody: `<pre>No access points discovered on ${ctx.iface}.</pre>` };

  // auto-pick target if none supplied
  if (!ctx.bssid) {
    ctx.bssid = ctx.networks[0].bssid;
    ctx.channel = ctx.networks[0].channel;
    log(`Auto-selected target ${ctx.bssid}.`, "info");
  }
  return { ok: true, summary: `${ctx.networks.length} APs · target ${ctx.bssid}` };
}

async function runAudit() {
  log(`Auditing ${ctx.bssid} …`, "info");
  const d = await postJSON("/api/audit", { bssid: ctx.bssid, interface: ctx.iface });
  if (!d.ok) return { ok: false, summary: "audit error", errBody: `<pre>${escapeHtml(d.error || "unknown error")}</pre>` };

  const rep = d.report;
  if (!rep.target_found)
    return { ok: false, summary: "target not found", errBody: `<pre>${escapeHtml(rep.summary)}</pre>` };

  const checks = rep.checks || [];
  const fails = checks.filter(c => c.status === "FAIL");
  const warns = checks.filter(c => c.status === "WARN");
  checks.forEach(c => log(`  [${c.status}] ${c.name} — ${c.detail}`,
    c.status === "FAIL" ? "fail" : c.status === "WARN" ? "warn" : c.status === "PASS" ? "ok" : "log"));

  // findings are reported but do NOT abort the pipeline
  if (fails.length || warns.length) {
    const rows = [...fails, ...warns].map(c =>
      `<div class="det"><span class="dn">${escapeHtml(c.name)}: ${escapeHtml(c.detail)}</span>` +
      `<span class="chip ${c.status === "FAIL" ? "fail" : "warn"}">${c.status}</span></div>`).join("");
    return {
      ok: true, warn: true,
      summary: `${fails.length} fail · ${warns.length} warn`,
      errBody: rows,
      errTitle: `${fails.length} security finding(s)`,
    };
  }
  return { ok: true, summary: `all ${checks.length} checks passed` };
}

function runAttack() {
  return new Promise(async (resolve) => {
    const scen = ctx.scenario;
    log(`Launching attack scenario "${scen}" on ${ctx.bssid} …`, "info");
    const params = { interface: ctx.iface, bssid: ctx.bssid, channel: ctx.channel || 6 };
    const d = await postJSON("/api/attack/start", { scenario: scen, params });
    if (!d.ok) return resolve({ ok: false, summary: "launch failed", errBody: `<pre>${escapeHtml(d.error || "unknown error")}</pre>` });

    const jobId = d.job_id;
    log(`Job ${jobId} started.`, "info");
    setResult("attack", `job ${jobId} · running`);

    let lines = 0;
    const onOut = (m) => { if (m.job_id === jobId) { log(m.line, "log"); lines++; } };
    const onUpd = (j) => {
      if (j.job_id !== jobId) return;
      if (j.status === "finished" || j.status === "error" || j.status === "killed") {
        socket.off("job_output", onOut);
        socket.off("job_update", onUpd);
        const ok = j.status === "finished";
        log(`Job ${jobId} ${j.status} (rc=${j.return_code}).`, ok ? "ok" : "fail");
        resolve(ok
          ? { ok: true, summary: `job ${jobId} · ${lines} lines` }
          : { ok: false, summary: `job ${j.status}`, errBody: `<pre>Scenario exited with status "${j.status}" (return code ${j.return_code}).</pre>` });
      }
    };
    socket.on("job_output", onOut);
    socket.on("job_update", onUpd);

    // safety timeout so the pipeline never hangs forever
    setTimeout(() => {
      socket.off("job_output", onOut);
      socket.off("job_update", onUpd);
      resolve({ ok: true, summary: `job ${jobId} · streamed ${lines} lines` });
    }, 30000);
  });
}

function runWids() {
  return new Promise(async (resolve) => {
    const WINDOW_MS = 7000;
    log(`Starting WIDS monitor on ${ctx.iface} for ${WINDOW_MS / 1000}s …`, "info");
    const d = await postJSON("/api/wids/start", { interface: ctx.iface });
    if (!d.ok) return resolve({ ok: false, summary: "WIDS start failed", errBody: `<pre>could not start monitor</pre>` });

    let events = 0, high = 0;
    const onEvt = (e) => {
      events++;
      if (e.severity === "high") high++;
      const lvl = e.severity === "high" ? "fail" : e.severity === "medium" ? "warn" : "info";
      log(`  [${e.severity.toUpperCase()}] ${e.type} — ${e.message}`, lvl);
    };
    socket.on("wids_event", onEvt);

    setTimeout(async () => {
      socket.off("wids_event", onEvt);
      await postJSON("/api/wids/stop", {});
      log(`WIDS stopped. ${events} event(s), ${high} high-severity.`, high ? "warn" : "ok");
      if (high)
        resolve({ ok: true, warn: true, summary: `${events} events · ${high} high`,
                  errTitle: `${high} high-severity intrusion event(s)`,
                  errBody: `<pre>${high} high-severity event(s) detected during the ${WINDOW_MS / 1000}s window. Review the log for details.</pre>` });
      else
        resolve({ ok: true, summary: `${events} events · clean` });
    }, WINDOW_MS);
  });
}

// ===========================================================================
//  PIPELINE DRIVER
// ===========================================================================

async function runPipeline() {
  if (running) return;
  running = true;
  resetUI(false);

  // pull config
  ctx.iface = $("#cfg-iface").value || "wlan0";
  ctx.scenario = $("#cfg-scenario").value;
  ctx.bssid = $("#cfg-bssid").value.trim();
  ctx.networks = [];

  $("#run-btn").disabled = true;
  $("#reset-btn").disabled = true;
  setDockStat("running", "running");
  $(".dock").classList.remove("collapsed");
  log("════ Pipeline started ════", "info");

  let failed = false;

  for (let i = 0; i < STAGES.length; i++) {
    const st = STAGES[i];
    setState(st.id, "running", "running");
    setProgress((i / STAGES.length) * 100);
    if (i > 0) setConnector(i - 1, "done");
    setConnector(i, "flowing");

    let res;
    try {
      res = await st.run();
    } catch (e) {
      res = { ok: false, summary: "exception", errBody: `<pre>${escapeHtml(e.message || String(e))}</pre>` };
    }

    if (res.ok) {
      if (res.warn) {
        setState(st.id, "warn", "passed ⚠");
        showError(st.id, res.errTitle || "Findings", res.errBody || "", "warn");
      } else {
        setState(st.id, "passed", "passed");
      }
      setResult(st.id, res.summary || "");
    } else {
      setState(st.id, "failed", "failed");
      setResult(st.id, res.summary || "failed");
      showError(st.id, res.errTitle || "Stage failed", res.errBody || "<pre>unknown error</pre>");
      log(`Stage "${st.title}" failed — aborting pipeline.`, "fail");
      setConnector(i, null);
      failed = true;
      break;
    }
  }

  if (failed) {
    setProgress(100, "failed");
    setDockStat("failed", "failed");
    log("════ Pipeline aborted ════", "fail");
  } else {
    setConnector(STAGES.length - 2, "done");
    setProgress(100, "done");
    setDockStat("complete", "done");
    log("════ Pipeline complete ════", "ok");
  }

  $("#run-btn").disabled = false;
  $("#reset-btn").disabled = false;
  running = false;
}

// ---- reset ----------------------------------------------------------------
function resetUI(full = true) {
  STAGES.forEach((st, i) => {
    setState(st.id, "pending", "pending");
    setResult(st.id, "");
    clearError(st.id);
    if (i < STAGES.length - 1) setConnector(i, null);
  });
  setProgress(0);
  setDockStat("idle");
  if (full) {
    $("#logstream").innerHTML = `<div class="log-empty">No activity yet — press <b>Run Pipeline</b> to begin.</div>`;
    logCount = 0;
    $("#log-count").textContent = "0 lines";
  }
}

// ---- helpers --------------------------------------------------------------
async function postJSON(url, body) {
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return await r.json();
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

async function loadInterfaces() {
  try {
    const r = await fetch("/api/interfaces");
    const d = await r.json();
    const sel = $("#cfg-iface");
    if (d.interfaces && d.interfaces.length) {
      sel.innerHTML = "";
      d.interfaces.forEach(i => {
        const o = document.createElement("option");
        o.value = i; o.textContent = i;
        sel.appendChild(o);
      });
    }
  } catch (e) { /* keep default */ }
}

// ---- wire up --------------------------------------------------------------
buildPipeline();
loadInterfaces();
$("#run-btn").addEventListener("click", runPipeline);
$("#reset-btn").addEventListener("click", () => resetUI(true));
$("#log-clear").addEventListener("click", () => {
  $("#logstream").innerHTML = `<div class="log-empty">cleared.</div>`;
  logCount = 0; $("#log-count").textContent = "0 lines";
});
$("#dock-head").addEventListener("click", () => $(".dock").classList.toggle("collapsed"));
