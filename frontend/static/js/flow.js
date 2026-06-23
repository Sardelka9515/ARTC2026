// ============================================================
// IoV Wi-Fi Security Testing — Flow / Pipeline controller
//
// Structure follows the mid-term report §二、研究方法與實施步驟:
//   AP 模式            a. 安全組態檢測   b. 進階防護技術檢測
//   Client/Station 模式 a. 主動防禦與異常偵測(WIDS)  b. 攻擊模擬與驗證
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

// ---- T-BOX operating modes (report's two top-level headings) --------------
const MODES = {
  ap: {
    label: "1. AP 模式",
    desc: "TBOX 作為訊號發射源，驗證所採協定是否合規",
  },
  client: {
    label: "2. Client / Station 模式",
    desc: "TBOX 作為接收端連線外部網路（OTA 更新 / 公共熱點）",
  },
};

// ---- stage definitions (the a./b. sub-items under each mode) ---------------
const STAGES = [
  {
    id: "config", mode: "ap", sub: "a",
    title: "安全組態檢測", en: "Security Configuration Audit",
    items: [
      "禁用不安全連線（WPS）杜絕暴力破解",
      "導入高安全性驗證（WPA3 / 802.1X）",
      "隱藏或管控 SSID 廣播",
    ],
    run: runConfigAudit,
  },
  {
    id: "advanced", mode: "ap", sub: "b",
    title: "進階防護技術檢測", en: "Advanced Protection",
    items: [
      "管理訊框保護（PMF / 802.11w）防偽造斷線",
      "網段安全隔離（Client Isolation）防橫向移動",
    ],
    run: runAdvancedProtection,
  },
  {
    id: "wids", mode: "client", sub: "a",
    title: "主動防禦與異常偵測", en: "Active Defense · WIDS",
    items: [
      "辨識大量重傳 / 非法握手（DoS·破解嘗試）",
      "偵測惡意熱點 / 釣魚熱點，防止誤連",
    ],
    run: runWids,
  },
  {
    id: "attacksim", mode: "client", sub: "b",
    title: "攻擊模擬與驗證", en: "Attack Simulation & Validation",
    items: [
      "模擬 Deauth 解除認證攻擊",
      "架設釣魚熱點（Rogue AP / Evil Twin）",
      "完整事件日誌（Log）儲存與紀錄",
    ],
    run: runAttackSim,
  },
];

// shared state passed between stages
const ctx = { iface: "wlan0", bssid: "", channel: 6, networks: [], report: null };
let running = false;

// ---- build the pipeline DOM (grouped by mode) -----------------------------
function cardHTML(st) {
  return `
    <div class="card" id="card-${st.id}" data-state="pending">
      <span class="num">${st.sub}</span>
      <h3>${st.title}</h3>
      <p class="desc">${st.en}</p>
      <ul class="items">${st.items.map(i => `<li>${i}</li>`).join("")}</ul>
      <div class="badge"><span class="spin"></span><span class="btxt">待測</span></div>
      <div class="result"></div>
    </div>
    <div class="err-panel" id="err-${st.id}"></div>`;
}
function connectorEl(flatIdx, mode = false) {
  const c = document.createElement("div");
  c.className = "connector" + (mode ? " mode-connector" : "");
  c.id = `conn-${flatIdx}`;
  c.innerHTML = `<span class="head"></span>`;
  return c;
}

function buildPipeline() {
  const wrap = $("#pipeline");
  wrap.innerHTML = "";
  const order = ["ap", "client"];
  let flat = 0;

  order.forEach((mode, gi) => {
    const stages = STAGES.filter(s => s.mode === mode);
    const group = document.createElement("div");
    group.className = "mode-group";
    group.dataset.mode = mode;
    const m = MODES[mode];
    group.innerHTML =
      `<div class="mode-band">
         <span class="mode-name">${m.label}</span>
         <span class="mode-desc">${m.desc}</span>
       </div>`;

    const row = document.createElement("div");
    row.className = "mode-cards";
    stages.forEach((st, i) => {
      const col = document.createElement("div");
      col.className = "card-col";
      col.innerHTML = cardHTML(st);
      row.appendChild(col);
      if (i < stages.length - 1) row.appendChild(connectorEl(flat));
      flat++;
    });
    group.appendChild(row);
    wrap.appendChild(group);

    // connector bridging the two modes
    if (gi < order.length - 1) wrap.appendChild(connectorEl(flat - 1, true));
  });
}

// ---- card / connector state helpers ---------------------------------------
function setState(id, state, badgeText) {
  const card = $(`#card-${id}`);
  card.dataset.state = state;
  if (badgeText) $(".btxt", card).textContent = badgeText;
}
function setResult(id, text) { $(`#card-${id} .result`).textContent = text || ""; }

function showError(id, title, body, variant = "fail") {
  const p = $(`#err-${id}`);
  p.className = `err-panel show ${variant === "warn" ? "warn" : ""}`;
  p.innerHTML = `<div class="err-title">${escapeHtml(title)}</div>${body}`;
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
  $("#log-count").textContent = `${logCount} 行`;
}

// ===========================================================================
//  SHARED BACKEND HELPERS
// ===========================================================================

// Map an audit status to a log level / chip class.
const lvlFor = (s) => ({ FAIL: "fail", WARN: "warn", PASS: "ok" }[s] || "info");
const chipFor = (s) => ({ FAIL: "fail", WARN: "warn", PASS: "ok" }[s] || "info");

function detRow(c) {
  return `<div class="det">
    <span class="dn">${escapeHtml(c.name)}：${escapeHtml(c.detail)}</span>
    <span class="chip ${chipFor(c.status)}">${c.status}</span>
  </div>`;
}

// Summarise a subset of audit checks into a stage result.
function summarizeChecks(report, names, label) {
  const checks = (report.checks || []).filter(c => names.includes(c.name));
  checks.forEach(c => log(`  [${c.status}] ${c.name} — ${c.detail}`, lvlFor(c.status)));

  const fails = checks.filter(c => c.status === "FAIL");
  const warns = checks.filter(c => c.status === "WARN");
  const manual = checks.filter(c => c.status === "MANUAL");
  const info = checks.filter(c => c.status === "INFO");

  if (fails.length || warns.length) {
    const rows = [...fails, ...warns, ...manual, ...info].map(detRow).join("");
    return {
      ok: true, warn: true,
      summary: `${fails.length} 不合規 · ${warns.length} 警告`,
      errTitle: `${label}：${fails.length + warns.length} 項待改善`,
      errBody: rows,
    };
  }
  if (manual.length) {
    return {
      ok: true, warn: true,
      summary: `需人工驗證`,
      errTitle: `${label}：需人工驗證`,
      errBody: manual.map(detRow).join(""),
    };
  }
  const passed = checks.filter(c => c.status === "PASS");
  const infoText = info.length ? ` · ${info.length} 資訊` : "";
  return { ok: true, summary: `${passed.length} 項通過${infoText}` };
}

// Launch one attack scenario as a job and resolve when it ends.
function runScenarioJob(scenario, extra) {
  return new Promise(async (resolve) => {
    const params = Object.assign(
      { interface: ctx.iface, bssid: ctx.bssid, channel: ctx.channel || 6 },
      extra || {});
    const d = await postJSON("/api/attack/start", { scenario, params });
    if (!d.ok) {
      log(`啟動 ${scenario} 失敗：${d.error}`, "fail");
      return resolve({ ok: false, lines: 0, status: "error" });
    }
    const jobId = d.job_id;
    log(`Job ${jobId}（${scenario}）已啟動。`, "info");
    let lines = 0;
    const onOut = (m) => { if (m.job_id === jobId) { log(m.line, "log"); lines++; } };
    const onUpd = (j) => {
      if (j.job_id !== jobId) return;
      if (["finished", "error", "killed"].includes(j.status)) {
        socket.off("job_output", onOut);
        socket.off("job_update", onUpd);
        log(`Job ${jobId} ${j.status}（rc=${j.return_code}）。`,
          j.status === "finished" ? "ok" : "fail");
        resolve({ ok: j.status === "finished", lines, status: j.status });
      }
    };
    socket.on("job_output", onOut);
    socket.on("job_update", onUpd);
    setTimeout(() => {
      socket.off("job_output", onOut);
      socket.off("job_update", onUpd);
      resolve({ ok: true, lines, status: "timeout" });
    }, 30000);
  });
}

// ===========================================================================
//  STAGE IMPLEMENTATIONS  (each returns { ok, warn?, summary, errTitle?, errBody? })
// ===========================================================================

// AP 模式 · a. 安全組態檢測 — WPS / WPA3·802.1X / SSID 廣播
async function runConfigAudit() {
  log("AP 模式｜掃描環境並選定受測 AP …", "info");
  const scan = await postJSON("/api/scan", { interface: ctx.iface, duration: 8 });
  if (!scan.ok)
    return { ok: false, summary: "掃描失敗", errBody: `<pre>${escapeHtml(scan.error || "unknown")}</pre>` };

  ctx.networks = scan.networks || [];
  log(`發現 ${ctx.networks.length} 個 AP。`, "ok");
  if (!ctx.networks.length)
    return { ok: false, summary: "無可測 AP", errBody: `<pre>未在 ${ctx.iface} 上發現任何 AP。</pre>` };

  if (!ctx.bssid) {
    ctx.bssid = ctx.networks[0].bssid;
    ctx.channel = ctx.networks[0].channel || 6;
    log(`自動選定受測目標 ${ctx.bssid}（ch${ctx.channel}）。`, "info");
  }

  log(`對 ${ctx.bssid} 執行安全組態稽核 …`, "info");
  const a = await postJSON("/api/audit", { bssid: ctx.bssid, interface: ctx.iface });
  if (!a.ok)
    return { ok: false, summary: "稽核錯誤", errBody: `<pre>${escapeHtml(a.error || "unknown")}</pre>` };
  if (!a.report.target_found)
    return { ok: false, summary: "目標未找到", errBody: `<pre>${escapeHtml(a.report.summary)}</pre>` };

  ctx.report = a.report;   // cached for the advanced-protection stage
  return summarizeChecks(
    a.report,
    ["WPS disabled", "Strong auth (WPA3 / 802.1X)", "SSID broadcast policy"],
    "安全組態");
}

// AP 模式 · b. 進階防護技術檢測 — PMF/802.11w + Client Isolation (+ 主動 PMF 探測)
async function runAdvancedProtection() {
  log("AP 模式｜進階防護技術檢測（PMF / Client Isolation）…", "info");

  // active management-frame protection probe
  log("執行 PMF (802.11w) 主動探測 …", "info");
  await runScenarioJob("pmf_probe", {});

  // reuse the audit report captured in the config stage
  let rep = ctx.report;
  if (!rep) {
    const a = await postJSON("/api/audit", { bssid: ctx.bssid, interface: ctx.iface });
    rep = a.ok ? a.report : { checks: [] };
  }
  return summarizeChecks(rep, ["PMF (802.11w)", "Client isolation"], "進階防護");
}

// Client/Station 模式 · a. 主動防禦與異常偵測 (WIDS)
function runWids() {
  return new Promise(async (resolve) => {
    const WINDOW_MS = 7000;
    log(`Client 模式｜啟動 WIDS 監聽 ${ctx.iface}（${WINDOW_MS / 1000}s）…`, "info");
    const d = await postJSON("/api/wids/start", { interface: ctx.iface });
    if (!d.ok)
      return resolve({ ok: false, summary: "WIDS 啟動失敗", errBody: `<pre>無法啟動監聽模組。</pre>` });

    let events = 0, high = 0, rogue = 0, retrans = 0;
    const onEvt = (e) => {
      events++;
      if (e.severity === "high") high++;
      if (e.type.includes("rogue")) rogue++;
      if (e.type.includes("retrans") || e.type.includes("handshake")) retrans++;
      const lvl = e.severity === "high" ? "fail" : e.severity === "medium" ? "warn" : "info";
      log(`  [${e.severity.toUpperCase()}] ${e.type} — ${e.message}`, lvl);
    };
    socket.on("wids_event", onEvt);

    setTimeout(async () => {
      socket.off("wids_event", onEvt);
      await postJSON("/api/wids/stop", {});
      log(`WIDS 停止。共 ${events} 事件，重傳/握手 ${retrans}，惡意熱點 ${rogue}，高危 ${high}。`,
        high ? "warn" : "ok");
      if (high) {
        resolve({
          ok: true, warn: true,
          summary: `${events} 事件 · ${high} 高危`,
          errTitle: `偵測到 ${high} 項高危入侵事件`,
          errBody: `<pre>於 ${WINDOW_MS / 1000}s 監聽視窗內偵測到 ${high} 項高危事件` +
            `（重傳/非法握手 ${retrans}，惡意/釣魚熱點 ${rogue}）。詳見下方日誌。</pre>`,
        });
      } else {
        resolve({ ok: true, summary: `${events} 事件 · 無高危` });
      }
    }, WINDOW_MS);
  });
}

// Client/Station 模式 · b. 攻擊模擬與驗證 — Deauth + Rogue AP + 完整日誌
async function runAttackSim() {
  log("Client 模式｜攻擊模擬與驗證 …", "info");

  log("① 模擬 Deauth 解除認證攻擊 …", "info");
  const d1 = await runScenarioJob("deauth", { count: "50" });

  log("② 架設釣魚熱點（Rogue AP / Evil Twin）…", "info");
  const d2 = await runScenarioJob("rogue_ap", { config_path: "configs/eviltwin.conf" });

  const totalLines = d1.lines + d2.lines;
  log("③ 所有異常連線事件已寫入稽核日誌（logs/testing.jsonl）。", "ok");

  if (!d1.ok && !d2.ok) {
    return {
      ok: false, summary: "攻擊腳本失敗",
      errBody: `<pre>Deauth 與 Rogue AP 腳本皆未正常結束，請檢查工具環境。</pre>`,
    };
  }
  const note = (!d1.ok || !d2.ok) ? " · 部分腳本未完成" : "";
  return { ok: true, summary: `Deauth + Rogue AP · ${totalLines} 行輸出${note}` };
}

// ===========================================================================
//  PIPELINE DRIVER
// ===========================================================================

async function runPipeline() {
  if (running) return;
  running = true;
  resetUI(false);

  ctx.iface = $("#cfg-iface").value || "wlan0";
  ctx.bssid = $("#cfg-bssid").value.trim();
  ctx.channel = 6;
  ctx.networks = [];
  ctx.report = null;

  $("#run-btn").disabled = true;
  $("#reset-btn").disabled = true;
  setDockStat("running", "running");
  $(".dock").classList.remove("collapsed");
  log("════ 檢測流程開始 ════", "info");

  let failed = false;

  for (let i = 0; i < STAGES.length; i++) {
    const st = STAGES[i];
    setState(st.id, "running", "檢測中");
    setProgress((i / STAGES.length) * 100);
    if (i > 0) setConnector(i - 1, "done");
    setConnector(i, "flowing");

    let res;
    try {
      res = await st.run();
    } catch (e) {
      res = { ok: false, summary: "例外錯誤", errBody: `<pre>${escapeHtml(e.message || String(e))}</pre>` };
    }

    if (res.ok) {
      if (res.warn) {
        setState(st.id, "warn", "注意");
        showError(st.id, res.errTitle || "檢測發現", res.errBody || "", "warn");
      } else {
        setState(st.id, "passed", "通過");
      }
      setResult(st.id, res.summary || "");
    } else {
      setState(st.id, "failed", "失敗");
      setResult(st.id, res.summary || "失敗");
      showError(st.id, res.errTitle || "此階段失敗", res.errBody || "<pre>unknown error</pre>");
      log(`階段「${st.title}」失敗 — 中止流程。`, "fail");
      setConnector(i, null);
      failed = true;
      break;
    }
  }

  if (failed) {
    setProgress(100, "failed");
    setDockStat("中止", "failed");
    log("════ 檢測流程中止 ════", "fail");
  } else {
    setConnector(STAGES.length - 2, "done");
    setProgress(100, "done");
    setDockStat("完成", "done");
    log("════ 檢測流程完成 ════", "ok");
  }

  $("#run-btn").disabled = false;
  $("#reset-btn").disabled = false;
  running = false;
}

// ---- reset ----------------------------------------------------------------
function resetUI(full = true) {
  STAGES.forEach((st, i) => {
    setState(st.id, "pending", "待測");
    setResult(st.id, "");
    clearError(st.id);
    if (i < STAGES.length - 1) setConnector(i, null);
  });
  setProgress(0);
  setDockStat("idle");
  if (full) {
    $("#logstream").innerHTML =
      `<div class="log-empty">尚無活動 — 按下 <b>開始檢測</b> 以執行檢測流程。</div>`;
    logCount = 0;
    $("#log-count").textContent = "0 行";
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
  $("#logstream").innerHTML = `<div class="log-empty">已清除。</div>`;
  logCount = 0; $("#log-count").textContent = "0 行";
});
$("#dock-head").addEventListener("click", () => $(".dock").classList.toggle("collapsed"));
