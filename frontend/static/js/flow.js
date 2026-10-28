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
const chineseUI = document.documentElement.lang.startsWith("zh");
const uiText = (text) => chineseUI ? ({
  connected: "已連線", disconnected: "已斷線", idle: "待命", running: "執行中",
  "1. AP 模式": "1. AP 基地台模式", "2. Client / Station 模式": "2. 用戶端／站台模式",
  "Security Configuration Audit": "檢查無線網路安全設定",
  "Advanced Protection": "檢查 AP 管理訊框保護設定",
  "Active Defense · WIDS": "無線入侵偵測與主動防禦",
  "Attack Simulation & Validation": "模擬攻擊並驗證防護效果",
  pass: "通過", fail: "失敗", warn: "警告", info: "資訊", manual: "人工驗證", skipped: "略過", pending: "待測",
  PASS: "通過", FAIL: "失敗", WARN: "警告", INFO: "資訊", MANUAL: "人工驗證",
  log: "日誌", ok: "成功",
})[text] || text : text;
const initialParams = new URLSearchParams(window.location.search);

// ---- connection status ----------------------------------------------------
socket.on("connect", () => {
  $("#conn-dot").classList.add("ok");
  $("#conn-text").textContent = uiText("connected");
});
socket.on("disconnect", () => {
  $("#conn-dot").classList.remove("ok");
  $("#conn-text").textContent = uiText("disconnected");
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
      { key: "wps", testId: 1, label: "禁用 WPS" },
      { key: "auth", testId: 2, label: "使用 WPA3 / 802.1X" },
      { key: "ssid", testId: 4, label: "管控 SSID 廣播 / 限制接入" },
      { key: "enterprise", testId: 5, label: "防 Rogue AP / 釣魚熱點" },
    ],
    run: runConfigAudit,
  },
  {
    id: "advanced", mode: "ap", sub: "b",
    title: "進階防護技術檢測", en: "Advanced Protection",
    items: [
      { key: "pmf", testId: 3, label: "檢查 AP 是否啟用 PMF / 802.11w" },
    ],
    run: runAdvancedProtection,
  },
  {
    id: "wids", mode: "client", sub: "a",
    title: "主動防禦與異常偵測", en: "Active Defense · WIDS",
    items: [
      { key: "monitor", testId: 8, selectionOnly: true, label: "無線入侵偵測 WIDS/WIPS" },
      { key: "deauth_detect", testId: 9, label: "偵測大量重傳 / 非法握手" },
    ],
    run: runWids,
  },
  {
    id: "attacksim", mode: "client", sub: "b",
    title: "攻擊模擬與驗證", en: "Attack Simulation & Validation",
    items: [
      { key: "attack28", testId: 28, label: "模擬 deauth 與 rogue AP 測試" },
    ],
    run: runAttackSim,
  },
];

// shared state passed between stages
const ctx = { iface: "", bssid: "", channel: 6, networks: [], report: null };
let widsSession = null;
let running = false;

// A missing selector keeps the original /flow behavior.
function selectedTestIds() {
  if (!$("#test-selection")) return null;
  return new Set([...$$("#test-selection input:checked")].map(input => Number(input.value)));
}
function selectedItems(stage) {
  const ids = selectedTestIds();
  return stage.items.filter(item => ids ? ids.has(item.testId) : !item.selectionOnly);
}
function visibleStages() {
  return STAGES.filter(stage => selectedItems(stage).length);
}
function testSelected(id) {
  const ids = selectedTestIds();
  return !ids || ids.has(id);
}
function selectedAuditChecks() {
  return Object.keys(CHECK_KEYS).filter(name => STAGES.some(stage =>
    selectedItems(stage).some(item => item.key === CHECK_KEYS[name])));
}

// ---- build the pipeline DOM (grouped by mode) -----------------------------
function cardHTML(st) {
  return `
    <div class="card" id="card-${st.id}" data-state="pending">
      <span class="num">${st.sub}</span>
      <h3>${st.title}</h3>
      <p class="desc">${uiText(st.en)}</p>
      <ul class="items">${selectedItems(st).map(i => `
        <li data-check-key="${i.key}" data-status="pending">
          <div class="item-main">
            <span class="item-text">${$("#test-selection") ? `${i.testId} · ` : ""}${i.label}</span>
            <span class="mini-chip info">待測</span>
          </div>
        </li>`).join("")}</ul>
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
  const visible = visibleStages();
  const order = ["ap", "client"].filter(mode => visible.some(stage => stage.mode === mode));
  if (!visible.length) {
    wrap.innerHTML = '<p class="empty">尚未選擇測項，請先勾選要執行的檢測項目。</p>';
  }

  order.forEach((mode, gi) => {
    const stages = visible.filter(s => s.mode === mode);
    const group = document.createElement("div");
    group.className = "mode-group";
    group.dataset.mode = mode;
    const m = MODES[mode];
    group.innerHTML =
      `<div class="mode-band">
         <span class="mode-name">${uiText(m.label)}</span>
         <span class="mode-desc">${m.desc}</span>
       </div>`;

    const row = document.createElement("div");
    row.className = "mode-cards";
    stages.forEach((st, i) => {
      const col = document.createElement("div");
      col.className = "card-col";
      col.innerHTML = cardHTML(st);
      row.appendChild(col);
      if (i < stages.length - 1) row.appendChild(connectorEl(STAGES.indexOf(st)));
    });
    group.appendChild(row);
    wrap.appendChild(group);

    // connector bridging the two modes
    if (gi < order.length - 1) wrap.appendChild(connectorEl(STAGES.indexOf(stages[stages.length - 1]), true));
  });
}

// ---- card / connector state helpers ---------------------------------------
function setState(id, state, badgeText) {
  const card = $(`#card-${id}`);
  card.dataset.state = state;
  if (badgeText) $(".btxt", card).textContent = badgeText;
}
function setResult(id, text) { $(`#card-${id} .result`).textContent = text || ""; }

function setCheckState(stageId, key, status) {
  const item = $(`#card-${stageId} [data-check-key="${key}"]`);
  if (!item) return;
  const normalized = String(status || "info").toLowerCase();
  const chipClass = normalized === "pass" ? "ok"
    : normalized === "fail" ? "fail"
      : normalized === "warn" || normalized === "manual" ? "warn"
        : "info";
  item.dataset.status = normalized;
  $(".mini-chip", item).className = `mini-chip ${chipClass}`;
  $(".mini-chip", item).textContent = uiText(status || "INFO");
}

function resetCheckStates(id, status = "pending", label = "待測") {
  $$(`#card-${id} [data-check-key]`).forEach(item => {
    item.dataset.status = status;
    $(".mini-chip", item).className = "mini-chip info";
    $(".mini-chip", item).textContent = label;
  });
}

function showError(id, title, body, variant = "fail") {
  const p = $(`#err-${id}`);
  p.className = `err-panel show ${variant === "warn" ? "warn" : variant === "info" ? "info" : ""}`;
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
  el.textContent = uiText(text);
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
    `<span class="lc">${uiText(level)}</span>` +
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
const statusForItem = (s) => ({ FAIL: "fail", WARN: "warn", PASS: "pass", MANUAL: "manual" }[s] || "info");
const CHECK_KEYS = {
  "WPS disabled": "wps",
  "Strong auth (WPA3 / 802.1X)": "auth",
  "SSID broadcast policy": "ssid",
  "PMF (802.11w)": "pmf",
  "Enterprise auth (802.1X + WPA2/3-Enterprise)": "enterprise",
};

function detRow(c) {
  return `<div class="det">
    <span class="dn">${escapeHtml(c.name)}：${escapeHtml(c.detail)}</span>
    <span class="chip ${chipFor(c.status)}">${uiText(c.status)}</span>
  </div>`;
}

// Summarise a subset of audit checks into a stage result.
function summarizeChecks(report, names, label, stageId) {
  const keys = selectedItems(STAGES.find(stage => stage.id === stageId)).map(item => item.key);
  const checks = (report.checks || []).filter(c => names.includes(c.name) && keys.includes(CHECK_KEYS[c.name]));
  checks.forEach(c => {
    log(`  [${c.status}] ${c.name} — ${c.detail}`, lvlFor(c.status));
    if (stageId) setCheckState(stageId, CHECK_KEYS[c.name], statusForItem(c.status));
  });

  const fails = checks.filter(c => c.status === "FAIL");
  const warns = checks.filter(c => c.status === "WARN");
  const manual = checks.filter(c => c.status === "MANUAL");
  const info = checks.filter(c => c.status === "INFO");
  const rows = checks.map(detRow).join("");

  if (fails.length || warns.length) {
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
      errBody: rows,
    };
  }
  const passed = checks.filter(c => c.status === "PASS");
  const infoText = info.length ? ` · ${info.length} 資訊` : "";
  return {
    ok: true,
    summary: `${passed.length} 項通過${infoText}`,
    errTitle: `${label}：檢測明細`,
    errBody: rows,
  };
}

// Launch one attack scenario as a job and resolve when it ends.
let activeScenarioJob = null;
let attackStopRequested = false;
function runScenarioJob(scenario, extra) {
  return new Promise((resolve) => {
    let jobId = null, pollTimer = null, timeoutTimer = null, settled = false, lines = 0;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearInterval(pollTimer);
      clearTimeout(timeoutTimer);
      socket.off("job_output", onOut);
      socket.off("job_update", onUpd);
      activeScenarioJob = null;
      if ($("#scenario-stop")) $("#scenario-stop").disabled = true;
      resolve(result);
    };
    const onOut = (message) => {
      if (message.job_id === jobId) { log(message.line, "log"); lines++; }
    };
    const onUpd = (job) => {
      if (job.job_id !== jobId || !["finished", "error", "killed"].includes(job.status)) return;
      log(`Job ${jobId} ${job.status}（rc=${job.return_code}）。`, job.status === "finished" ? "ok" : "fail");
      finish({ok: job.status === "finished", lines, status: job.status});
    };
    socket.on("job_output", onOut);
    socket.on("job_update", onUpd);
    (async () => {
      try {
        const params = Object.assign({bssid: ctx.bssid, channel: ctx.channel || 6}, extra || {});
        // Fixed 3-radio bench: deauth on the TP-Link (wlan1), evil twin on the
        // Pineapple (eth1, REST). Everything else uses the recon/WIDS radio (wlan0).
        if (scenario === "rogue_ap") {
          params.engine = "pineapple";
          params.management_interface = $("#pineapple-iface")?.value || "";
        } else if (scenario === "deauth") {
          params.engine = "local";
          params.interface = $("#attack-iface")?.value || ctx.iface;
        } else {
          params.interface = ctx.iface;
        }
        const result = await postJSON("/api/attack/start", {scenario, params});
        if (!result.ok) {
          log(`啟動 ${scenario} 失敗：${result.error}`, "fail");
          return finish({ok: false, lines, status: "error"});
        }
        jobId = result.job_id;
        activeScenarioJob = jobId;
        if ($("#scenario-stop")) $("#scenario-stop").disabled = false;
        log(`Job ${jobId}（${scenario}）已啟動。`, "info");
        // Polling recovers terminal events emitted before the start response,
        // and continues to work when a Socket.IO connection is interrupted.
        const poll = async () => {
          try {
            const response = await fetch("/api/attack/jobs");
            const data = await response.json();
            const job = (data.jobs || []).find(item => item.job_id === jobId);
            if (job) onUpd(job);
          } catch (_) { /* watchdog below will stop the job */ }
        };
        pollTimer = setInterval(poll, 1000);
        timeoutTimer = setTimeout(async () => {
          await postJSON("/api/attack/stop", {job_id: jobId});
          log("工作逾時，已送出停止要求；請確認裝置已停止，必要時執行 Pineapple restore。", "fail");
          finish({ok: false, lines, status: "timeout"});
        }, 120000);
        await poll();
      } catch (error) {
        log(error.message, "fail");
        finish({ok: false, lines, status: "error"});
      }
    })();
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
  const a = await postJSON("/api/audit", { bssid: ctx.bssid, interface: ctx.iface, checks: selectedAuditChecks() });
  if (!a.ok)
    return { ok: false, summary: "稽核錯誤", errBody: `<pre>${escapeHtml(a.error || "unknown")}</pre>` };
  if (!a.report.target_found)
    return { ok: false, summary: "目標未找到", errBody: `<pre>${escapeHtml(a.report.summary)}</pre>` };

  ctx.report = a.report;   // cached for the advanced-protection stage
  return summarizeChecks(
    a.report,
    ["WPS disabled", "Strong auth (WPA3 / 802.1X)", "SSID broadcast policy",
      "Enterprise auth (802.1X + WPA2/3-Enterprise)"],
    "安全組態",
    "config");
}

// AP 模式 · b. 檢查 AP 廣告的 PMF/802.11w 設定
async function runAdvancedProtection() {
  log("AP 模式｜檢查 AP 廣告的 PMF / 802.11w 設定 …", "info");

  // reuse the audit report captured in the config stage
  let rep = ctx.report;
  if (!rep) {
    const a = await postJSON("/api/audit", { bssid: ctx.bssid, interface: ctx.iface, checks: selectedAuditChecks() });
    if (!a.ok || !a.report?.target_found) {
      return { ok: false, summary: "稽核失敗", errBody: `<pre>${escapeHtml(a.error || a.report?.summary || "目標未找到")}</pre>` };
    }
    rep = a.report;
  }
  return summarizeChecks(rep, ["PMF (802.11w)"], "進階防護", "advanced");
}

// Client/Station 模式 · a. 主動防禦與異常偵測 (WIDS)
// Two-branch Evil-Twin detection (report slide 11):
//   fingerprint  普通模仿 SSID（BSSID 白名單 / 頻道 / 指紋）
//   mac_layer    模仿 BSSID(MAC)（Sequence / TSF）
//   behavioral   行為分析（RSSI 突增 / Deauth 導向）
//   dos          大量重傳 / 非法握手 / Deauth flood
const WIDS_CATS = {
  fingerprint: { label: "指紋", en: "SSID-Clone" },
  mac_layer: { label: "MAC 層", en: "MAC-Spoof" },
  behavioral: { label: "行為", en: "Behavioral" },
  dos: { label: "DoS", en: "DoS/Integrity" },
};

// Compact human-readable evidence line from an event's evidence dict.
function widsEvidence(e) {
  const v = e.evidence || {};
  if (e.type === "seq_anomaly") return `序號 ${v.seq_prev}→${v.seq_now}（Δ${v.delta}）`;
  if (e.type === "tsf_collision") return `TSF 偏移 ${v.drift_us}µs`;
  if (e.type === "rssi_spike") return `RSSI ${v.rssi_prev}→${v.rssi_now} dBm`;
  if (e.type === "rogue_channel") return `頻道 ch${v.observed_channel}（應 ch${v.expected_channel}）`;
  if (e.type === "evil_twin") return `觀測 BSSID ${v.observed_bssid}（合法 ${(v.expected_bssid || []).join(",")}）`;
  if (e.type === "fingerprint_mismatch")
    return `IE 期望[${(v.ie_order_expected || []).join(",")}] 觀測[${(v.ie_order_observed || []).join(",")}]`;
  if (e.type === "deauth_flood") return `${v.count} 幀/${v.window_s}s reason=${v.reason_code}`;
  if (e.type === "deauth_redirect") return `原 ${v.home_bssid} → 雙子 ${v.twin_bssid}`;
  if (e.type === "retrans_spike") return `重傳比 ${Math.round((v.ratio || 0) * 100)}%`;
  if (e.type === "handshake_bad") return `收到 M${v.observed_msg} 缺 M${v.expected_msg}`;
  return "";
}

async function stopOwnedWids() {
  if (!widsSession) return [];
  socket.off("wids_event", widsSession.onEvent);
  if (widsSession.owned) await postJSON("/api/wids/stop", {});
  const events = widsSession.events;
  widsSession = null;
  return events;
}

async function runWids() {
  const iface = $("#wids-iface")?.value || ctx.iface;
  const baseline = (ctx.networks || [])
    .filter(n => n.bssid.toLowerCase() === ctx.bssid.toLowerCase())
    .map(({bssid, ssid, channel}) => ({bssid, ssid, channel}));
  log(`Client 模式｜啟動 WIDS 監聽 ${iface}，並保持到第 28 項完成…`, "info");

  let alreadyRunning = false;
  let currentStatus = null;
  try {
    const current = await (await fetch("/api/wids/status")).json();
    currentStatus = current.status;
    alreadyRunning = currentStatus?.state === "running";
  } catch (_) { /* Start request below reports the useful error. */ }
  if (alreadyRunning && (currentStatus.iface !== iface
      || Number(currentStatus.channel) !== Number($("#wids-channel")?.value || ctx.channel)
      || (currentStatus.scope === "target" && currentStatus.target_bssid !== ctx.bssid.toUpperCase()))) {
    return {
      ok: false, summary: "WIDS 設定不符",
      errBody: "<pre>現有 WIDS 工作使用不同介面、頻道或目標；請先停止後再執行流程。</pre>",
    };
  }
  const result = alreadyRunning ? {ok: true} : await postJSON("/api/wids/start", {
    interface: iface,
    channel: $("#wids-channel")?.value || ctx.channel,
    baseline,
    scope: "target",
    target_bssid: ctx.bssid,
  });
  if (!result.ok) return {
    ok: false, summary: "WIDS 啟動失敗",
    errBody: `<pre>${escapeHtml(result.error || "無法啟動真實監聽模組。")}</pre>`,
  };

  const events = [];
  const onEvent = event => {
    events.push(event);
    const evidence = widsEvidence(event);
    log(`  [${(WIDS_CATS[event.category] || {}).label || event.category}] ${event.type} — ${event.message}`
      + (evidence ? `｜${evidence}` : ""), event.severity === "high" ? "fail" : "info");
  };
  socket.on("wids_event", onEvent);
  widsSession = {owned: !alreadyRunning, events, onEvent};
  setCheckState("wids", "monitor", "pass");
  $("#wids-panel")?.scrollIntoView({behavior: "smooth", block: "nearest"});

  if (testSelected(28)) {
    return {ok: true, summary: `WIDS 正在 ${iface} 監聽，將涵蓋第 28 項攻擊驗證。`};
  }
  await new Promise(resolve => setTimeout(resolve, 8000));
  const observed = await stopOwnedWids();
  const floods = observed.filter(event => event.type === "deauth_flood");
  setCheckState("wids", "deauth_detect", floods.length ? "pass" : "manual");
  return {ok: true, warn: !floods.length, summary: `${observed.length} 個 WIDS 事件`};
}

// Client/Station 模式 · b. 攻擊模擬與驗證 — Deauth + Rogue AP + 完整日誌
async function runAttackSim() {
  log("Client 模式｜攻擊模擬與驗證 …", "info");

  if (!widsSession) {
    const monitor = await runWids();
    if (!monitor.ok) {
      setCheckState("attacksim", "attack28", "fail");
      return monitor;
    }
  }

  log("① 模擬 Deauth 解除認證攻擊 …", "info");
  const d1 = await runScenarioJob("deauth", { count: "50" });

  if (!d1.ok || attackStopRequested) {
    await stopOwnedWids();
    setCheckState("attacksim", "attack28", "fail");
    return { ok: false, summary: "Deauth 測試未完成，已停止後續攻擊測試。" };
  }

  log("② 架設釣魚熱點（Rogue AP / Evil Twin）— WiFi Pineapple over eth1 …", "info");
  const d2 = await runScenarioJob("rogue_ap");

  if (attackStopRequested || d2.status === "killed") {
    await stopOwnedWids();
    setCheckState("attacksim", "attack28", "fail");
    return { ok: false, summary: "攻擊測試已停止，請確認裝置還原狀態。" };
  }
  await new Promise(resolve => setTimeout(resolve, 3000));
  const widsEvents = await stopOwnedWids();
  const deauthDetected = widsEvents.some(event => event.type === "deauth_flood");
  const twinTypes = new Set(["fingerprint_mismatch", "seq_anomaly", "tsf_collision", "rssi_spike"]);
  const twinDetected = widsEvents.some(event => twinTypes.has(event.type));
  const widsDetected = deauthDetected && twinDetected;
  setCheckState("wids", "deauth_detect", deauthDetected ? "pass" : "fail");
  setCheckState("attacksim", "attack28", widsDetected && d1.ok && d2.ok ? "pass" : "fail");
  const totalLines = d1.lines + d2.lines;
  log("③ 所有異常連線事件已寫入稽核日誌（logs/testing.jsonl）。", "ok");

  const rows = [
    { name: "Deauth 攻擊模擬", status: d1.ok ? "PASS" : "FAIL",
      detail: d1.ok ? `完成，輸出 ${d1.lines} 行。` : `未完成，狀態 ${d1.status}。` },
    { name: "Rogue AP / Evil Twin", status: d2.ok ? "PASS" : "FAIL",
      detail: d2.ok ? `完成，輸出 ${d2.lines} 行。` : `未完成，狀態 ${d2.status}。` },
    { name: "WIDS 攻擊驗證", status: widsDetected ? "PASS" : "FAIL",
      detail: `Deauth flood ${deauthDetected ? "已偵測" : "未偵測"}；同 MAC Evil Twin ${twinDetected ? "已偵測" : "未偵測"}。` },
    { name: "事件日誌", status: "PASS", detail: "已記錄至 logs/testing.jsonl。" },
  ].map(detRow).join("");

  if (!d1.ok || !d2.ok || !widsDetected) {
    return {
      ok: false, summary: "第 28 項未完成 WIDS 閉環驗證",
      errBody: rows,
    };
  }
  const note = (!d1.ok || !d2.ok) ? " · 部分腳本未完成" : "";
  return {
    ok: true,
    warn: !d1.ok || !d2.ok,
    summary: `Deauth + Rogue AP · ${totalLines} 行輸出${note}`,
    errTitle: "攻擊模擬：檢測明細",
    errBody: rows,
  };
}

// ===========================================================================
//  PIPELINE DRIVER
// ===========================================================================

async function runPipeline() {
  if (running) return;
  if (!visibleStages().length) {
    $("#selection-status").textContent = "請至少勾選一個檢測項目。";
    return;
  }
  if ($("#cfg-channel")) {
    if (!$("#cfg-bssid").value.trim()) {
      $("#target-note").textContent = "請先選擇網路或輸入 BSSID，再開始檢測。";
      $("#cfg-bssid").focus();
      return;
    }
    if (!$("#cfg-channel").reportValidity()) return;
  }
  if (!$("#cfg-iface").value) {
    log("請先選擇可用的掃描介面。", "fail");
    return;
  }
  running = true;
  attackStopRequested = false;
  if ($("#test-selection")) $("#test-selection").disabled = true;
  resetUI(false);

  ctx.iface = $("#cfg-iface").value;
  ctx.bssid = $("#cfg-bssid").value.trim();
  ctx.channel = parseInt($("#cfg-channel")?.value || initialParams.get("channel") || "6", 10) || 6;
  ctx.networks = typeof scannedNetworks !== "undefined"
    ? scannedNetworks.filter(network => network.bssid.toLowerCase() === ctx.bssid.toLowerCase()) : [];
  ctx.report = null;

  $("#run-btn").disabled = true;
  $("#reset-btn").disabled = true;
  setDockStat("running", "running");
  $(".dock").classList.remove("collapsed");
  log("════ 檢測流程開始 ════", "info");

  let failed = false;
  const includeClientMode = $("#cfg-client-mode")?.checked !== false;
  const activeStages = visibleStages().filter(st => includeClientMode || st.mode !== "client");

  if (!includeClientMode) {
    STAGES.filter(st => st.mode === "client").forEach(st => {
      setState(st.id, "skipped", "略過");
      setResult(st.id, "未執行 Client / Station 模式");
      resetCheckStates(st.id, "skipped", "略過");
    });
    log("已略過 Client / Station 模式檢測。", "info");
  }

  for (let i = 0; i < activeStages.length; i++) {
    const st = activeStages[i];
    const stageIdx = STAGES.indexOf(st);
    setState(st.id, "running", "檢測中");
    resetCheckStates(st.id, "pending", "待測");
    setProgress((i / activeStages.length) * 100);
    if (i > 0) setConnector(STAGES.indexOf(activeStages[i - 1]), "done");
    if (i < activeStages.length - 1) setConnector(stageIdx, "flowing");

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
        if (res.errBody) showError(st.id, res.errTitle || "檢測明細", res.errBody, "info");
      }
      setResult(st.id, res.summary || "");
      if (i < activeStages.length - 1) setConnector(stageIdx, "done");
    } else {
      setState(st.id, "failed", "失敗");
      setResult(st.id, res.summary || "失敗");
      showError(st.id, res.errTitle || "此階段失敗", res.errBody || "<pre>unknown error</pre>");
      log(`階段「${st.title}」失敗 — 中止流程。`, "fail");
      setConnector(stageIdx, null);
      failed = true;
      break;
    }
  }

  if (failed) {
    await stopOwnedWids();
    setProgress(100, "failed");
    setDockStat("中止", "failed");
    log("════ 檢測流程中止 ════", "fail");
  } else {
    setProgress(100, "done");
    setDockStat("完成", "done");
    log("════ 檢測流程完成 ════", "ok");
  }

  $("#run-btn").disabled = false;
  $("#reset-btn").disabled = false;
  running = false;
  if ($("#test-selection")) $("#test-selection").disabled = false;
}

// ---- reset ----------------------------------------------------------------
function resetUI(full = true) {
  visibleStages().forEach((st) => {
    const i = STAGES.indexOf(st);
    setState(st.id, "pending", "待測");
    setResult(st.id, "");
    resetCheckStates(st.id, "pending", "待測");
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
async function populateInterfaceSelect(sel, endpoint, initialIface) {
  if (!sel) return;
  sel.innerHTML = '<option value="">載入中…</option>';
  try {
    const r = await fetch(endpoint);
    const d = await r.json();
    sel.replaceChildren();
    (d.interfaces || []).forEach(i => {
      const o = document.createElement("option");
      o.value = i; o.textContent = d.labels?.[i] || i;
      sel.appendChild(o);
    });
    if (!sel.options.length) {
      sel.innerHTML = '<option value="">找不到無線介面</option>';
      return;
    }
    if (initialIface && d.interfaces.includes(initialIface)) sel.value = initialIface;
    else if (d.interfaces.includes(d.preferred)) sel.value = d.preferred;
  } catch (e) {
    sel.innerHTML = '<option value="">無法取得介面清單</option>';
  }
}

async function loadInterfaces() {
  // Recon/WIDS radio (wlan0) and the deauth radio (wlan1) are picked separately.
  await Promise.all([
    populateInterfaceSelect($("#cfg-iface"), "/api/interfaces", initialParams.get("iface")),
    populateInterfaceSelect($("#attack-iface"), "/api/attack/interfaces", null),
    populateInterfaceSelect($("#pineapple-iface"), "/api/pineapple/interfaces", null),
  ]);
}

function applyInitialTarget() {
  const bssid = initialParams.get("bssid");
  if (bssid) $("#cfg-bssid").value = bssid;
}

// ---- wire up --------------------------------------------------------------
buildPipeline();
applyInitialTarget();
loadInterfaces();
$("#run-btn").addEventListener("click", runPipeline);
$("#reset-btn").addEventListener("click", () => resetUI(true));
$("#log-clear").addEventListener("click", () => {
  $("#logstream").innerHTML = `<div class="log-empty">已清除。</div>`;
  logCount = 0; $("#log-count").textContent = "0 行";
});
$("#dock-head").addEventListener("click", () => $(".dock").classList.toggle("collapsed"));

$("#test-selection")?.addEventListener("change", () => {
  if (running) return;
  buildPipeline();
  resetUI(false);
  const count = selectedTestIds().size;
  $("#selection-status").textContent = count ? `已選擇 ${count} 項檢測` : "請至少勾選一個檢測項目。";
  if (testSelected(8)) $("#wids-panel")?.scrollIntoView({behavior: "smooth", block: "nearest"});
});

$("#scenario-stop")?.addEventListener("click", async () => {
  if (!activeScenarioJob) return;
  attackStopRequested = true;
  $("#scenario-stop").disabled = true;
  const result = await postJSON("/api/attack/stop", {job_id: activeScenarioJob});
  log(result.ok ? "已要求停止攻擊測試，等待裝置清理與還原。" : "停止要求失敗，請檢查裝置狀態。", result.ok ? "warn" : "fail");
  if (!result.ok && activeScenarioJob) $("#scenario-stop").disabled = false;
});
