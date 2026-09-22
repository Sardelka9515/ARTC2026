// Dashboard scan selection and the existing WIDS controls. Uses flow.js helpers.
(() => {
async function loadWidsInterfaces() {
  const sel = $("#wids-iface");
  const previous = sel.value;
  sel.innerHTML = '<option value="">載入中…</option>';
  try {
    const r = await fetch("/api/wids/interfaces");
    const d = await r.json();
    sel.innerHTML = "";
    if (!d.interfaces.length) {
      sel.innerHTML = '<option value="">找不到無線介面</option>';
      return;
    }
    d.interfaces.forEach(i => {
      const o = document.createElement("option");
      o.value = i;
      o.textContent = d.labels?.[i] || i;
      sel.appendChild(o);
    });
    if (d.interfaces.includes(previous)) sel.value = previous;
    else if (d.interfaces.includes(d.preferred)) sel.value = d.preferred;
  } catch (e) {
    sel.innerHTML = '<option value="">無法取得介面清單</option>';
  }
}
loadWidsInterfaces();

// ---- WIDS -----------------------------------------------------------------
function renderWidsStatus(status) {
  const box = $("#wids-status");
  const state = status.state || "stopped";
  const stateLabel = ({stopped: "已停止", starting: "啟動中", running: "監聽中", stopping: "停止中", error: "失敗"})[state] || state;
  box.className = `wids-status state-${state}`;
  const details = [];
  if (status.iface) details.push(status.iface);
  if (status.channel) details.push(`頻道 ${status.channel}`);
  if (status.scope) details.push(status.scope === "target" ? `僅受測 AP ${status.target_bssid}（含同名偽冒 AP）` : "完整 WIDS（目前頻道）");
  if (state === "running") {
    details.push("實體無線訊號");
    details.push(`${status.frames || 0} 個訊框`);
    details.push(status.last_frame_ts
      ? `最後封包時間 ${new Date(status.last_frame_ts * 1000).toLocaleTimeString()}`
      : "等待第一個封包");
  }
  if (status.error) details.push(status.error);
  box.innerHTML = `<strong>${escapeHtml(stateLabel)}</strong><span>${escapeHtml(details.join(" · ") || "尚未啟動")}</span>`;
  $("#wids-start").disabled = state === "starting" || state === "running";
  $("#wids-stop").disabled = state !== "starting" && state !== "running";
  $("#wids-scope").disabled = state === "starting" || state === "running";
  if (status.scope && $("#wids-scope").disabled) $("#wids-scope").value = status.scope;
}

async function refreshWidsStatus() {
  try {
    const r = await fetch("/api/wids/status");
    const d = await r.json();
    if (d.ok) renderWidsStatus(d.status);
  } catch (_) { /* Socket connection indicator already reports backend loss. */ }
}

$("#wids-refresh").addEventListener("click", loadWidsInterfaces);
$("#wids-start").addEventListener("click", async () => {
  const iface = $("#wids-iface").value;
  if (!iface) return renderWidsStatus({state: "error", error: "請選擇無線介面。"});
  renderWidsStatus({state: "starting", iface});
  try {
    const r = await fetch("/api/wids/start", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        interface: iface,
        channel: $("#wids-channel").value,
        scope: $("#wids-scope").value,
        target_bssid: $("#cfg-bssid").value.trim(),
        baseline: scannedNetworks
          .filter(network => network.bssid.toLowerCase() === $("#cfg-bssid").value.trim().toLowerCase())
          .map(({bssid, ssid, channel}) => ({bssid, ssid, channel})),
      }),
    });
    const d = await r.json();
    renderWidsStatus(d.status || {state: "error", error: d.error || "啟動失敗"});
    if (!d.ok) return;
    $("#wids-events").innerHTML = '<p class="empty">正在監聽實體 802.11 訊框…</p>';
  } catch (e) {
    renderWidsStatus({state: "error", iface, error: `啟動失敗: ${e.message}`});
  }
});
$("#wids-stop").addEventListener("click", async () => {
  try {
    const r = await fetch("/api/wids/stop", { method: "POST" });
    const d = await r.json();
    renderWidsStatus(d.status || {state: "stopped"});
  } catch (e) {
    renderWidsStatus({state: "error", error: `停止失敗: ${e.message}`});
  }
});
socket.on("wids_status", renderWidsStatus);
setInterval(refreshWidsStatus, 2000);
refreshWidsStatus();

const WIDS_CAT_LABEL = {
  fingerprint: "指紋", mac_layer: "MAC層", behavioral: "行為",
  dos: "DoS", baseline: "基準",
};
function widsEvidenceStr(evt) {
  const v = evt.evidence || {};
  const keys = Object.keys(v);
  if (!keys.length) return "";
  return keys.slice(0, 3).map(k => `${k}=${Array.isArray(v[k]) ? `[${v[k].join(",")}]` : v[k]}`).join("  ");
}
socket.on("wids_event", (evt) => {
  const box = $("#wids-events");
  const empty = box.querySelector(".empty");
  if (empty) empty.remove();
  const ts = new Date(evt.ts * 1000).toLocaleTimeString();
  const ev = widsEvidenceStr(evt);
  const row = document.createElement("div");
  row.className = "event";
  row.innerHTML = `
    <span class="ts">${ts}</span>
    <span class="chip info">${escapeHtml(WIDS_CAT_LABEL[evt.category] || evt.category || "")}</span>
    <span class="type">${escapeHtml(({seq_anomaly: "序號異常", tsf_collision: "時間戳記衝突", rssi_spike: "訊號強度突增", rogue_channel: "異常頻道", evil_twin: "雙胞胎惡意熱點", fingerprint_mismatch: "指紋不符", deauth_flood: "解除認證洪水攻擊", deauth_redirect: "解除認證重新導向", retrans_spike: "重傳率異常", handshake_bad: "握手異常"})[evt.type] || evt.type)}</span>
    <span class="sev-${evt.severity}">${escapeHtml(({high: "高風險", medium: "中風險", low: "低風險", info: "資訊"})[evt.severity] || evt.severity)}</span>
    <span>${escapeHtml(evt.message)}${ev ? ` <span class="evi">${escapeHtml(ev)}</span>` : ""}</span>`;
  box.prepend(row);
  while (box.children.length > 200) box.removeChild(box.lastChild);
});


})();

let scannedNetworks = [];
const targetNote = $("#target-note");
$("#cfg-channel").value = initialParams.get("channel") || "6";
$("#scan-btn").addEventListener("click", async () => {
  if (!$("#cfg-iface").value) {
    targetNote.textContent = "請先選擇可用的掃描介面。";
    return;
  }
  const duration = $("#scan-duration");
  if (!duration.reportValidity()) return;
  const button = $("#scan-btn");
  button.disabled = true;
  $("#run-btn").disabled = true;
  targetNote.textContent = "正在掃描無線網路…";
  const result = await postJSON("/api/scan", {
    interface: $("#cfg-iface").value, duration: Number(duration.value),
  });
  button.disabled = false;
  $("#run-btn").disabled = false;
  const tbody = $("#scan-tbody");
  tbody.replaceChildren();
  scannedNetworks = result.ok ? result.networks || [] : [];
  targetNote.textContent = result.ok
    ? `${scannedNetworks.length} 個網路，請在下方選擇 BSSID。`
    : `掃描失敗： ${result.error || "未知錯誤"}`;
  if (!scannedNetworks.length) {
    const row = tbody.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 8; cell.className = "empty";
    cell.textContent = result.ok ? "找不到網路，請重新掃描。" : targetNote.textContent;
  }
  scannedNetworks.forEach(network => {
    const row = tbody.insertRow();
    [network.bssid, network.ssid || "〈隱藏網路〉", network.channel ?? "—",
      network.signal ?? "—", network.encryption, network.wps ? "啟用" : "停用", ({required: "必要", capable: "支援", none: "未啟用"})[network.pmf || "none"] || network.pmf]
      .forEach(value => { row.insertCell().textContent = value; });
    const button = document.createElement("button");
    button.textContent = "選擇";
    button.setAttribute("aria-label", `選擇 ${network.bssid}`);
    button.addEventListener("click", () => {
      $("#cfg-bssid").value = network.bssid;
      $("#cfg-channel").value = network.channel || 6;
      if (!$("#wids-start").disabled) $("#wids-channel").value = network.channel || 6;
      $$("#scan-tbody tr").forEach(r => r.classList.remove("selected"));
      row.classList.add("selected");
      targetNote.textContent = `已選擇 ${network.ssid || "〈隱藏網路〉"} · ${network.bssid} · 頻道 ${network.channel || 6}`;
    });
    row.insertCell().appendChild(button);
  });
});
// Freeze target controls while the shared pipeline is running.
const syncControls = () => {
  $$(".scan-block input, .scan-block select, #scan-btn, #scan-tbody button").forEach(el => { el.disabled = running; });
};
new MutationObserver(syncControls).observe($("#run-btn"), { attributes: true, attributeFilter: ["disabled"] });
