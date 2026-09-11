const $ = (id) => document.getElementById(id);
let liveTimer = null;
let liveSocket = null;
let currentFlows = [];
let liveAlerts = [];

$("run").addEventListener("click", async () => {
  const file = $("pcap").files[0];
  if (!file) { $("status").textContent = "Select a PCAP file first."; return; }
  const body = new FormData();
  body.append("file", file);
  body.append("model", $("model").value);
  body.append("threshold", $("threshold").value);
  body.append("limit", $("limit").value);
  $("run").disabled = true;
  $("status").textContent = "Analyzing: PCAP → flows → features → Kalman → classifier...";
  try {
    const response = await fetch("/api/analyze", { method: "POST", body });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Analysis failed");
    render(result);
    $("status").textContent = `Completed ${result.file}.`;
  } catch (error) {
    $("status").textContent = error.message;
  } finally { $("run").disabled = false; }
});

async function refreshLive() {
  const response = await fetch("/api/live/status");
  const result = await response.json();
  if (result.error) $("status").textContent = `Live capture error: ${result.error}`;
  if (result.running || result.flows_processed > 0) {
    render({
      model: result.model || "Live capture",
      threshold: result.threshold ?? 0.5,
      flows_processed: result.flows_processed || 0,
      flows_flagged: result.flows_flagged || 0,
      flag_rate: result.flag_rate || 0,
      packets: result.packets || 0,
      packets_analyzed: result.packets_analyzed || 0,
      packets_ignored_by_filter: result.packets_ignored_by_filter || 0,
      target_ips: result.target_ips || [],
      active_flows: result.active_flows || 0,
      flows: result.flows || [],
      flows_per_second: result.packets_per_second || 0
    });
    $("throughput-unit").textContent = "packets/sec";
    $("status").textContent = result.running
      ? `LIVE: reading ${result.interface} | ${result.packets.toLocaleString()} packets | ` +
        `${result.target_ips?.length ? `filter ${result.target_ips.join(", ")} | ` : ""}` +
        `last packet ${result.last_packet_at || "not received yet"}`
      : `Live capture stopped. ${result.packets.toLocaleString()} packets observed.`;
  }
  $("start-live").disabled = result.running;
  $("stop-live").disabled = !result.running;
  if (!result.running && liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
  }
}

function connectLiveAlerts() {
  if (liveSocket && liveSocket.readyState <= WebSocket.OPEN) return;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  liveSocket = new WebSocket(`${protocol}//${window.location.host}/ws/live-alerts`);
  liveSocket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "alerts" && message.alerts.length) {
      liveAlerts = [...message.alerts, ...liveAlerts]
        .filter((alert, index, alerts) =>
          alerts.findIndex((item) => item.flow_id === alert.flow_id) === index)
        .slice(0, 100);
      renderAlerts();
      $("status").textContent =
        `Real-time stream received ${message.alerts.length} new alert(s).`;
    }
    if (message.type === "status") renderLiveStatus(message.status);
  };
  liveSocket.onclose = () => { liveSocket = null; };
}

function renderLiveStatus(result) {
  if (result.error) $("status").textContent = `Live capture error: ${result.error}`;
  if (result.running || result.flows_processed > 0) {
    render({
      model: result.model || "Live capture",
      threshold: result.threshold ?? 0.5,
      flows_processed: result.flows_processed || 0,
      flows_flagged: result.flows_flagged || 0,
      flag_rate: result.flag_rate || 0,
      packets: result.packets || 0,
      active_flows: result.active_flows || 0,
      flows: result.flows || [],
      flows_per_second: result.packets_per_second || 0
    });
  }
}

function renderAlerts() {
  $("alert-feed").classList.toggle("hidden", liveAlerts.length === 0);
  $("alert-count").textContent = liveAlerts.length
    ? `${liveAlerts.length} recent alert(s)`
    : "No live alerts received.";
  $("alerts").innerHTML = liveAlerts.map((alert) => `
    <article class="alert-item">
      <div><strong>${alert.threat_class}</strong><span>${alert.severity}</span></div>
      <p>${alert.evidence?.flag_reason || "Flagged flow requires review."}</p>
      <small>${alert.timestamp} · ${alert.flow_id} · confidence ${(alert.confidence * 100).toFixed(1)}%</small>
    </article>`).join("");
}

$("start-live").addEventListener("click", async () => {
  const interfaceName = $("interface").value.trim();
  if (!interfaceName) {
    $("status").textContent = "Enter a capture interface name first.";
    return;
  }
  const body = new FormData();
  body.append("interface", interfaceName);
  body.append("model", $("model").value);
  body.append("threshold", $("threshold").value);
  body.append("target_ips", $("target-ips").value);
  $("start-live").disabled = true;
  $("status").textContent = "Starting live capture...";
  const response = await fetch("/api/live/start", { method: "POST", body });
  const result = await response.json();
  if (!response.ok) {
    $("status").textContent = result.detail || "Could not start live capture.";
    $("start-live").disabled = false;
    return;
  }
  liveTimer = setInterval(refreshLive, 1000);
  connectLiveAlerts();
  await refreshLive();
});

$("stop-live").addEventListener("click", async () => {
  await fetch("/api/live/stop", { method: "POST" });
  if (liveSocket) { liveSocket.close(); liveSocket = null; }
  await refreshLive();
});

$("clear-alerts").addEventListener("click", () => {
  liveAlerts = [];
  renderAlerts();
});

refreshLive().catch(() => {});
fetch("/api/live/interfaces")
  .then((response) => response.json())
  .then((result) => {
    $("interfaces").innerHTML = (result.interfaces || [])
      .map((item) => {
        const value = item.value.replaceAll('"', "&quot;");
        const status = item.status === "Up" ? "active" : item.status;
        return `<option value="${value}">${item.name} — ${status}</option>`;
      }).join("");
  })
  .catch(() => {});

function render(result) {
  $("summary").classList.remove("hidden");
  $("details").classList.remove("hidden");
  $("processed").textContent = result.flows_processed.toLocaleString();
  $("flagged").textContent = result.flows_flagged.toLocaleString();
  $("rate").textContent = `${(result.flag_rate * 100).toFixed(2)}%`;
  $("throughput").textContent = result.flows_per_second.toLocaleString();
  $("packets").textContent = (result.packets ?? "-").toLocaleString();
  $("active-flows").textContent = (result.active_flows ?? "-").toLocaleString();
  $("model-label").textContent = `${result.model} | threshold ${result.threshold}`;
  $("algorithm-label").textContent = result.algorithm || "XGBoost model";
  const target = result.attack_summary?.most_targeted_destination;
  $("attack-summary").textContent = target
    ? `Volumetric assessment: ${result.attack_summary.dos_ddos_claim.toUpperCase()} | ` +
      `target ${target.destination_ip} | ${target.packets.toLocaleString()} packets | ` +
      `${target.distinct_sources} distinct source(s). A 3-packet flow is not DDoS evidence.`
    : "Volumetric assessment: no destination evidence.";
  currentFlows = result.flows || [];
  applyFilters();
}

function applyFilters() {
  const text = $("filter-text").value.trim().toLowerCase();
  const minPackets = Number($("filter-min-packets").value || 0);
  const minBytes = Number($("filter-min-bytes").value || 0);
  const minProbability = Number($("filter-min-probability").value || 0);
  const status = $("filter-status").value;
  const severity = $("filter-severity").value;
  const anomaly = $("filter-anomaly").value;
  const filtered = currentFlows.filter((flow) => {
    const searchable = JSON.stringify(flow).toLowerCase();
    return (!text || searchable.includes(text))
      && flow.packets >= minPackets
      && flow.bytes >= minBytes
      && flow.probability >= minProbability
      && (status === "all" || (status === "flagged" ? flow.flagged : !flow.flagged))
      && (severity === "all" || flow.severity === severity)
      && (anomaly === "all" || flow.anomaly_level === anomaly);
  });
  $("filter-count").textContent = `Showing ${filtered.length.toLocaleString()} of ${currentFlows.length.toLocaleString()} flows`;
  $("flows").innerHTML = filtered.map((flow) => `
    <tr>
      <td>${flow.start_time_utc || new Date(flow.timestamp * 1000).toISOString()}</td>
      <td class="${flow.flagged ? "danger" : "normal"}">${flow.flagged ? "FLAGGED" : "CLEAR"}</td>
      <td>${flow.threat_class || "generic_malicious_flow"}</td>
      <td>${flow.severity || "low"}</td>
      <td>${flow.flag_reason || "-"}</td>
      <td>${(flow.probability * 100).toFixed(2)}%</td>
      <td>${formatEndpoint(flow.observed_source_ip || flow.source_ip, flow.observed_source_port ?? flow.source_port)}</td>
      <td>${formatEndpoint(flow.observed_destination_ip || flow.destination_ip, flow.observed_destination_port ?? flow.destination_port)}</td>
      <td>${flow.packets}</td><td>${flow.bytes.toLocaleString()}</td>
      <td>${(flow.packets_per_second || 0).toLocaleString()}</td>
      <td>${flow.anomaly_level} (${flow.anomaly_score})<br>R=${flow.kalman?.rate ?? "-"} IAT=${flow.kalman?.iat ?? "-"}</td>
      <td>${Object.entries(flow.top_features || {}).map(([name, value]) => `${name}=${value}`).join(", ")}</td>
    </tr>`).join("");
}

function formatEndpoint(address, port) {
  const formatted = address?.includes(":") ? `[${address}]` : address;
  return `${formatted}:${port}`;
}

["filter-text", "filter-min-packets", "filter-min-bytes", "filter-min-probability",
  "filter-status", "filter-severity", "filter-anomaly"].forEach((id) => {
  $(id).addEventListener("input", applyFilters);
  $(id).addEventListener("change", applyFilters);
});
$("clear-filters").addEventListener("click", () => {
  ["filter-text", "filter-min-packets", "filter-min-bytes", "filter-min-probability"].forEach((id) => { $(id).value = ""; });
  ["filter-status", "filter-severity", "filter-anomaly"].forEach((id) => { $(id).value = "all"; });
  applyFilters();
});
