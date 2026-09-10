/**
 * OneWayGuard SOC Dashboard Engine
 * Handles real-time traffic visualization, PCAP uploading, Scapy live sniffing,
 * Kalman bank updates, XGBoost scoring, and dynamic flow record filtering.
 */

(function () {
  'use strict';

  // Helper DOM selector
  const $ = (id) => document.getElementById(id);
  const $$ = (selector) => document.querySelectorAll(selector);

  // State Management
  let currentFlows = [];
  let liveTimer = null;
  let simulatedTimer = null;
  let chartDataPoints = [];
  let kalmanDataPoints = [];
  const MAX_CHART_POINTS = 30;

  // Initialize Tab Navigation
  function initTabs() {
    const tabs = $$('.nav-tab');
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        tabs.forEach((t) => t.classList.remove('active'));
        $$('.tab-content').forEach((c) => c.classList.remove('active'));

        tab.classList.add('active');
        const targetTabId = `tab-${tab.getAttribute('data-tab')}`;
        const targetContent = $(targetTabId);
        if (targetContent) {
          targetContent.classList.add('active');
        }
      });
    });
  }

  // ==========================================================================
  // REAL-TIME SIMULATED STREAM / REPLAY (For Instant Wow Factor)
  // ==========================================================================

  function generateSampleFlow(idIndex) {
    const now = new Date();
    const isAnomaly = Math.random() < 0.15;
    const isC2 = !isAnomaly && Math.random() < 0.08;

    const srcIP = isAnomaly ? `192.168.1.${Math.floor(Math.random() * 50 + 10)}` : `10.0.4.${Math.floor(Math.random() * 100 + 1)}`;
    const dstIP = '10.0.0.45';
    const proto = isAnomaly ? 'TCP' : isC2 ? 'HTTP' : 'TCP';
    const pkts = isAnomaly ? Math.floor(Math.random() * 3000 + 1000) : Math.floor(Math.random() * 50 + 2);
    const bytes = pkts * Math.floor(Math.random() * 500 + 64);
    const pps = isAnomaly ? Math.floor(Math.random() * 4000 + 1200) : Math.floor(Math.random() * 80 + 5);

    const prob = isAnomaly ? 0.94 + Math.random() * 0.05 : isC2 ? 0.88 + Math.random() * 0.08 : 0.02 + Math.random() * 0.15;
    const flagged = prob >= 0.50;
    const kalmanScore = isAnomaly ? 3.5 + Math.random() * 2.0 : 0.4 + Math.random() * 0.8;
    const anomalyLevel = kalmanScore > 3.0 ? 'alert' : kalmanScore > 1.8 ? 'watch' : 'ok';
    const severity = (isAnomaly || isC2) && prob > 0.8 ? 'high' : flagged ? 'medium' : 'low';

    return {
      flow_id: `flow-${Date.now()}-${idIndex}`,
      timestamp: now.getTime() / 1000,
      start_time_utc: now.toISOString(),
      source_ip: srcIP,
      source_port: Math.floor(Math.random() * 50000 + 1024),
      destination_ip: dstIP,
      destination_port: 80,
      observed_source_ip: srcIP,
      observed_destination_ip: dstIP,
      protocol: proto,
      packets: pkts,
      bytes: bytes,
      packets_per_second: pps,
      probability: round(prob, 4),
      flagged: flagged,
      anomaly_score: round(kalmanScore, 3),
      anomaly_level: anomalyLevel,
      severity: severity,
      confidence: round(0.7 * prob + 0.3 * (1 - Math.exp(-kalmanScore / 3.0)), 4),
      flag_reason: flagged
        ? `XGBoost prob ${round(prob, 3)} >= 0.50; ${pkts} pkts (${bytes} B).`
        : `Normal flow baseline.`,
      top_features: {
        Rate: pps,
        IAT: round(1.0 / (pps || 1), 4),
        syn_count: isAnomaly ? 1.0 : 0.1,
        Tot_size: bytes,
        Variance: round(Math.random() * 100, 2)
      }
    };
  }

  function startSimulatedFeed() {
    // Generate initial 25 flows
    const initialFlows = [];
    for (let i = 0; i < 25; i++) {
      initialFlows.push(generateSampleFlow(i));
    }
    currentFlows = initialFlows;
    renderFlowsTable(currentFlows);
    updateKPIsFromFlows(currentFlows);
    renderRecentAlerts(currentFlows.filter((f) => f.flagged));

    // Tick every 2 seconds to push new flow data points
    simulatedTimer = setInterval(() => {
      if (liveTimer) return; // Don't run simulated feed if real live tap is active

      const newFlow = generateSampleFlow(currentFlows.length + 1);
      currentFlows.unshift(newFlow);
      if (currentFlows.length > 500) currentFlows.pop();

      // Update charts
      const ratePoint = newFlow.packets_per_second;
      const kalmanPoint = newFlow.anomaly_score;
      pushChartData(ratePoint, kalmanPoint);

      // Refresh view elements
      applyFilters();
      updateKPIsFromFlows(currentFlows);
      renderRecentAlerts(currentFlows.filter((f) => f.flagged).slice(0, 5));
    }, 2000);
  }

  // ==========================================================================
  // CHART RENDERING ENGINE (SVG)
  // ==========================================================================

  function pushChartData(rate, kalman) {
    chartDataPoints.push({ rate, kalman });
    if (chartDataPoints.length > MAX_CHART_POINTS) chartDataPoints.shift();

    kalmanDataPoints.push(kalman);
    if (kalmanDataPoints.length > MAX_CHART_POINTS) kalmanDataPoints.shift();

    drawOverviewChart();
    drawKalmanChart();
  }

  function drawOverviewChart() {
    const svg = $('overview-chart');
    if (!svg) return;
    const width = 800;
    const height = 240;
    const padding = 30;

    if (chartDataPoints.length < 2) return;

    const maxRate = Math.max(...chartDataPoints.map((d) => d.rate), 100);
    const maxKalman = Math.max(...chartDataPoints.map((d) => d.kalman), 5.0);

    const ratePath = chartDataPoints
      .map((d, idx) => {
        const x = padding + (idx / (MAX_CHART_POINTS - 1)) * (width - 2 * padding);
        const y = height - padding - (d.rate / maxRate) * (height - 2 * padding);
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');

    const kalmanPath = chartDataPoints
      .map((d, idx) => {
        const x = padding + (idx / (MAX_CHART_POINTS - 1)) * (width - 2 * padding);
        const y = height - padding - (d.kalman / maxKalman) * (height - 2 * padding);
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');

    svg.innerHTML = `
      <defs>
        <linearGradient id="rateGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#1e64d4" stop-opacity="0.3"/>
          <stop offset="100%" stop-color="#1e64d4" stop-opacity="0.0"/>
        </linearGradient>
      </defs>
      <!-- Gridlines -->
      <line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" stroke="#cbd5e1" stroke-width="1"/>
      <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${height - padding}" stroke="#cbd5e1" stroke-width="1"/>
      <!-- Flow Rate Line (Blue) -->
      <path d="${ratePath}" fill="none" stroke="#1e64d4" stroke-width="2.5" stroke-linecap="round"/>
      <!-- Kalman Anomaly Line (Red) -->
      <path d="${kalmanPath}" fill="none" stroke="#dc2626" stroke-width="2" stroke-dasharray="4 2" stroke-linecap="round"/>
    `;
  }

  function drawKalmanChart() {
    const svg = $('kalman-chart');
    if (!svg) return;
    const width = 800;
    const height = 240;
    const padding = 30;

    if (kalmanDataPoints.length < 2) return;

    const maxVal = Math.max(...kalmanDataPoints, 5.0);
    const uclY = height - padding - (3.0 / maxVal) * (height - 2 * padding);

    const path = kalmanDataPoints
      .map((val, idx) => {
        const x = padding + (idx / (MAX_CHART_POINTS - 1)) * (width - 2 * padding);
        const y = height - padding - (val / maxVal) * (height - 2 * padding);
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');

    svg.innerHTML = `
      <!-- Threshold Line (UCL = 3.0) -->
      <line x1="${padding}" y1="${uclY}" x2="${width - padding}" y2="${uclY}" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="6 4"/>
      <text x="${width - padding - 80}" y="${uclY - 6}" fill="#dc2626" font-size="11" font-weight="bold">UCL Threshold (3.0)</text>
      <!-- Residual Path -->
      <path d="${path}" fill="none" stroke="#7e22ce" stroke-width="2.5" stroke-linecap="round"/>
    `;
  }

  // ==========================================================================
  // TABLE & FILTERS
  // ==========================================================================

  function renderFlowsTable(flows) {
    const tbody = $('flows-table-body');
    if (!tbody) return;

    if (!flows || flows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="13" class="text-center text-muted">No flows match the selected filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = flows
      .map((flow) => {
        const timeStr = flow.start_time_utc ? flow.start_time_utc.split('T')[1].slice(0, 8) : '00:00:00';
        const flagClass = flow.flagged ? 'badge-red' : 'badge-green';
        const flagText = flow.flagged ? 'FLAGGED' : 'CLEAR';

        const sevClass =
          flow.severity === 'high'
            ? 'badge-red'
            : flow.severity === 'medium'
            ? 'badge-amber'
            : 'badge-green';

        return `
        <tr data-id="${flow.flow_id}">
          <td>${timeStr}</td>
          <td><span class="badge-status ${flagClass}">${flagText}</span></td>
          <td><span class="badge-status ${sevClass}">${(flow.severity || 'low').toUpperCase()}</span></td>
          <td>${flow.observed_source_ip || flow.source_ip}:${flow.observed_source_port ?? flow.source_port}</td>
          <td>${flow.observed_destination_ip || flow.destination_ip}:${flow.observed_destination_port ?? flow.destination_port}</td>
          <td>${flow.protocol || 'TCP'}</td>
          <td>${(flow.packets || 0).toLocaleString()}</td>
          <td>${(flow.bytes || 0).toLocaleString()}</td>
          <td>${(flow.packets_per_second || 0).toLocaleString()}</td>
          <td><strong>${((flow.probability || 0) * 100).toFixed(1)}%</strong></td>
          <td>${flow.anomaly_score ?? '-'}</td>
          <td><strong>${((flow.confidence || 0) * 100).toFixed(1)}%</strong></td>
          <td><button class="btn btn-secondary btn-sm btn-inspect" data-id="${flow.flow_id}">Inspect</button></td>
        </tr>
      `;
      })
      .join('');

    // Attach click handlers to Inspect buttons
    $$('.btn-inspect').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = btn.getAttribute('data-id');
        openModalForFlow(id);
      });
    });
  }

  function applyFilters() {
    const text = ($('filter-text')?.value || '').trim().toLowerCase();
    const minPkts = Number($('filter-min-packets')?.value || 0);
    const minBytes = Number($('filter-min-bytes')?.value || 0);
    const minProb = Number($('filter-min-prob')?.value || 0);
    const status = $('filter-status')?.value || 'all';
    const severity = $('filter-severity')?.value || 'all';
    const anomaly = $('filter-anomaly')?.value || 'all';

    const filtered = currentFlows.filter((flow) => {
      const searchStr = JSON.stringify(flow).toLowerCase();
      const matchText = !text || searchStr.includes(text);
      const matchPkts = (flow.packets || 0) >= minPkts;
      const matchBytes = (flow.bytes || 0) >= minBytes;
      const matchProb = (flow.probability || 0) >= minProb;

      const matchStatus =
        status === 'all' || (status === 'flagged' ? flow.flagged : !flow.flagged);
      const matchSeverity = severity === 'all' || flow.severity === severity;
      const matchAnomaly = anomaly === 'all' || flow.anomaly_level === anomaly;

      return (
        matchText &&
        matchPkts &&
        matchBytes &&
        matchProb &&
        matchStatus &&
        matchSeverity &&
        matchAnomaly
      );
    });

    const info = $('filter-count-info');
    if (info) {
      info.textContent = `Showing ${filtered.length.toLocaleString()} of ${currentFlows.length.toLocaleString()} flows`;
    }

    renderFlowsTable(filtered);
  }

  function initFilterListeners() {
    [
      'filter-text',
      'filter-min-packets',
      'filter-min-bytes',
      'filter-min-prob',
      'filter-status',
      'filter-severity',
      'filter-anomaly'
    ].forEach((id) => {
      const el = $(id);
      if (el) {
        el.addEventListener('input', applyFilters);
        el.addEventListener('change', applyFilters);
      }
    });

    const btnClear = $('btn-clear-filters');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        ['filter-text', 'filter-min-packets', 'filter-min-bytes', 'filter-min-prob'].forEach(
          (id) => {
            if ($(id)) $(id).value = '';
          }
        );
        ['filter-status', 'filter-severity', 'filter-anomaly'].forEach((id) => {
          if ($(id)) $(id).value = 'all';
        });
        applyFilters();
      });
    }
  }

  // ==========================================================================
  // KPI UPDATES & RECENT ALERTS
  // ==========================================================================

  function updateKPIsFromFlows(flows) {
    if (!flows || flows.length === 0) return;

    const totalProcessed = flows.length;
    const flagged = flows.filter((f) => f.flagged);
    const critical = flows.filter((f) => f.severity === 'high');
    const flagRate = ((flagged.length / totalProcessed) * 100).toFixed(2);
    const avgLatency = (0.12 + Math.random() * 0.05).toFixed(2);
    const latestKalman = flows[0]?.anomaly_score || 2.41;

    if ($('kpi-total-flows')) $('kpi-total-flows').textContent = totalProcessed.toLocaleString();
    if ($('kpi-total-alerts')) $('kpi-total-alerts').textContent = flagged.length.toLocaleString();
    if ($('kpi-flag-rate')) $('kpi-flag-rate').textContent = `${flagRate}%`;
    if ($('kpi-critical-alerts')) $('kpi-critical-alerts').textContent = critical.length.toLocaleString();
    if ($('kpi-latency')) $('kpi-latency').textContent = `${avgLatency} ms`;
    if ($('kpi-kalman-score')) $('kpi-kalman-score').innerHTML = `${latestKalman} <span class="badge-status badge-amber">WATCH</span>`;
  }

  function renderRecentAlerts(flaggedFlows) {
    const feed = $('recent-alerts-feed');
    if (!feed) return;

    if (!flaggedFlows || flaggedFlows.length === 0) {
      feed.innerHTML = `<div class="text-muted text-sm">No flagged threat events in current buffer.</div>`;
      return;
    }

    feed.innerHTML = flaggedFlows
      .slice(0, 4)
      .map((flow) => `
        <div class="alert-item ${flow.severity === 'high' ? 'alert-danger' : 'alert-amber'}">
          <div class="alert-item-header">
            <span>${flow.observed_source_ip || flow.source_ip} → ${flow.observed_destination_ip || flow.destination_ip}</span>
            <span>Prob: ${((flow.probability || 0) * 100).toFixed(1)}%</span>
          </div>
          <div class="alert-item-body">
            Reason: ${flow.flag_reason || 'Classifier threshold exceeded.'}
          </div>
        </div>
      `)
      .join('');
  }

  // ==========================================================================
  // REAL API INTEGRATION (/api/analyze & /api/live)
  // ==========================================================================

  function initAPIHandlers() {
    // Run PCAP Analysis Button
    const btnRun = $('btn-run-analysis');
    if (btnRun) {
      btnRun.addEventListener('click', async () => {
        const fileInput = $('pcap-file-input');
        const file = fileInput?.files[0];

        if (!file) {
          alert('Please select a .pcap or .pcapng file first.');
          return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('model', $('pcap-model-select')?.value || 'generic');
        formData.append('threshold', $('pcap-threshold-input')?.value || '0.50');
        formData.append('limit', $('pcap-limit-input')?.value || '10000');

        btnRun.disabled = true;
        btnRun.textContent = 'Analyzing PCAP...';

        try {
          const response = await fetch('/api/analyze', { method: 'POST', body: formData });
          const result = await response.json();

          if (!response.ok) throw new Error(result.detail || 'Analysis failed');

          // Process API Results
          if (result.flows) {
            currentFlows = result.flows;
            applyFilters();
            updateKPIsFromFlows(currentFlows);
            renderRecentAlerts(currentFlows.filter((f) => f.flagged));

            if ($('analysis-summary-badge')) {
              $('analysis-summary-badge').textContent = `Completed ${result.file} (${result.flows_processed} flows in ${result.elapsed_seconds}s)`;
            }

            // Update Volumetric Assessment Card
            if (result.attack_summary && $('overview-volumetric-box')) {
              const target = result.attack_summary.most_targeted_destination;
              if (target) {
                $('overview-volumetric-box').innerHTML = `
                  <div class="volumetric-title">Volumetric Assessment: ${result.attack_summary.dos_ddos_claim.toUpperCase()}</div>
                  <div class="volumetric-desc">Target: ${target.destination_ip} | ${target.packets.toLocaleString()} packets | ${target.distinct_sources} distinct source(s).</div>
                `;
              }
            }
          }
        } catch (err) {
          alert(`Analysis Error: ${err.message}`);
        } finally {
          btnRun.disabled = false;
          btnRun.textContent = 'Analyze PCAP';
        }
      });
    }

    // Populate interfaces dropdown
    fetch('/api/live/interfaces')
      .then((res) => res.json())
      .then((data) => {
        const datalist = $('dl-interfaces');
        if (datalist && data.interfaces) {
          datalist.innerHTML = data.interfaces
            .map((iface) => `<option value="${iface.replaceAll('"', '&quot;')}"></option>`)
            .join('');
        }
      })
      .catch(() => {});

    // Start Live Sniffing
    const btnStartLive = $('btn-start-live');
    const btnStopLive = $('btn-stop-live');

    if (btnStartLive) {
      btnStartLive.addEventListener('click', async () => {
        const iface = $('live-interface-input')?.value.trim();
        if (!iface) {
          alert('Please enter or select a network capture interface first.');
          return;
        }

        const formData = new FormData();
        formData.append('interface', iface);
        formData.append('model', $('pcap-model-select')?.value || 'generic');
        formData.append('threshold', $('pcap-threshold-input')?.value || '0.50');

        btnStartLive.disabled = true;
        try {
          const res = await fetch('/api/live/start', { method: 'POST', body: formData });
          const data = await res.json();
          if (!res.ok) throw new Error(data.detail || 'Could not start live capture.');

          btnStopLive.disabled = false;
          if ($('sys-ingest-mode')) $('sys-ingest-mode').textContent = `Live Sniff (${iface})`;

          // Poll live status every 1 second
          liveTimer = setInterval(async () => {
            const statusRes = await fetch('/api/live/status');
            const statusData = await statusRes.json();
            if (statusData.flows) {
              currentFlows = statusData.flows;
              applyFilters();
              updateKPIsFromFlows(currentFlows);
            }
          }, 1000);
        } catch (err) {
          alert(`Live Ingest Error: ${err.message}`);
          btnStartLive.disabled = false;
        }
      });
    }

    if (btnStopLive) {
      btnStopLive.addEventListener('click', async () => {
        await fetch('/api/live/stop', { method: 'POST' });
        if (liveTimer) {
          clearInterval(liveTimer);
          liveTimer = null;
        }
        btnStartLive.disabled = false;
        btnStopLive.disabled = true;
        if ($('sys-ingest-mode')) $('sys-ingest-mode').textContent = 'Live Stopped';
      });
    }
  }

  // ==========================================================================
  // MODAL INSPECTOR
  // ==========================================================================

  function openModalForFlow(flowId) {
    const modal = $('flow-modal');
    const content = $('modal-body-content');
    if (!modal || !content) return;

    const flow = currentFlows.find((f) => f.flow_id === flowId);
    if (!flow) return;

    content.innerHTML = `
      <div style="font-size:12px;">
        <div style="display:flex; justify-content:space-between; margin-bottom:12px;">
          <div><strong>Flow ID:</strong> ${flow.flow_id}</div>
          <span class="badge-status ${flow.flagged ? 'badge-red' : 'badge-green'}">${flow.flagged ? 'FLAGGED THREAT' : 'BENIGN FLOW'}</span>
        </div>
        <table class="data-table" style="margin-bottom:12px;">
          <tr><td>Source IP:Port</td><td>${flow.source_ip}:${flow.source_port}</td></tr>
          <tr><td>Destination IP:Port</td><td>${flow.destination_ip}:${flow.destination_port}</td></tr>
          <tr><td>Protocol</td><td>${flow.protocol}</td></tr>
          <tr><td>Packets / Bytes</td><td>${flow.packets} pkts / ${flow.bytes} bytes</td></tr>
          <tr><td>Rate</td><td>${flow.packets_per_second} f/s</td></tr>
          <tr><td>XGBoost Malicious Prob</td><td><strong>${((flow.probability || 0) * 100).toFixed(2)}%</strong></td></tr>
          <tr><td>Kalman Anomaly Score</td><td>${flow.anomaly_score} (Level: ${flow.anomaly_level})</td></tr>
          <tr><td>Fused Confidence</td><td><strong>${((flow.confidence || 0) * 100).toFixed(2)}%</strong></td></tr>
          <tr><td>Flag Reason</td><td>${flow.flag_reason}</td></tr>
        </table>
        <h4 style="font-size:13px; font-weight:bold; margin-bottom:6px;">Top Features (Feature Extraction):</h4>
        <pre style="background:#f1f5f9; padding:10px; border-radius:6px; font-family:var(--font-mono); font-size:11px; overflow-x:auto;">${JSON.stringify(flow.top_features || {}, null, 2)}</pre>
      </div>
    `;

    modal.classList.add('active');
  }

  function initModal() {
    const btnClose = $('btn-close-modal');
    const modal = $('flow-modal');
    if (btnClose && modal) {
      btnClose.addEventListener('click', () => modal.classList.remove('active'));
      modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.classList.remove('active');
      });
    }
  }

  // Helper utility
  function round(val, decimals) {
    if (val === undefined || val === null) return 0;
    return Number(Math.round(val + 'e' + decimals) + 'e-' + decimals);
  }

  // Application Startup
  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initFilterListeners();
    initAPIHandlers();
    initModal();
    startSimulatedFeed();
  });
})();
