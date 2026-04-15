// lq.js

// --------------------
// Format metric label for display
// --------------------
function formatLabel(key) {
  if (key.startsWith('DOWNLINK')) return 'DNLINK ' + key.split('_')[1];
  if (key.startsWith('UPLINK')) return 'UPLINK ' + key.split('_')[1];
  return key;
}
function formatScoreLabel(key) {
  if (key === 'DOWNLINK_Score') return 'DNLINK SCORE';
  if (key === 'UPLINK_Score') return 'UPLINK SCORE';
  if (key === 'Score') return 'SCORE'; // Aggregate score
  return key;
}

// --------------------
// Fetch link parameters from server
// --------------------
export async function fetchLinkParams(userEditing = false, lastLocalChange = 0) {
  if (userEditing && (Date.now() - lastLocalChange < 1500)) return;
  try {
    const r = await fetch('/linkparams.json', { cache: 'no-store' });
    if (!r.ok) return;
    return await r.json();
  } catch (e) {
    console.error('fetchLinkParams error:', e);
  }
}

// --------------------
// VAP name helper
// --------------------
function getVapName(vapIndex) {
  const map = {
    0: 'private(2g)',
    1: 'private(5g)',
    2: 'iot(2g)',
    3: 'iot(5g)',
    4: 'hotspot_open(2g)',
    5: 'hotspot_open(5g)',
    6: 'lnf_psk(2g)',
    7: 'lnf_psk(5g)',
    8: 'hotspot_secure(2g)',
    9: 'hotspot_secure(5g)',
    10: 'lnf_radius(2g)',
    11: 'lnf_radius(5g)',
    12: 'mesh_backhaul(2g)',
    13: 'mesh_backhaul(5g)',
    14: 'mesh_sta(2g)',
    15: 'mesh_sta(5g)',
    16: 'private(6g)',
    17: 'iot(6g)',
    18: 'hotspot_open(6g)',
    19: 'lnf_psk(6g)',
    20: 'hotspot_secure(6g)',
    22: 'mesh_backhaul(6g)',
    23: 'mesh_sta(6g)'
  };
  return map[vapIndex] || `vap_${vapIndex}`;
}
const LINE_WIDTHS = {
  metric: 2,   // SNR / PER / PHY
  score: 5     // Score
};
// --------------------
// Line styles and colors
// --------------------
const LINE_STYLES = {
  downlink: { dash: 'solid'},
  uplink: { dash: 'dash' },
  aggregate: { dash: 'solid'}
};

const COLORS_METRICS = {
  DNLINK_SNR: '#1f77b4',
  DNLINK_PER: '#2ca02c',
  DNLINK_PHY: '#9467bd',
  DNLINK_Score: '#d62728',
  UPLINK_SNR: '#1f77b4',
  UPLINK_PER: '#2ca02c',
  UPLINK_PHY: '#9467bd',
  UPLINK_Score: '#d62728',
  SNR: '#1f77b4',
  PER: '#2ca02c',
  PHY: '#9467bd',
  Score: '#d62728'
};
function getMetricColor(key) {
  return COLORS_METRICS[key] || COLORS_METRICS[
    key.includes('_SNR') ? 'SNR' :
    key.includes('_PER') ? 'PER' :
    key.includes('_PHY') ? 'PHY' :
    key.includes('Score') ? 'Score' :
    '#000000'
  ];
}

// --------------------
// Get selected metrics from checkboxes
// --------------------
function getSelectedMetrics() {
  return {
    downlink: [...document.querySelectorAll('#downlinkDropdown input:checked')].map(cb => cb.value),
    uplink:   [...document.querySelectorAll('#uplinkDropdown input:checked')].map(cb => cb.value),
    aggregate: document.querySelector('#aggregateCheckbox')?.checked === true
  };
}
// --------------------
// Render Link Quality Charts (scroll-safe)
// --------------------
export function renderLinkQualityChart(data) {
  const container = document.getElementById('LeftGridContainer');
  if (!container) return;

  // Preserve scroll
  const scrollTop = container.scrollTop;

  if (!data || !data.Devices) return;

  // Read user selections
  const selected = {
    downlink: [...document.querySelectorAll('#downlinkDropdown input:checked')].map(cb => cb.value),
    uplink: [...document.querySelectorAll('#uplinkDropdown input:checked')].map(cb => cb.value),
    aggregate: document.querySelector('#aggregateCheckbox')?.checked === true
  };

  // Metric families helper
  const metricFamilies = [...new Set([...selected.downlink, ...selected.uplink].flatMap(k => {
    const arr = [];
    if (k.includes('_PER')) arr.push('PER');
    if (k.includes('_PHY')) arr.push('PHY');
    if (k.includes('_SNR')) arr.push('SNR');
    return arr;
  }))];

  // Reuse or create chart divs per device
  data.Devices.forEach((dev, idx) => {
    if (!dev.LinkQuality || !dev.Time) return;

    let div = container.querySelector(`.chartDiv[data-mac="${dev.MAC}"]`);
    if (!div) {
      div = document.createElement('div');
      div.className = 'chartDiv';
      div.dataset.mac = dev.MAC;
      div.style.height = '400px';
      div.style.width = '100%';
      container.appendChild(div);
    }

    const traces = [];

    // Aggregate mode
    if (selected.aggregate) {
      metricFamilies.forEach(type => {
        const val = dev.LinkQuality[type];
        if (!val) return;
        traces.push({
          name: type,
          x: dev.Time,
          y: val,
          type: 'scatter',
          mode: 'lines',
          line: { ...LINE_STYLES.aggregate, color: getMetricColor(type), width: LINE_WIDTHS.metric }
        });
      });

      if (dev.LinkQuality.Score) {
        traces.push({
          name: formatScoreLabel('Score'),
          x: dev.Time,
          y: dev.LinkQuality.Score,
          type: 'scatter',
          mode: 'lines',
          line: { ...LINE_STYLES.aggregate, color: COLORS_METRICS.Score, width: LINE_WIDTHS.score }
        });
      }
    } else {
      // Downlink
      selected.downlink.forEach(key => {
        const val = dev.LinkQuality[key];
        if (!val) return;
        traces.push({
          name: formatLabel(key),
          x: dev.Time,
          y: val,
          type: 'scatter',
          mode: 'lines',
          line: { ...LINE_STYLES.downlink, color: getMetricColor(key), width: LINE_WIDTHS.metric }
        });
      });

      // Uplink
      selected.uplink.forEach(key => {
        const val = dev.LinkQuality[key];
        if (!val) return;
        traces.push({
          name: formatLabel(key),
          x: dev.Time,
          y: val,
          type: 'scatter',
          mode: 'lines',
          line: { ...LINE_STYLES.uplink, color: getMetricColor(key), width: LINE_WIDTHS.metric }
        });
      });

      // Scores
      if (selected.downlink.length && dev.LinkQuality.DOWNLINK_Score) {
        traces.push({
          name: formatScoreLabel('DOWNLINK_Score'),
          x: dev.Time,
          y: dev.LinkQuality.DOWNLINK_Score,
          type: 'scatter',
          mode: 'lines',
          line: { ...LINE_STYLES.downlink, color: COLORS_METRICS.DNLINK_Score, width: LINE_WIDTHS.score }
        });
      }

      if (selected.uplink.length && dev.LinkQuality.UPLINK_Score) {
        traces.push({
          name: formatScoreLabel('UPLINK_Score'),
          x: dev.Time,
          y: dev.LinkQuality.UPLINK_Score,
          type: 'scatter',
          mode: 'lines',
          line: { ...LINE_STYLES.uplink, color: COLORS_METRICS.UPLINK_Score, width: LINE_WIDTHS.score }
        });
      }
    }

    // Latest score for title
    let latestScore = '-';
    if (selected.aggregate && dev.LinkQuality.Score) {
      latestScore = dev.LinkQuality.Score.slice(-1)[0]?.toFixed(3) ?? '-';
    } else {
      const dl = dev.LinkQuality.DOWNLINK_Score?.slice(-1)[0];
      const ul = dev.LinkQuality.UPLINK_Score?.slice(-1)[0];
      if (dl != null && ul != null) latestScore = `Downlink: ${dl.toFixed(3)}, Uplink: ${ul.toFixed(3)}`;
      else if (dl != null) latestScore = dl.toFixed(3);
      else if (ul != null) latestScore = ul.toFixed(3);
    }

    const vapName = dev.VapIndex !== undefined ? getVapName(dev.VapIndex) : 'unknown';
    const layout = {
      title: { text: `<b>Link Quality:</b>${dev.MAC}<br><b>Score:</b> ${latestScore} &nbsp;&nbsp; <b>VAP:</b> ${vapName}`, x: 0.5, xanchor: 'center' },
      xaxis: { title: 'Time', tickangle: -45 },
      yaxis: { title: 'Score', range: [0, 1], tick0: 0, dtick: 0.1, fixedrange: true },
      height: 400,
      autosize: true,
      uirevision: 'keep',
      margin: { t: 100, l: 60, r: 40, b: 60 }
    };

    Plotly.react(div, traces, layout, { responsive: true });
  });

  // Restore container scroll
  container.scrollTop = scrollTop;
}

// --------------------
// Render Alarms Table (scroll-safe)
// --------------------
export function renderAlarms(data) {
  const table = document.getElementById('Alarms');
  if (!table) return;

  // Preserve scroll
  const scrollTop = table.scrollTop;

  // Keep header, remove old rows
  if (table.rows.length === 0) {
    const header = document.createElement('tr');
    header.innerHTML = `<th>Device</th><th>Description</th><th>Time</th>`;
    table.appendChild(header);
  } else {
    while (table.rows.length > 1) table.deleteRow(1);
  }

  // Add alarm rows
  let hasAlarm = false;
  data.Devices?.forEach(dev => {
    dev.LinkQuality?.Alarms?.forEach(a => {
      if (!a) return;
      hasAlarm = true;
      const row = document.createElement('tr');
      row.innerHTML = `<td>${dev.MAC}</td><td>Link Quality Alarm</td><td>${a}</td>`;
      table.appendChild(row);
    });
  });

  // Update alarm dot safely
  const dot = document.getElementById('alarmDot');
  if (dot) dot.style.visibility = hasAlarm ? 'visible' : 'hidden';

  // Restore scroll
  table.scrollTop = scrollTop;
}
let multiChartDiv = null;
let aggregateChartDiv = null;

// Static non-connected clients with default negative scores
const staticDevices = [
  { MAC: '92:AC:1E:22:AD:01', defaultScore: -0.3 },
  { MAC: '94:AB:1C:13:25:AD', defaultScore: -0.15 },
  { MAC: '12:BD:1B:12:7F:BC', defaultScore: -0.1 }
];

// Pastel colors for static clients
const STATIC_COLORS = ['#a3c1ad', '#f7c59f', '#c1aed6'];

// Generate negative scores for static clients
function generateStaticScores(timeAxis) {
  return staticDevices.map((d, idx) => {
    const scores = timeAxis.map(() => {
      // Small random negative variation around default score
      let val = d.defaultScore + (Math.random() - 0.5) * 0.05;
      return Math.min(0, Math.max(-1, val)); // clamp between -1 and 0
    });
    return {
      MAC: d.MAC + ' (Unassoc_clients)',
      Score: scores,
      isStatic: true,
      color: STATIC_COLORS[idx % STATIC_COLORS.length]
    };
  });
}

export function renderConnectionAffinityCharts(data) {
  const multiContainer = document.getElementById('affinityMultiContainer');
  const aggregateDiv = document.getElementById('affinityAggregateChart');
  if (!multiContainer || !aggregateDiv || !data) return;

  const COLORS = ['#5caee9','#f7a761','#2ca02c','#d62728','#9467bd','#8c564b','#e377c2','#7f7f7f'];

  // ---------------- STEP 1: Build global time axis ----------------
  const connectedDevices = (data.Devices || [])
    .filter(d => d.ConnectionAffinity);
  if (connectedDevices.length === 0) return;

  // Global time axis from all connected devices
  const timeSet = new Set();
  connectedDevices.forEach(d => d.ConnectionAffinity.Time.forEach(t => timeSet.add(t)));
  const timeAxis = Array.from(timeSet).sort((a,b) => a - b);

  // ---------------- STEP 2: Generate static unassoc clients ----------------
  const staticClients = generateStaticScores(timeAxis);

  // ---------------- STEP 3: Build all devices aligned to global timeAxis ----------------
  const allDevices = [
    ...connectedDevices.map((d, idx) => {
      // Align scores to global timeAxis
      const alignedScore = timeAxis.map(t => {
        const i = d.ConnectionAffinity.Time.indexOf(t);
        return i !== -1 ? d.ConnectionAffinity.Score[i] : null; // missing → null
      });
      return {
        MAC: d.MAC,
        Score: alignedScore,
        isStatic: false,
        color: COLORS[idx % COLORS.length]
      };
    }),
    ...staticClients
  ];

  // ---------------- STEP 4: Multi client bar chart ----------------
  const barTraces = allDevices.map(d => ({
    x: timeAxis,
    y: d.Score,
    type: 'bar',
    name: d.MAC,
    marker: { color: d.color }
  }));

  if (!multiChartDiv) {
    multiChartDiv = document.createElement('div');
    multiChartDiv.style.height = '420px';
    multiChartDiv.style.width = '100%';
    multiContainer.appendChild(multiChartDiv);
  }

  Plotly.react(multiChartDiv, barTraces, {
    title: { text: '<b>Connection Affinity — Clients Score</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time' , tickangle: -45 },
    yaxis: { title: 'Score', range: [-1, 1], tick0: -1, dtick: 0.2 },
    barmode: 'group',
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });

  // ---------------- STEP 5: Aggregate line chart ----------------
  const aggregateValues = timeAxis.map((_, i) => {
    let sum = 0, count = 0;
    allDevices.forEach(d => {
      const val = d.Score[i];
      if (val !== null && val !== undefined) {
        sum += val;
        count++;
      }
    });
    return count ? sum / count : 0;
  });

  if (!aggregateChartDiv) {
    aggregateChartDiv = document.createElement('div');
    aggregateChartDiv.style.height = '420px';
    aggregateChartDiv.style.width = '100%';
    aggregateDiv.appendChild(aggregateChartDiv);
  }

  Plotly.react(aggregateChartDiv, [{
    x: timeAxis,
    y: aggregateValues,
    type: 'scatter',
    mode: 'lines',
    name: 'Aggregate',
    line: { color: '#d87c7c', width: 3 }
  }], {
    title: { text: '<b>Connection Affinity — Aggregate Score</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45  },
    yaxis: { title: 'Score', range: [-1, 100], tick0: -1, dtick: 2 },
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });
}

// --------------------
// Render CAffinityScore Charts (Bar Graph)
// --------------------
let caffinityMultiChartDiv = null;
let caffinityAggregateChartDiv = null;

export function renderCAffinityScoreCharts(data) {
  const multiContainer = document.getElementById('caffinityMultiContainer');
  const aggregateDiv = document.getElementById('caffinityAggregateChart');
  if (!multiContainer || !aggregateDiv || !data) return;

  const COLORS = ['#8fc5ec','#eca466','#65d665','#ea7373','#9467bd','#8c564b','#e377c2','#7f7f7f','#bcbd22','#17becf'];

  // Get devices from ConnectedClients array with CAffinityScore data
  const devicesWithScores = (data.ConnectedClients || [])
    .filter(d => d.CAffinityScore && d.CAffinityScore.Score && d.CAffinityScore.Score.length > 0);

  if (devicesWithScores.length === 0) {
    // Clear charts if no data
    if (caffinityMultiChartDiv) caffinityMultiChartDiv.innerHTML = '<p style="text-align:center;color:#666;padding:40px;">No caffinity score data available yet.</p>';
    if (caffinityAggregateChartDiv) caffinityAggregateChartDiv.innerHTML = '';
    return;
  }

  // Build global time axis from all devices
  const timeSet = new Set();
  devicesWithScores.forEach(d => {
    if (d.CAffinityScore.Time) {
      d.CAffinityScore.Time.forEach(t => timeSet.add(t));
    }
  });
  const timeAxis = Array.from(timeSet).sort((a, b) => a - b);

  // Align scores to global timeAxis for each device
  const allDevices = devicesWithScores.map((d, idx) => {
    const alignedScore = timeAxis.map(t => {
      const i = d.CAffinityScore.Time.indexOf(t);
      return i !== -1 ? d.CAffinityScore.Score[i] : null;
    });
    return {
      MAC: d.MAC,
      Score: alignedScore,
      color: COLORS[idx % COLORS.length]
    };
  });

  // Multi client bar chart
  const barTraces = allDevices.map(d => ({
    x: timeAxis,
    y: d.Score,
    type: 'bar',
    name: d.MAC,
    marker: { color: d.color }
  }));

  if (!caffinityMultiChartDiv) {
    caffinityMultiChartDiv = document.createElement('div');
    caffinityMultiChartDiv.style.height = '420px';
    caffinityMultiChartDiv.style.width = '100%';
    multiContainer.appendChild(caffinityMultiChartDiv);
  }

  Plotly.react(caffinityMultiChartDiv, barTraces, {
    title: { text: '<b>Connection Affinity Score — Clients Score</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'Score', range: [0, 1], tick0: 0, dtick: 0.1 },
    barmode: 'group',
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });

  // Aggregate line chart
  const aggregateValues = timeAxis.map((_, i) => {
    let sum = 0, count = 0;
    allDevices.forEach(d => {
      const val = d.Score[i];
      if (val !== null && val !== undefined) {
        sum += val;
        count++;
      }
    });
    return count ? sum / count : 0;
  });

  if (!caffinityAggregateChartDiv) {
    caffinityAggregateChartDiv = document.createElement('div');
    caffinityAggregateChartDiv.style.height = '420px';
    caffinityAggregateChartDiv.style.width = '100%';
    aggregateDiv.appendChild(caffinityAggregateChartDiv);
  }

  Plotly.react(caffinityAggregateChartDiv, [{
    x: timeAxis,
    y: aggregateValues,
    type: 'scatter',
    mode: 'lines',
    name: 'Aggregate',
    line: { color: '#541e1e', width: 3 }
  }], {
    title: { text: '<b>Connection Affinity Score — Aggregate Score</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'Score', range: [0, 1], tick0: 0, dtick: 0.1 },
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });
}

// --------------------
// Render Unconnected Clients Charts
// --------------------
let unconnectedMultiChartDiv = null;
let unconnectedAggregateChartDiv = null;

export function renderUnconnectedClientsCharts(data) {
  const multiContainer = document.getElementById('unconnectedMultiContainer');
  const aggregateDiv = document.getElementById('unconnectedAggregateChart');
  if (!multiContainer || !aggregateDiv || !data) return;

  const COLORS = ['#b85454','#7fc9d3','#c36e83','#d9bd71','#b28d3d','#4edf94','#3d30b6','#00d2d3'];

  // Get devices from UnconnectedClients array with CAffinityScore data
  const devicesWithScores = (data.UnconnectedClients || [])
    .filter(d => d.CAffinityScore && d.CAffinityScore.Score && d.CAffinityScore.Score.length > 0);

  if (devicesWithScores.length === 0) {
    // Clear charts if no data
    if (unconnectedMultiChartDiv) unconnectedMultiChartDiv.innerHTML = '<p style="text-align:center;color:#666;padding:40px;">No unconnected client data available yet.</p>';
    if (unconnectedAggregateChartDiv) unconnectedAggregateChartDiv.innerHTML = '';
    return;
  }

  // Build global time axis from all devices
  const timeSet = new Set();
  devicesWithScores.forEach(d => {
    if (d.CAffinityScore.Time) {
      d.CAffinityScore.Time.forEach(t => timeSet.add(t));
    }
  });
  const timeAxis = Array.from(timeSet).sort((a, b) => a - b);

  // Align scores to global timeAxis for each device
  const allDevices = devicesWithScores.map((d, idx) => {
    const alignedScore = timeAxis.map(t => {
      const i = d.CAffinityScore.Time.indexOf(t);
      return i !== -1 ? d.CAffinityScore.Score[i] : null;
    });
    return {
      MAC: d.MAC,
      Score: alignedScore,
      LastSeen: d.LastSeen || 'Unknown',
      color: COLORS[idx % COLORS.length]
    };
  });

  // Multi client bar chart
  const barTraces = allDevices.map(d => ({
    x: timeAxis,
    y: d.Score,
    type: 'bar',
    name: `${d.MAC} (Last: ${d.LastSeen})`,
    marker: { color: d.color }
  }));

  if (!unconnectedMultiChartDiv) {
    unconnectedMultiChartDiv = document.createElement('div');
    unconnectedMultiChartDiv.style.height = '420px';
    unconnectedMultiChartDiv.style.width = '100%';
    multiContainer.appendChild(unconnectedMultiChartDiv);
  }

  Plotly.react(unconnectedMultiChartDiv, barTraces, {
    title: { text: '<b>Unconnected Clients — Caffinity Scores</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'Score', range: [0, 10], tick0: 0, dtick: 2 },
    barmode: 'group',
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 80 }
  }, { responsive: true });

  // Aggregate line chart
  const aggregateValues = timeAxis.map((_, i) => {
    let sum = 0, count = 0;
    allDevices.forEach(d => {
      const val = d.Score[i];
      if (val !== null && val !== undefined) {
        sum += val;
        count++;
      }
    });
    return count ? sum / count : 0;
  });

  if (!unconnectedAggregateChartDiv) {
    unconnectedAggregateChartDiv = document.createElement('div');
    unconnectedAggregateChartDiv.style.height = '420px';
    unconnectedAggregateChartDiv.style.width = '100%';
    aggregateDiv.appendChild(unconnectedAggregateChartDiv);
  }

  Plotly.react(unconnectedAggregateChartDiv, [{
    x: timeAxis,
    y: aggregateValues,
    type: 'scatter',
    mode: 'lines',
    name: 'Aggregate',
    line: { color: '#712bd3', width: 3 }
  }], {
    title: { text: '<b>Unconnected Clients — Aggregate Caffinity Score</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'Score', range: [0, 50], tick0: 0, dtick: 2 },
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });
}

// --------------------
// Render RMS Connected Aggregate Chart
// --------------------
let rmsConnectedChartDiv = null;

export function renderRMSConnectedChart(data) {
  const container = document.getElementById('rmsConnectedChart');
  if (!container || !data) return;

  // Get RMS_score data from caffinity telemetry
  const rmsData = data.RMS_score;
  if (!rmsData || !rmsData.connected || rmsData.connected.length === 0) {
    if (!rmsConnectedChartDiv) {
      rmsConnectedChartDiv = document.createElement('div');
      rmsConnectedChartDiv.style.height = '420px';
      rmsConnectedChartDiv.style.width = '100%';
      container.appendChild(rmsConnectedChartDiv);
    }
    rmsConnectedChartDiv.innerHTML = '<p style="text-align:center;color:#666;padding:40px;">No RMS connected data available yet.</p>';
    return;
  }

  const timeAxis = rmsData.Time || rmsData.connected.map((_, i) => `T${i}`);
  const connectedScores = rmsData.connected;

  if (!rmsConnectedChartDiv) {
    rmsConnectedChartDiv = document.createElement('div');
    rmsConnectedChartDiv.style.height = '420px';
    rmsConnectedChartDiv.style.width = '100%';
    container.appendChild(rmsConnectedChartDiv);
  }

  Plotly.react(rmsConnectedChartDiv, [{
    x: timeAxis,
    y: connectedScores,
    type: 'scatter',
    mode: 'lines+markers',
    name: 'RMS Connected',
    line: { color: '#2ecc71', width: 3 },
    marker: { size: 6 }
  }], {
    title: { text: '<b>RMS Aggregate — Connected Clients</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'RMS Score', range: [0, 50], tick0: 0, dtick: 2 },
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });
}

// --------------------
// Render RMS Unconnected Aggregate Chart
// --------------------
let rmsUnconnectedChartDiv = null;

export function renderRMSUnconnectedChart(data) {
  const container = document.getElementById('rmsUnconnectedChart');
  if (!container || !data) return;

  // Get RMS_score data from caffinity telemetry
  const rmsData = data.RMS_score;
  if (!rmsData || !rmsData.unconnected || rmsData.unconnected.length === 0) {
    if (!rmsUnconnectedChartDiv) {
      rmsUnconnectedChartDiv = document.createElement('div');
      rmsUnconnectedChartDiv.style.height = '420px';
      rmsUnconnectedChartDiv.style.width = '100%';
      container.appendChild(rmsUnconnectedChartDiv);
    }
    rmsUnconnectedChartDiv.innerHTML = '<p style="text-align:center;color:#666;padding:40px;">No RMS unconnected data available yet.</p>';
    return;
  }

  const timeAxis = rmsData.Time || rmsData.unconnected.map((_, i) => `T${i}`);
  const unconnectedScores = rmsData.unconnected;

  if (!rmsUnconnectedChartDiv) {
    rmsUnconnectedChartDiv = document.createElement('div');
    rmsUnconnectedChartDiv.style.height = '420px';
    rmsUnconnectedChartDiv.style.width = '100%';
    container.appendChild(rmsUnconnectedChartDiv);
  }

  Plotly.react(rmsUnconnectedChartDiv, [{
    x: timeAxis,
    y: unconnectedScores,
    type: 'scatter',
    mode: 'lines+markers',
    name: 'RMS Unconnected',
    line: { color: '#e74c3c', width: 3 },
    marker: { size: 6 }
  }], {
    title: { text: '<b>RMS Aggregate — Unconnected Clients</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'RMS Score', range: [0, 50], tick0: 0, dtick: 2 },
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });
}

// --------------------
// Render RMS Link Quality Aggregate Chart
// --------------------
let rmsLinkQualityChartDiv = null;

export function renderRMSLinkQualityChart(data) {
  const container = document.getElementById('rmsLinkQualityChart');
  if (!container || !data) return;

  // Get RMS_lq_score data from telemetry
  const rmsData = data.RMS_lq_score;
  if (!rmsData || !rmsData.Score || rmsData.Score.length === 0) {
    if (!rmsLinkQualityChartDiv) {
      rmsLinkQualityChartDiv = document.createElement('div');
      rmsLinkQualityChartDiv.style.height = '420px';
      rmsLinkQualityChartDiv.style.width = '100%';
      container.appendChild(rmsLinkQualityChartDiv);
    }
    rmsLinkQualityChartDiv.innerHTML = '<p style="text-align:center;color:#666;padding:40px;">No RMS Link Quality data available yet.</p>';
    return;
  }

  const timeAxis = rmsData.Time || rmsData.Score.map((_, i) => `T${i}`);
  const scores = rmsData.Score;

  if (!rmsLinkQualityChartDiv) {
    rmsLinkQualityChartDiv = document.createElement('div');
    rmsLinkQualityChartDiv.style.height = '420px';
    rmsLinkQualityChartDiv.style.width = '100%';
    container.appendChild(rmsLinkQualityChartDiv);
  }

  Plotly.react(rmsLinkQualityChartDiv, [{
    x: timeAxis,
    y: scores,
    type: 'scatter',
    mode: 'lines+markers',
    name: 'RMS Link Quality',
    line: { color: '#00f7ff', width: 3 },
    marker: { size: 6 }
  }], {
    title: { text: '<b>RMS Aggregate — Link Quality Score</b>', x: 0.5, xanchor: 'center' },
    xaxis: { title: 'Time', tickangle: -45 },
    yaxis: { title: 'RMS Score', range: [0, 50], tick0: 0, dtick: 2 },
    height: 420,
    margin: { t: 80, l: 60, r: 60, b: 60 }
  }, { responsive: true });
}
