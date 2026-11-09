/**
 * Centralized Security Log Monitoring & Alert System (SentinelSIEM)
 * Frontend Application Core Logic
 */

let currentTab = 'dashboard';
let currentRole = 'analyst';
let currentAlertModalId = null;
let currentIncidentModalId = null;
let logPageOffset = 0;
const logPageLimit = 50;

// Chart references
let chartSeverityInstance = null;
let chartTopIpsInstance = null;
let chartTopUsersInstance = null;

// Initializer
document.addEventListener('DOMContentLoaded', () => {
  updateClock();
  setInterval(updateClock, 1000);

  // Initial Data Loads
  loadDashboardData();
  loadRulesList();

  // Periodic polling every 6 seconds for live monitoring
  setInterval(() => {
    if (currentTab === 'dashboard') {
      loadDashboardData();
    }
  }, 6000);
});

// Live UTC Clock
function updateClock() {
  const clockEl = document.getElementById('liveClock');
  if (clockEl) {
    const now = new Date();
    clockEl.innerText = now.toUTCString().slice(17, 25) + ' UTC';
  }
}

// Role Switcher
function switchRole(role) {
  currentRole = role;
  console.log(`[AUTH] Switched view to role: ${role}`);
  
  // IT Support or Network Admin view adjustments
  const rulesTabBtn = document.getElementById('tabBtn-rules');
  if (role === 'itsupport') {
    if (rulesTabBtn) rulesTabBtn.style.opacity = '0.5';
  } else {
    if (rulesTabBtn) rulesTabBtn.style.opacity = '1';
  }
}

// Tab Navigation
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.nav-tab').forEach(el => {
    el.style.borderBottomColor = 'transparent';
    el.style.color = '#9ca3af';
  });

  const targetContent = document.getElementById(`tab-${tabId}`);
  const targetBtn = document.getElementById(`tabBtn-${tabId}`);
  if (targetContent) targetContent.style.display = 'block';
  if (targetBtn) {
    targetBtn.style.borderBottomColor = '#3b82f6';
    targetBtn.style.color = '#f9fafb';
  }

  // Refresh data based on selected tab
  if (tabId === 'dashboard') loadDashboardData();
  else if (tabId === 'alerts') loadAlertsList();
  else if (tabId === 'incidents') loadIncidentsList();
  else if (tabId === 'logs') executeLogSearch();
  else if (tabId === 'rules') loadRulesList();
  else if (tabId === 'reports') loadExecutiveReport();
}

// ---------------- DASHBOARD & TELEMETRY ----------------

async function loadDashboardData() {
  try {
    const res = await fetch('/api/logs/stats');
    if (!res.ok) return;
    const stats = await res.json();

    // Update KPI Counters
    document.getElementById('statTotalEvents').innerText = Number(stats.total_events).toLocaleString();
    document.getElementById('statActiveAlerts').innerText = stats.active_alerts;
    document.getElementById('statCriticalAlerts').innerText = `${stats.alerts_by_severity.CRITICAL || 0} Critical`;
    document.getElementById('statHighAlerts').innerText = `${stats.alerts_by_severity.HIGH || 0} High`;
    document.getElementById('statOpenIncidents').innerText = stats.open_incidents;

    // Update tab alert badge
    const alertBadge = document.getElementById('tabAlertCount');
    if (stats.active_alerts > 0) {
      alertBadge.innerText = stats.active_alerts;
      alertBadge.style.display = 'inline-block';
    } else {
      alertBadge.style.display = 'none';
    }

    // Threat Posture calculation
    const threatBadge = document.getElementById('threatLevelBadge');
    const threatDetail = document.getElementById('threatLevelDetail');
    if (stats.alerts_by_severity.CRITICAL > 0) {
      threatBadge.className = 'badge badge-critical';
      threatBadge.innerText = 'DEFCON 1 / CRITICAL INTRUSION';
      threatDetail.innerText = 'Immediate action required: active compromised accounts or privilege abuse!';
    } else if (stats.alerts_by_severity.HIGH > 0) {
      threatBadge.className = 'badge badge-high';
      threatBadge.innerText = 'DEFCON 2 / ELEVATED ATTACK';
      threatDetail.innerText = 'Active brute force or repetitive access violations detected.';
    } else if (stats.alerts_by_severity.MEDIUM > 0) {
      threatBadge.className = 'badge badge-medium';
      threatBadge.innerText = 'DEFCON 3 / ADVISORY';
      threatDetail.innerText = 'Reconnaissance or volumetric spikes detected.';
    } else {
      threatBadge.className = 'badge badge-info';
      threatBadge.innerText = 'DEFCON 5 / NORMAL';
      threatDetail.innerText = 'No critical intrusions detected across authorized hosts.';
    }

    // Render Charts
    renderSeverityChart(stats.alerts_by_severity);
    renderTopIpsChart(stats.top_ips);
    renderTopUsersChart(stats.top_users);

    // Populate Dashboard Recent Alerts Table
    populateDashboardAlerts(stats.recent_alerts);

  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

function renderSeverityChart(sevData) {
  const ctx = document.getElementById('chartSeverity');
  if (!ctx || typeof Chart === 'undefined') return;

  const data = [
    sevData.CRITICAL || 0,
    sevData.HIGH || 0,
    sevData.MEDIUM || 0,
    sevData.LOW || 0
  ];

  if (chartSeverityInstance) {
    chartSeverityInstance.data.datasets[0].data = data;
    chartSeverityInstance.update();
  } else {
    chartSeverityInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: data,
          backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
          borderWidth: 2,
          borderColor: '#111827'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 11 } } }
        }
      }
    });
  }
}

function renderTopIpsChart(topIps) {
  const ctx = document.getElementById('chartTopIps');
  if (!ctx || typeof Chart === 'undefined') return;

  const labels = topIps.map(x => x.source_ip);
  const values = topIps.map(x => x.count);

  if (chartTopIpsInstance) {
    chartTopIpsInstance.data.labels = labels;
    chartTopIpsInstance.data.datasets[0].data = values;
    chartTopIpsInstance.update();
  } else {
    chartTopIpsInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Events Count',
          data: values,
          backgroundColor: '#3b82f6',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
          y: { ticks: { color: '#9ca3af' }, grid: { display: false } }
        }
      }
    });
  }
}

function renderTopUsersChart(topUsers) {
  const ctx = document.getElementById('chartTopUsers');
  if (!ctx || typeof Chart === 'undefined') return;

  const labels = topUsers.map(x => x.username || 'unknown');
  const values = topUsers.map(x => x.count);

  if (chartTopUsersInstance) {
    chartTopUsersInstance.data.labels = labels;
    chartTopUsersInstance.data.datasets[0].data = values;
    chartTopUsersInstance.update();
  } else {
    chartTopUsersInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Activity Count',
          data: values,
          backgroundColor: '#06b6d4',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#9ca3af' }, grid: { display: false } },
          y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
        }
      }
    });
  }
}

function populateDashboardAlerts(alerts) {
  const tbody = document.getElementById('dashboardAlertsTbody');
  if (!tbody) return;

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #6b7280; padding: 24px;">No alerts generated yet. Trigger an attack scenario from the Simulation Lab to test detection rules!</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
      <td style="font-family: monospace; color: #38bdf8;">${a.rule_code}</td>
      <td style="font-weight: 500;">
        <div>${escapeHtml(a.title)}</div>
        <div style="font-size: 0.75rem; color: #9ca3af;">${escapeHtml(a.description).slice(0, 80)}...</div>
      </td>
      <td><code>${a.source_ip || a.hostname || 'N/A'}</code></td>
      <td><code>${a.username || 'N/A'}</code></td>
      <td><span class="badge badge-info">${a.matched_events_count}</span></td>
      <td style="font-size: 0.75rem; color: #9ca3af;">${formatTime(a.last_event_time)}</td>
      <td><span class="badge ${getStatusBadgeClass(a.status)}">${a.status}</span></td>
      <td>
        <button class="btn-secondary" style="font-size: 0.75rem; padding: 4px 8px;" onclick="openAlertModal(${a.id})">🔍 Investigate</button>
      </td>
    </tr>
  `).join('');
}

// ---------------- ALERTS CENTER ----------------

async function loadAlertsList() {
  const status = document.getElementById('alertFilterStatus')?.value || '';
  const severity = document.getElementById('alertFilterSeverity')?.value || '';
  const tbody = document.getElementById('alertsListTbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; color: #9ca3af; padding: 20px;">Fetching alerts...</td></tr>`;

  try {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);

    const res = await fetch(`/api/alerts?${params.toString()}`);
    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; color: #6b7280; padding: 24px;">No alerts match filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td>#${a.id}</td>
        <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td style="font-family: monospace; color: #38bdf8;">${a.rule_code}</td>
        <td>
          <div style="font-weight: 600;">${escapeHtml(a.title)}</div>
          <div style="font-size: 0.75rem; color: #9ca3af;">${escapeHtml(a.description).slice(0, 100)}...</div>
        </td>
        <td><code>${a.source_ip || 'N/A'}</code></td>
        <td>${a.hostname || 'N/A'}</td>
        <td><code>${a.username || 'N/A'}</code></td>
        <td><span class="badge badge-info">${a.matched_events_count}</span></td>
        <td style="font-size: 0.75rem; color: #9ca3af;">${formatTime(a.last_event_time)}</td>
        <td><span class="badge ${getStatusBadgeClass(a.status)}">${a.status}</span></td>
        <td>
          <div style="display: flex; gap: 4px;">
            <button class="btn-secondary" style="font-size: 0.75rem; padding: 4px 8px;" onclick="openAlertModal(${a.id})">Drilldown</button>
            <button class="btn-success" style="font-size: 0.75rem; padding: 4px 8px;" onclick="quickResolveAlert(${a.id})" title="Resolve">✓</button>
          </div>
        </td>
      </tr>
    `).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; color: #ef4444; padding: 20px;">Error loading alerts: ${err.message}</td></tr>`;
  }
}

async function openAlertModal(alertId) {
  currentAlertModalId = alertId;
  try {
    const res = await fetch(`/api/alerts/${alertId}`);
    if (!res.ok) return;
    const a = await res.json();

    document.getElementById('modalAlertSeverityBadge').innerText = a.severity;
    document.getElementById('modalAlertSeverityBadge').className = `badge badge-${a.severity.toLowerCase()}`;
    document.getElementById('modalAlertTitle').innerText = a.title;
    document.getElementById('modalAlertRule').innerText = `${a.rule_code} (${a.rule ? a.rule.name : ''})`;
    document.getElementById('modalAlertSourceIp').innerText = a.source_ip || 'N/A';
    document.getElementById('modalAlertHost').innerText = a.hostname || 'N/A';
    document.getElementById('modalAlertUser').innerText = a.username || 'N/A';
    document.getElementById('modalAlertCount').innerText = `${a.matched_events_count} events correlated`;
    document.getElementById('modalAlertTime').innerText = formatTime(a.last_event_time);
    document.getElementById('modalAlertDesc').innerText = a.description;

    // Correlated events table
    const evTbody = document.getElementById('modalAlertEventsTbody');
    if (a.events && a.events.length > 0) {
      evTbody.innerHTML = a.events.map(e => `
        <tr>
          <td style="white-space: nowrap;">${formatTime(e.timestamp)}</td>
          <td><code>${e.source_ip || '0.0.0.0'}</code></td>
          <td><code>${e.username || '-'}</code></td>
          <td><span class="badge badge-${e.severity.toLowerCase()}">${e.event_type}</span></td>
          <td>${e.action}</td>
          <td style="font-family: monospace; font-size: 0.75rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${escapeHtml(e.raw_log || e.message)}
          </td>
        </tr>
      `).join('');
    } else {
      evTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #6b7280;">No correlated log records found.</td></tr>`;
    }

    document.getElementById('alertDetailModal').style.display = 'flex';
  } catch (err) {
    alert('Failed to load alert details: ' + err.message);
  }
}

function closeAlertModal() {
  document.getElementById('alertDetailModal').style.display = 'none';
  currentAlertModalId = null;
}

async function updateAlertStatusFromModal(newStatus) {
  if (!currentAlertModalId) return;
  try {
    await fetch(`/api/alerts/${currentAlertModalId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    closeAlertModal();
    loadDashboardData();
    if (currentTab === 'alerts') loadAlertsList();
  } catch (err) {
    alert('Error updating alert status: ' + err.message);
  }
}

async function quickResolveAlert(alertId) {
  try {
    await fetch(`/api/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'RESOLVED' })
    });
    loadDashboardData();
    loadAlertsList();
  } catch (err) {
    alert('Error resolving alert: ' + err.message);
  }
}

async function escalateAlertToIncidentFromModal() {
  if (!currentAlertModalId) return;
  const title = prompt('Enter Incident Title:', `Incident for Alert #${currentAlertModalId}`);
  if (!title) return;

  try {
    const res = await fetch('/api/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: title,
        description: document.getElementById('modalAlertDesc').innerText,
        severity: document.getElementById('modalAlertSeverityBadge').innerText,
        assigned_to: 'Incident Response Lead',
        alert_ids: [currentAlertModalId]
      })
    });
    if (res.ok) {
      alert('Alert successfully escalated to Incident!');
      closeAlertModal();
      switchTab('incidents');
    }
  } catch (err) {
    alert('Failed to escalate: ' + err.message);
  }
}

// ---------------- INCIDENT MANAGEMENT ----------------

async function loadIncidentsList() {
  const tbody = document.getElementById('incidentsTbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #9ca3af; padding: 20px;">Fetching incidents...</td></tr>`;

  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();
    const incidents = data.incidents || [];

    if (incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #6b7280; padding: 24px;">No active security incidents recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents.map(inc => `
      <tr>
        <td style="font-family: monospace; font-weight: 600; color: #38bdf8;">${inc.incident_number}</td>
        <td><span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity}</span></td>
        <td style="font-weight: 600;">
          <div>${escapeHtml(inc.title)}</div>
          <div style="font-size: 0.75rem; color: #9ca3af;">${escapeHtml(inc.description || '').slice(0, 80)}...</div>
        </td>
        <td><span class="badge ${getIncidentStatusBadgeClass(inc.status)}">${inc.status}</span></td>
        <td>${escapeHtml(inc.assigned_to || 'Unassigned')}</td>
        <td><span class="badge badge-info">${inc.alert_count} Alerts</span></td>
        <td><span class="badge badge-low">${inc.note_count} Notes</span></td>
        <td style="font-size: 0.75rem; color: #9ca3af;">${formatTime(inc.created_at)}</td>
        <td>
          <button class="btn-secondary" style="font-size: 0.75rem; padding: 4px 10px;" onclick="openIncidentModal(${inc.id})">Open Case</button>
        </td>
      </tr>
    `).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #ef4444; padding: 20px;">Error loading incidents: ${err.message}</td></tr>`;
  }
}

async function openIncidentModal(incId) {
  currentIncidentModalId = incId;
  try {
    const res = await fetch(`/api/incidents/${incId}`);
    if (!res.ok) return;
    const inc = await res.json();

    document.getElementById('modalIncNumber').innerText = inc.incident_number;
    document.getElementById('modalIncTitle').innerText = inc.title;
    document.getElementById('modalIncSeverity').innerText = inc.severity;
    document.getElementById('modalIncSeverity').className = `badge badge-${inc.severity.toLowerCase()}`;
    document.getElementById('modalIncCreatedAt').innerText = formatTime(inc.created_at);
    document.getElementById('modalIncDesc').innerText = inc.description || 'No description provided.';
    document.getElementById('modalIncStatusSelect').value = inc.status;
    document.getElementById('modalIncAssigneeSelect').value = inc.assigned_to || 'Lead Analyst';

    // Populate notes
    const notesContainer = document.getElementById('modalIncNotesContainer');
    if (inc.notes && inc.notes.length > 0) {
      notesContainer.innerHTML = inc.notes.map(n => `
        <div style="border-left: 2px solid #3b82f6; padding-left: 8px; font-size: 0.8rem;">
          <div style="display: flex; justify-content: space-between; color: #9ca3af; font-size: 0.7rem;">
            <strong>${escapeHtml(n.author)}</strong>
            <span>${formatTime(n.created_at)}</span>
          </div>
          <div style="color: #e5e7eb; margin-top: 2px;">${escapeHtml(n.note)}</div>
        </div>
      `).join('');
    } else {
      notesContainer.innerHTML = `<div style="color: #6b7280; font-size: 0.8rem;">No analyst notes yet. Add initial assessment below.</div>`;
    }

    document.getElementById('incidentDetailModal').style.display = 'flex';
  } catch (err) {
    alert('Failed to load incident: ' + err.message);
  }
}

function closeIncidentModal() {
  document.getElementById('incidentDetailModal').style.display = 'none';
  currentIncidentModalId = null;
}

async function saveIncidentUpdates() {
  if (!currentIncidentModalId) return;
  const status = document.getElementById('modalIncStatusSelect').value;
  const assigned_to = document.getElementById('modalIncAssigneeSelect').value;

  try {
    await fetch(`/api/incidents/${currentIncidentModalId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, assigned_to })
    });
    loadIncidentsList();
    loadDashboardData();
  } catch (err) {
    console.error('Failed to update incident:', err);
  }
}

async function submitIncidentNote() {
  if (!currentIncidentModalId) return;
  const input = document.getElementById('modalIncNewNoteInput');
  const note = input.value.trim();
  if (!note) return;

  try {
    await fetch(`/api/incidents/${currentIncidentModalId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author: currentRole, note })
    });
    input.value = '';
    openIncidentModal(currentIncidentModalId); // reload notes
  } catch (err) {
    alert('Failed to add note: ' + err.message);
  }
}

async function openCreateIncidentModal() {
  const title = prompt('Enter Incident Title:');
  if (!title) return;
  const desc = prompt('Enter Incident Description:');

  try {
    const res = await fetch('/api/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        description: desc,
        severity: 'HIGH',
        assigned_to: 'Security Analyst'
      })
    });
    if (res.ok) {
      loadIncidentsList();
    }
  } catch (err) {
    alert('Error creating incident: ' + err.message);
  }
}

// ---------------- LOG EXPLORER ----------------

async function executeLogSearch() {
  const q = document.getElementById('logSearchQuery')?.value || '';
  const evType = document.getElementById('logFilterEventType')?.value || '';
  const sev = document.getElementById('logFilterSeverity')?.value || '';
  const tbody = document.getElementById('logsTableTbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: #9ca3af; padding: 20px;">Searching logs...</td></tr>`;

  try {
    const params = new URLSearchParams({
      limit: logPageLimit,
      offset: logPageOffset
    });
    if (q) params.append('q', q);
    if (evType) params.append('event_type', evType);
    if (sev) params.append('severity', sev);

    const res = await fetch(`/api/logs?${params.toString()}`);
    const data = await res.json();
    const events = data.events || [];
    const total = data.total || 0;

    // Update pagination controls
    const start = total === 0 ? 0 : logPageOffset + 1;
    const end = Math.min(logPageOffset + logPageLimit, total);
    document.getElementById('logPaginationInfo').innerText = `Showing ${start} to ${end} of ${total} events`;
    document.getElementById('btnPrevLogs').disabled = logPageOffset === 0;
    document.getElementById('btnNextLogs').disabled = end >= total;

    if (events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: #6b7280; padding: 24px;">No logs match your filter criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td>#${e.id}</td>
        <td style="white-space: nowrap; font-size: 0.75rem; color: #9ca3af;">${formatTime(e.timestamp)}</td>
        <td><code>${e.source_ip || '0.0.0.0'}</code></td>
        <td>${e.hostname || '-'}</td>
        <td><code>${e.username || '-'}</code></td>
        <td><span class="badge badge-info">${e.event_type}</span></td>
        <td>${e.action}</td>
        <td><span class="badge badge-${e.severity.toLowerCase()}">${e.severity}</span></td>
        <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(e.message)}">
          ${escapeHtml(e.message)}
        </td>
        <td>
          <button class="btn-secondary" style="font-size: 0.75rem; padding: 2px 6px;" onclick="inspectLogRecord(${e.id})">{ }</button>
        </td>
      </tr>
    `).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: #ef4444; padding: 20px;">Search failed: ${err.message}</td></tr>`;
  }
}

function changeLogPage(direction) {
  logPageOffset = Math.max(0, logPageOffset + (direction * logPageLimit));
  executeLogSearch();
}

function resetLogFilters() {
  document.getElementById('logSearchQuery').value = '';
  document.getElementById('logFilterEventType').value = '';
  document.getElementById('logFilterSeverity').value = '';
  logPageOffset = 0;
  executeLogSearch();
}

async function inspectLogRecord(eventId) {
  try {
    const res = await fetch(`/api/logs?q=${eventId}&limit=1`);
    const data = await res.json();
    if (data.events && data.events.length > 0) {
      const ev = data.events[0];
      document.getElementById('inspectContent').innerText = JSON.stringify(ev, null, 2);
      document.getElementById('logInspectModal').style.display = 'flex';
    }
  } catch (err) {
    alert('Inspection error: ' + err.message);
  }
}

function closeLogInspectModal() {
  document.getElementById('logInspectModal').style.display = 'none';
}

function exportLogsCsv() {
  window.location.href = '/api/export/logs';
}

function exportAlertsCsv() {
  window.location.href = '/api/export/alerts';
}

// ---------------- DETECTION RULES ----------------

async function loadRulesList() {
  const tbody = document.getElementById('rulesTableTbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const rules = data.rules || [];

    tbody.innerHTML = rules.map(r => `
      <tr>
        <td style="font-family: monospace; font-weight: 700; color: #38bdf8;">${r.rule_code}</td>
        <td style="font-weight: 600;">${escapeHtml(r.name)}</td>
        <td><span class="badge badge-${r.severity.toLowerCase()}">${r.severity}</span></td>
        <td>${r.window_seconds}s</td>
        <td>&ge; ${r.threshold_count}</td>
        <td style="font-size: 0.8rem; color: #9ca3af; max-width: 300px;">${escapeHtml(r.description)}</td>
        <td>
          <span class="badge ${r.enabled ? 'badge-info' : 'badge-low'}">
            ${r.enabled ? 'ACTIVE' : 'DISABLED'}
          </span>
        </td>
        <td>
          <button class="btn-${r.enabled ? 'secondary' : 'primary'}" style="font-size: 0.75rem; padding: 4px 8px;" onclick="toggleRule(${r.id}, ${r.enabled ? 0 : 1})">
            ${r.enabled ? 'Disable' : 'Enable'}
          </button>
        </td>
      </tr>
    `).join('');

  } catch (err) {
    console.error('Error loading rules:', err);
  }
}

async function toggleRule(ruleId, newStatus) {
  try {
    await fetch(`/api/rules/${ruleId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: newStatus === 1 })
    });
    loadRulesList();
  } catch (err) {
    alert('Failed to toggle rule: ' + err.message);
  }
}

// ---------------- ATTACK SIMULATOR ----------------

function openSimulatorModal() {
  switchTab('simulator');
}

async function triggerSimulator(scenario, intensity) {
  const consoleEl = document.getElementById('simulatorConsoleOutput');
  const timestamp = new Date().toLocaleTimeString();
  consoleEl.innerHTML += `\n[${timestamp}] [TRIGGER] Initiating scenario: '${scenario}' (intensity: ${intensity})...`;
  consoleEl.scrollTop = consoleEl.scrollHeight;

  try {
    const res = await fetch('/api/simulator/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario, intensity })
    });
    const result = await res.json();

    if (res.ok) {
      consoleEl.innerHTML += `\n[${timestamp}] [SUCCESS] ${result.title || scenario} executed: ${result.events_generated} events sent, ${result.alerts_triggered} alerts triggered!`;
      loadDashboardData();
    } else {
      consoleEl.innerHTML += `\n[${timestamp}] [ERROR] ${result.error || 'Execution failed'}`;
    }
  } catch (err) {
    consoleEl.innerHTML += `\n[${timestamp}] [EXCEPTION] ${err.message}`;
  }
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

async function confirmResetDatabase() {
  if (!confirm('Are you sure you want to reset all events, alerts, and incidents? This clears the test database for a clean demo run.')) {
    return;
  }
  try {
    const res = await fetch('/api/system/reset', { method: 'POST' });
    if (res.ok) {
      const consoleEl = document.getElementById('simulatorConsoleOutput');
      consoleEl.innerHTML += `\n[RESET] Test database cleared successfully.`;
      loadDashboardData();
      loadAlertsList();
      loadIncidentsList();
      alert('Database successfully reset!');
    }
  } catch (err) {
    alert('Error resetting database: ' + err.message);
  }
}

// ---------------- LOG INGESTION & SAMPLES ----------------

function openUploadModal() {
  document.getElementById('uploadModal').style.display = 'flex';
}

function closeUploadModal() {
  document.getElementById('uploadModal').style.display = 'none';
}

async function loadSampleLogIntoInput(filename) {
  try {
    // Standard samples pre-packaged
    let sampleContent = '';
    if (filename === 'auth_bruteforce.log') {
      sampleContent = `Nov 05 14:10:01 auth-gw sshd[14201]: Failed password for invalid user admin from 192.168.1.185 port 42101 ssh2\nNov 05 14:10:05 auth-gw sshd[14205]: Failed password for invalid user admin from 192.168.1.185 port 42102 ssh2\nNov 05 14:10:12 auth-gw sshd[14210]: Failed password for invalid user root from 192.168.1.185 port 42103 ssh2\nNov 05 14:10:18 auth-gw sshd[14215]: Failed password for invalid user sarah_admin from 192.168.1.185 port 42104 ssh2\nNov 05 14:10:25 auth-gw sshd[14220]: Failed password for invalid user sarah_admin from 192.168.1.185 port 42105 ssh2\nNov 05 14:10:32 auth-gw sshd[14225]: Failed password for invalid user sarah_admin from 192.168.1.185 port 42106 ssh2\nNov 05 14:10:45 auth-gw sshd[14230]: Accepted password for sarah_admin from 192.168.1.185 port 42107 ssh2`;
    } else {
      sampleContent = `192.168.1.92 - - [05/Nov/2026:14:15:01 +0000] "GET /api/v1/payroll/salaries HTTP/1.1" 403 241 "-" "CustomScanner/2.1"\n192.168.1.92 - - [05/Nov/2026:14:15:08 +0000] "GET /admin/database/backup.sql HTTP/1.1" 403 241 "-" "CustomScanner/2.1"\n192.168.1.92 - - [05/Nov/2026:14:15:15 +0000] "GET /etc/ssl/private/server.key HTTP/1.1" 403 241 "-" "CustomScanner/2.1"\n192.168.1.92 - - [05/Nov/2026:14:15:22 +0000] "GET /api/v2/internal/tokens HTTP/1.1" 403 241 "-" "CustomScanner/2.1"`;
    }
    document.getElementById('rawLogInputArea').value = sampleContent;
  } catch (err) {
    console.error('Error loading sample:', err);
  }
}

async function submitRawLogUpload() {
  const text = document.getElementById('rawLogInputArea').value.trim();
  if (!text) {
    alert('Please enter or paste log lines to ingest.');
    return;
  }

  try {
    const res = await fetch('/api/logs/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ raw_text: text })
    });
    const result = await res.json();

    if (res.ok) {
      alert(`Ingestion Successful!\n• ${result.lines_parsed} lines parsed\n• ${result.alerts_triggered} alerts triggered!`);
      closeUploadModal();
      loadDashboardData();
    } else {
      alert('Ingestion error: ' + (result.error || 'Failed'));
    }
  } catch (err) {
    alert('Network/API error: ' + err.message);
  }
}

// ---------------- EXECUTIVE REPORTS ----------------

async function loadExecutiveReport() {
  const container = document.getElementById('reportContainer');
  if (!container) return;

  container.innerHTML = '<p style="color: #9ca3af;">Generating executive security summary report...</p>';

  try {
    const res = await fetch('/api/reports/summary');
    const data = await res.json();
    const sum = data.summary;

    container.innerHTML = `
      <div style="background: #111827; border: 1px solid #374151; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
        <h4 style="font-size: 1.1rem; color: #f9fafb; margin-bottom: 8px;">${data.report_title}</h4>
        <div style="font-size: 0.75rem; color: #9ca3af; margin-bottom: 16px;">Timestamp: ${data.generated_at}</div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px;">
          <div style="background: #1f2937; padding: 12px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #9ca3af;">Total Events Analyzed</div>
            <div style="font-size: 1.4rem; font-weight: 700; color: #3b82f6;">${sum.total_events_analyzed}</div>
          </div>
          <div style="background: #1f2937; padding: 12px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #9ca3af;">Total Security Alerts</div>
            <div style="font-size: 1.4rem; font-weight: 700; color: #f97316;">${sum.security_alerts_generated}</div>
          </div>
          <div style="background: #1f2937; padding: 12px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #9ca3af;">Formal Incidents Recorded</div>
            <div style="font-size: 1.4rem; font-weight: 700; color: #ef4444;">${sum.formal_incidents_recorded}</div>
          </div>
        </div>

        <h5 style="color: #e5e7eb; margin: 16px 0 8px 0;">Strategic Remediation Recommendations:</h5>
        <ul style="color: #d1d5db; font-size: 0.85rem; padding-left: 20px; line-height: 1.6;">
          ${data.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<p style="color: #ef4444;">Failed to load report: ${err.message}</p>`;
  }
}

// ---------------- HELPERS ----------------

function formatTime(isoStr) {
  if (!isoStr) return '-';
  try {
    const d = new Date(isoStr);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  } catch {
    return isoStr;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getStatusBadgeClass(status) {
  switch (status) {
    case 'NEW': return 'badge-status-new';
    case 'ACKNOWLEDGED': return 'badge-status-ack';
    case 'RESOLVED': return 'badge-status-resolved';
    default: return 'badge-low';
  }
}

function getIncidentStatusBadgeClass(status) {
  switch (status) {
    case 'OPEN': return 'badge-critical';
    case 'INVESTIGATING': return 'badge-high';
    case 'CONTAINED': return 'badge-medium';
    case 'RESOLVED': return 'badge-info';
    case 'CLOSED': return 'badge-low';
    default: return 'badge-low';
  }
}
