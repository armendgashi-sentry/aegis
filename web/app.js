// === AEGIS DASHBOARD ===

const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/api/live`;

let events = [];
let currentFilter = 'all';
let eventCount = 0;
let allowedCount = 0;
let deniedCount = 0;
let lastSecondCount = 0;
let rpsInterval = null;
let liveSearchQuery = '';
let livePage = 0;
const PAGE_SIZE = 1000;

// DOM elements
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const statTotal = document.getElementById('stat-total');
const statAllowed = document.getElementById('stat-allowed');
const statDenied = document.getElementById('stat-denied');
const statRps = document.getElementById('stat-rps');
const eventsBody = document.getElementById('events-body');
const eventCountEl = document.getElementById('event-count');

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    renderEvents();
  });
});

// Live search
const liveSearchInput = document.getElementById('live-search');
let liveSearchTimer = null;
liveSearchInput.addEventListener('input', () => {
  clearTimeout(liveSearchTimer);
  liveSearchTimer = setTimeout(() => {
    liveSearchQuery = liveSearchInput.value.trim().toLowerCase();
    livePage = 0;
    renderEvents();
  }, 150);
});

// WebSocket connection
function connect() {
  const ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    statusDot.className = 'status-dot connected';
    statusText.textContent = 'ONLINE';
  };

  ws.onclose = () => {
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'DISCONNECTED';
    // Reconnect after 3s
    setTimeout(connect, 3000);
  };

  ws.onerror = () => {
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'ERROR';
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === 'event') {
        handleEvent(msg.data);
      }
    } catch (err) {
      console.error('Failed to parse message:', err);
    }
  };
}

function handleEvent(entry) {
  events.unshift(entry);
  if (events.length > 500) events.pop();

  eventCount++;
  lastSecondCount++;
  if (entry.decision === 'allow') allowedCount++;
  else if (entry.decision === 'deny') deniedCount++;

  // Update stats (only if viewing live feed)
  if (currentMode === 'live') {
    statTotal.textContent = eventCount;
    statAllowed.textContent = allowedCount;
    statDenied.textContent = deniedCount;
  }
  eventCountEl.textContent = `${eventCount} events`;

  renderNewEvent(entry);
}

function renderEvents() {
  const filtered = filterEvents();
  const total = filtered.length;
  const start = livePage * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, total);
  const page = filtered.slice(start, end);

  if (page.length === 0) {
    eventsBody.innerHTML = `
      <div class="empty-state">
        <p>NO EVENTS${currentFilter !== 'all' ? ` (${currentFilter.toUpperCase()})` : ''}${liveSearchQuery ? ` matching "${escapeHtml(liveSearchQuery)}"` : ''}</p>
        <p class="blink">_</p>
      </div>`;
    document.getElementById('live-pagination').style.display = 'none';
    return;
  }

  eventsBody.innerHTML = '';
  page.forEach(entry => {
    eventsBody.appendChild(createEventRow(entry));
  });

  renderPagination('live-pagination', total, livePage, (p) => { livePage = p; renderEvents(); });
}

function renderNewEvent(entry) {
  if (currentFilter !== 'all') {
    const decision = entry.decision === 'allow' ? 'allow' : 'deny';
    if (currentFilter !== decision) return;
  }

  // Remove empty state if present
  const emptyState = eventsBody.querySelector('.empty-state');
  if (emptyState) emptyState.remove();

  const row = createEventRow(entry);
  eventsBody.insertBefore(row, eventsBody.firstChild);

  // Keep max 200 visible rows
  while (eventsBody.children.length > 200) {
    eventsBody.removeChild(eventsBody.lastChild);
  }
}

let expandedEntry = null;
let expandedRow = null;

function createEventRow(entry) {
  const row = document.createElement('div');
  row.className = 'event-row';

  const time = new Date(entry.timestamp).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });

  const isAllow = entry.decision === 'allow';
  const decisionClass = isAllow ? 'decision-allow' : 'decision-deny';
  const decisionText = isAllow ? 'ALLOW' : 'BLOCK';

  // Truncate URL for display
  let displayUrl = entry.url || '';
  if (displayUrl.length > 60) {
    displayUrl = displayUrl.substring(0, 57) + '...';
  }

  row.innerHTML = `
    <span class="col-time">${time}</span>
    <span class="col-decision ${decisionClass}">${decisionText}</span>
    <span class="col-method">${entry.method || '-'}</span>
    <span class="col-url" title="${escapeHtml(entry.url || '')}">${escapeHtml(displayUrl)}</span>
    <span class="col-source">${escapeHtml(entry.source || '-')}</span>
    <span class="col-reason" title="${escapeHtml(entry.reason || '')}">${escapeHtml(entry.reason || '-')}</span>
  `;

  row.addEventListener('click', () => toggleDetail(entry, row));

  return row;
}

function toggleDetail(entry, row) {
  // Remove existing detail panel
  const existing = document.querySelector('.detail-panel');
  if (existing) existing.remove();

  // Deselect previous row
  if (expandedRow) expandedRow.classList.remove('selected');

  // If clicking the same row, just close
  if (expandedEntry === entry) {
    expandedEntry = null;
    expandedRow = null;
    return;
  }

  expandedEntry = entry;
  expandedRow = row;
  row.classList.add('selected');

  const isAllow = entry.decision === 'allow';
  const decisionClass = isAllow ? 'detail-allow' : 'detail-deny';
  const decisionText = isAllow ? 'ALLOW' : 'BLOCK';
  const reasonClass = isAllow ? 'reason-allow' : 'reason-deny';

  const timestamp = new Date(entry.timestamp).toLocaleString('en-US', {
    hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    fractionalSecondDigits: 3
  });

  // Extract blocked pattern from reason for highlighting
  const blockedPattern = extractBlockedPattern(entry.reason || '');

  // Build raw HTTP request display
  let requestHtml = '';
  const methodHighlight = (!isAllow && !blockedPattern && entry.source === 'builtin:http');
  const methodSpan = methodHighlight
    ? `<span class="highlight-blocked">${escapeHtml(entry.method)}</span>`
    : `<span class="detail-value method">${escapeHtml(entry.method)}</span>`;

  requestHtml += `<div class="request-line">${methodSpan} <span class="detail-value">${escapeHtml(entry.url || '')}</span></div>`;

  // Headers
  if (entry.headers && Object.keys(entry.headers).length > 0) {
    const sortedKeys = Object.keys(entry.headers).sort();
    requestHtml += '<div class="request-headers">';
    for (const key of sortedKeys) {
      requestHtml += `<div class="request-header-line"><span class="header-key">${escapeHtml(key)}:</span> <span class="header-val">${escapeHtml(entry.headers[key])}</span></div>`;
    }
    requestHtml += '</div>';
  }

  // Body with highlighting
  if (entry.body) {
    let bodyHtml;
    if (blockedPattern) {
      bodyHtml = highlightPattern(escapeHtml(entry.body), escapeHtml(blockedPattern));
    } else {
      bodyHtml = escapeHtml(entry.body);
    }
    requestHtml += `<div class="request-body-section"><div class="request-body-label">Body</div><pre class="request-body">${bodyHtml}</pre></div>`;
  }

  // Build secrets section if secrets were injected
  let secretsHtml = '';
  if (entry.secrets_applied && entry.secrets_applied.length > 0) {
    secretsHtml = `
      <div class="secrets-section">
        <div class="secrets-label">SECRETS INJECTED</div>
        <div class="secrets-table">
          <div class="secrets-header-row">
            <span class="secrets-col-hdr">RULE</span>
            <span class="secrets-col-hdr">HEADER (BEFORE)</span>
            <span class="secrets-col-hdr">HEADER (AFTER)</span>
          </div>
          ${entry.secrets_applied.map(s => {
            const beforeVal = entry.headers ? (entry.headers[s.header] || '(not set)') : '(not set)';
            return `
              <div class="secrets-row">
                <span class="secrets-col rule">${escapeHtml(s.rule_name)}</span>
                <span class="secrets-col before">${escapeHtml(s.header)}: ${escapeHtml(beforeVal)}</span>
                <span class="secrets-col after">${escapeHtml(s.header)}: <span class="secret-masked">${escapeHtml(s.masked_value)}</span></span>
              </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  // Build response section
  let responseHtml = '';
  if (entry.response_status) {
    const statusCode = entry.response_status;
    const statusClass = statusCode < 300 ? 'status-2xx' : statusCode < 400 ? 'status-3xx' : statusCode < 500 ? 'status-4xx' : 'status-5xx';

    let respHeadersHtml = '';
    if (entry.response_headers && Object.keys(entry.response_headers).length > 0) {
      const sortedKeys = Object.keys(entry.response_headers).sort();
      respHeadersHtml = '<div class="request-headers">';
      for (const key of sortedKeys) {
        respHeadersHtml += `<div class="request-header-line"><span class="header-key">${escapeHtml(key)}:</span> <span class="header-val">${escapeHtml(entry.response_headers[key])}</span></div>`;
      }
      respHeadersHtml += '</div>';
    }

    let respBodyHtml = '';
    if (entry.response_body) {
      respBodyHtml = `<div class="request-body-section"><div class="request-body-label">Body</div><pre class="request-body">${escapeHtml(entry.response_body)}</pre></div>`;
    }

    responseHtml = `
      <div class="response-display">
        <div class="response-status-line">
          <span class="response-label">RESPONSE</span>
          <span class="response-status ${statusClass}">${statusCode}</span>
        </div>
        ${respHeadersHtml}
        ${respBodyHtml}
      </div>`;
  }

  const panel = document.createElement('div');
  panel.className = `detail-panel ${decisionClass}`;
  panel.innerHTML = `
    <div class="detail-header">
      <span class="detail-title ${decisionClass}">// REQUEST DETAIL — ${decisionText}</span>
      <div class="detail-actions">
        <button class="detail-replay-btn" id="replay-btn">▶ REPLAY</button>
        <button class="detail-replay-btn edit" id="edit-replay-btn">✎ EDIT & REPLAY</button>
        <button class="detail-close" onclick="closeDetail()">✕ CLOSE</button>
      </div>
    </div>
    <div class="request-display">${requestHtml}</div>
    <div class="replay-editor" id="replay-editor" style="display:none;">
      <div class="replay-editor-title">// EDIT REQUEST</div>
      <div class="replay-editor-row">
        <label>METHOD</label>
        <select id="replay-method" class="config-input replay-input-sm">
          ${['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(m =>
            `<option value="${m}" ${m === entry.method ? 'selected' : ''}>${m}</option>`
          ).join('')}
        </select>
      </div>
      <div class="replay-editor-row">
        <label>URL</label>
        <input type="text" id="replay-url" class="config-input" value="${escapeAttr(entry.url || '')}" />
      </div>
      <div class="replay-editor-row">
        <label>HEADERS</label>
        <textarea id="replay-headers" class="config-input replay-textarea" rows="4">${escapeHtml(
          Object.entries(entry.headers || {})
            .filter(([k]) => k.toLowerCase() !== 'proxy-connection' && k.toLowerCase() !== 'host')
            .map(([k, v]) => `${k}: ${v}`).join('\n')
        )}</textarea>
      </div>
      <div class="replay-editor-row">
        <label>BODY</label>
        <textarea id="replay-body" class="config-input replay-textarea" rows="3">${escapeHtml(entry.body || '')}</textarea>
      </div>
      <div class="config-form-actions">
        <button class="detail-replay-btn" id="send-edited-replay">▶ SEND</button>
        <button class="filter-btn" id="cancel-edit-replay">CANCEL</button>
      </div>
    </div>
    ${secretsHtml}
    ${responseHtml}
    ${entry.reason ? `<div class="detail-reason ${reasonClass}">${escapeHtml(entry.reason)}</div>` : ''}
    <div class="detail-grid detail-meta">
      <span class="detail-label">Source</span>
      <span class="detail-value source">${escapeHtml(entry.source || '-')}</span>
      <span class="detail-label">Layer</span>
      <span class="detail-value">${escapeHtml(entry.layer || '-')}</span>
      <span class="detail-label">Timestamp</span>
      <span class="detail-value dim">${timestamp}</span>
      <span class="detail-label">ID</span>
      <span class="detail-value dim">${escapeHtml(entry.id || '-')}</span>
    </div>
  `;

  row.after(panel);

  // Wire up replay button (sends original as-is)
  panel.querySelector('#replay-btn').addEventListener('click', () => replayRequest(entry));

  // Wire up edit & replay
  const editor = panel.querySelector('#replay-editor');
  panel.querySelector('#edit-replay-btn').addEventListener('click', () => {
    editor.style.display = editor.style.display === 'none' ? '' : 'none';
  });
  panel.querySelector('#cancel-edit-replay').addEventListener('click', () => {
    editor.style.display = 'none';
  });
  panel.querySelector('#send-edited-replay').addEventListener('click', () => {
    const method = panel.querySelector('#replay-method').value;
    const url = panel.querySelector('#replay-url').value;
    const headersText = panel.querySelector('#replay-headers').value;
    const body = panel.querySelector('#replay-body').value || null;

    // Parse headers from "Key: Value" lines
    const headers = {};
    headersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        headers[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
      }
    });

    replayRequest({ method, url, headers, body });
    editor.style.display = 'none';
  });
}

function extractBlockedPattern(reason) {
  for (const prefix of ['pattern: ', 'payload: ']) {
    const idx = reason.indexOf(prefix);
    if (idx !== -1) {
      const pattern = reason.substring(idx + prefix.length).trim();
      if (pattern) return pattern;
    }
  }
  return null;
}

function highlightPattern(text, pattern) {
  if (!pattern) return text;
  // Case-insensitive replace, wrapping matches in highlight span
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`(${escaped})`, 'gi');
  return text.replace(regex, '<span class="highlight-blocked">$1</span>');
}

function closeDetail() {
  const existing = document.querySelector('.detail-panel');
  if (existing) existing.remove();
  if (expandedRow) expandedRow.classList.remove('selected');
  expandedEntry = null;
  expandedRow = null;
}

function filterEvents() {
  let filtered = events;
  if (currentFilter !== 'all') {
    filtered = filtered.filter(e => {
      if (currentFilter === 'allow') return e.decision === 'allow';
      if (currentFilter === 'deny') return e.decision === 'deny';
      return true;
    });
  }
  if (liveSearchQuery) {
    filtered = filtered.filter(e => matchesSearch(e, liveSearchQuery));
  }
  return filtered;
}

function matchesSearch(entry, query) {
  return (entry.url || '').toLowerCase().includes(query)
    || (entry.method || '').toLowerCase().includes(query)
    || (entry.reason || '').toLowerCase().includes(query)
    || (entry.source || '').toLowerCase().includes(query)
    || (entry.host || '').toLowerCase().includes(query)
    || (entry.body || '').toLowerCase().includes(query);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Pagination renderer
function renderPagination(containerId, total, currentPage, onPageChange) {
  const container = document.getElementById(containerId);
  const totalPages = Math.ceil(total / PAGE_SIZE);

  if (totalPages <= 1) {
    container.style.display = 'none';
    return;
  }

  container.style.display = '';
  const start = currentPage * PAGE_SIZE + 1;
  const end = Math.min((currentPage + 1) * PAGE_SIZE, total);

  let html = `<span class="page-info">${start}-${end} of ${total}</span>`;
  html += `<button class="page-btn" ${currentPage === 0 ? 'disabled' : ''} data-page="prev">◂ PREV</button>`;

  // Show max 7 page buttons
  const maxBtns = 7;
  let pageStart = Math.max(0, currentPage - 3);
  let pageEnd = Math.min(totalPages, pageStart + maxBtns);
  if (pageEnd - pageStart < maxBtns) pageStart = Math.max(0, pageEnd - maxBtns);

  for (let i = pageStart; i < pageEnd; i++) {
    html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i + 1}</button>`;
  }

  html += `<button class="page-btn" ${currentPage >= totalPages - 1 ? 'disabled' : ''} data-page="next">NEXT ▸</button>`;
  container.innerHTML = html;

  container.querySelectorAll('.page-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = btn.dataset.page;
      if (p === 'prev') onPageChange(currentPage - 1);
      else if (p === 'next') onPageChange(currentPage + 1);
      else onPageChange(parseInt(p));
    });
  });
}

// Replay request
async function replayRequest(entry) {
  const payload = {
    method: entry.method,
    url: entry.url,
    headers: entry.headers || {},
    body: entry.body || null,
  };

  try {
    const resp = await fetch(`${API_BASE}/api/replay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();

    // The replayed request is logged and will appear via WebSocket
    // Show a brief notification
    showNotification(
      data.decision === 'allow'
        ? `Replay: ${data.response?.status || 'sent'} — ALLOW`
        : `Replay: BLOCKED — ${data.reason}`
    );
  } catch (e) {
    showNotification(`Replay failed: ${e.message}`);
  }
}

function showNotification(msg) {
  let el = document.getElementById('notification');
  if (!el) {
    el = document.createElement('div');
    el.id = 'notification';
    el.className = 'notification';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.display = '';
  el.style.opacity = '1';
  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => { el.style.display = 'none'; }, 300);
  }, 3000);
}

// RPS counter
rpsInterval = setInterval(() => {
  statRps.textContent = lastSecondCount;
  lastSecondCount = 0;
}, 1000);

// Fetch stats from API (used by logs mode, not live feed)
async function fetchStats() {
  try {
    const resp = await fetch(`${API_BASE}/api/stats`);
    return await resp.json();
  } catch (e) {
    return null;
  }
}

// === MODE TABS (LIVE / LOGS) ===

let currentMode = 'live';
let logFilter = 'all';
let logEntries = [];
let logSearchQuery = '';
let logPage = 0;
let logTotalEntries = 0;
let currentLogFile = '';

document.querySelectorAll('.mode-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentMode = btn.dataset.mode;

    document.getElementById('live-section').style.display = currentMode === 'live' ? '' : 'none';
    document.getElementById('logs-section').style.display = currentMode === 'logs' ? '' : 'none';
    document.getElementById('config-section').style.display = currentMode === 'config' ? '' : 'none';

    if (currentMode === 'live') {
      // Restore live session stats to main cards
      statTotal.textContent = eventCount;
      statAllowed.textContent = allowedCount;
      statDenied.textContent = deniedCount;
      statRps.textContent = lastSecondCount;
    } else if (currentMode === 'logs') {
      fetchLogFiles();
    } else if (currentMode === 'config') {
      fetchConfig();
    }
  });
});

// === LOGS TAB ===

const logFileSelect = document.getElementById('log-file-select');
const logEventsBody = document.getElementById('log-events-body');
const logStats = document.getElementById('log-stats');

// Log filter buttons — trigger server-side re-fetch
document.querySelectorAll('[data-log-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-log-filter]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    logFilter = btn.dataset.logFilter;
    logPage = 0;
    if (currentLogFile) fetchLogEntries(currentLogFile);
  });
});

logFileSelect.addEventListener('change', () => {
  const file = logFileSelect.value;
  if (file) {
    currentLogFile = file;
    logPage = 0;
    logSearchQuery = '';
    document.getElementById('log-search').value = '';
    fetchLogEntries(file);
  }
});

// Log search
const logSearchInput = document.getElementById('log-search');
let logSearchTimer = null;
logSearchInput.addEventListener('input', () => {
  clearTimeout(logSearchTimer);
  logSearchTimer = setTimeout(() => {
    logSearchQuery = logSearchInput.value.trim();
    logPage = 0;
    if (currentLogFile) fetchLogEntries(currentLogFile);
  }, 300);
});

async function fetchLogFiles() {
  try {
    const resp = await fetch(`${API_BASE}/api/logs`);
    const data = await resp.json();
    logFileSelect.innerHTML = '<option value="">SELECT LOG FILE...</option>';
    (data.logs || []).forEach(log => {
      const opt = document.createElement('option');
      opt.value = log.path;
      const sizeKb = (log.size / 1024).toFixed(1);
      opt.textContent = `${log.name} (${sizeKb} KB)`;
      logFileSelect.appendChild(opt);
    });
  } catch (e) {
    console.error('Failed to fetch log files:', e);
  }
}

async function fetchLogEntries(file) {
  try {
    logEventsBody.innerHTML = `
      <div class="empty-state">
        <p>LOADING...</p>
        <p class="blink">_</p>
      </div>`;

    const offset = logPage * PAGE_SIZE;
    let url = `${API_BASE}/api/logs/entries?file=${encodeURIComponent(file)}&limit=${PAGE_SIZE}&offset=${offset}`;
    if (logFilter !== 'all') url += `&decision=${logFilter}`;
    if (logSearchQuery) url += `&search=${encodeURIComponent(logSearchQuery)}`;

    const resp = await fetch(url);
    const data = await resp.json();

    if (data.error) {
      logEventsBody.innerHTML = `
        <div class="empty-state">
          <p>ERROR: ${escapeHtml(data.error)}</p>
        </div>`;
      return;
    }

    logEntries = data.entries || [];
    logTotalEntries = data.stats?.total || logEntries.length;

    // Update log stats (inline + main stat cards)
    if (data.stats) {
      logStats.style.display = '';
      document.getElementById('log-stat-total').textContent = data.stats.total || 0;
      document.getElementById('log-stat-allowed').textContent = data.stats.allowed || 0;
      document.getElementById('log-stat-denied').textContent = data.stats.denied || 0;
      statTotal.textContent = data.stats.total || 0;
      statAllowed.textContent = data.stats.allowed || 0;
      statDenied.textContent = data.stats.denied || 0;
    }

    renderLogEntries();

    // Pagination for logs (server-side)
    renderPagination('log-pagination', logTotalEntries, logPage, (p) => {
      logPage = p;
      fetchLogEntries(currentLogFile);
    });
  } catch (e) {
    console.error('Failed to fetch log entries:', e);
    logEventsBody.innerHTML = `
      <div class="empty-state">
        <p>FAILED TO LOAD LOG</p>
      </div>`;
  }
}

function renderLogEntries() {
  if (logEntries.length === 0) {
    logEventsBody.innerHTML = `
      <div class="empty-state">
        <p>NO ENTRIES${logFilter !== 'all' ? ` (${logFilter.toUpperCase()})` : ''}${logSearchQuery ? ` matching "${escapeHtml(logSearchQuery)}"` : ''}</p>
        <p class="blink">_</p>
      </div>`;
    return;
  }

  logEventsBody.innerHTML = '';
  logEntries.forEach(entry => {
    logEventsBody.appendChild(createEventRow(entry));
  });
}

// === CONFIG TAB ===

let currentConfig = null;

async function fetchConfig() {
  try {
    const [configResp, presetsResp] = await Promise.all([
      fetch(`${API_BASE}/api/config`),
      fetch(`${API_BASE}/api/config/presets`),
    ]);
    const config = await configResp.json();
    const presets = await presetsResp.json();
    currentConfig = config;
    renderConfig(config, presets);
  } catch (e) {
    console.error('Failed to fetch config:', e);
  }
}

function renderConfig(config, presets) {
  // Presets dropdown
  const presetSelect = document.getElementById('preset-select');
  presetSelect.innerHTML = '<option value="">SELECT PRESET...</option>';
  (presets.presets || []).forEach(p => {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p.toUpperCase();
    if (p === presets.active) opt.selected = true;
    presetSelect.appendChild(opt);
  });

  // Active preset badge
  const badge = document.getElementById('active-preset-badge');
  badge.textContent = config.preset ? config.preset.toUpperCase() : '';

  // HTTP policy
  const policy = config.policy || {};
  const http = policy.http || {};
  const methods = http.methods || {};
  const payload = http.payload || {};
  document.getElementById('http-safe').textContent = (methods.safe || []).join(', ') || '-';
  document.getElementById('http-inspect').textContent = (methods.inspect || []).join(', ') || '-';
  document.getElementById('http-block').textContent = (methods.block || []).join(', ') || '-';
  document.getElementById('http-block-sql').textContent = (payload.block_sql || []).join(', ') || '-';
  document.getElementById('http-allow-sql').textContent = (payload.allow_sql || []).join(', ') || '-';
  document.getElementById('http-block-cmds').textContent = (payload.block_commands || []).join(', ') || '-';
  document.getElementById('http-max-body').textContent = http.max_request_body != null ? `${http.max_request_body} bytes` : '-';

  // Shell policy
  const shell = policy.shell || {};
  document.getElementById('shell-patterns').textContent = (shell.block_patterns || []).join(', ') || '-';
  document.getElementById('shell-sql').textContent = shell.block_sql_in_cli ? 'BLOCKED' : 'ALLOWED';
  document.getElementById('shell-sql').className = 'config-value ' + (shell.block_sql_in_cli ? 'enabled' : 'disabled');

  // Rate limit
  const rl = policy.rate_limit || {};
  document.getElementById('rl-rps').textContent = rl.requests_per_second != null ? rl.requests_per_second : '-';
  document.getElementById('rl-burst').textContent = rl.burst != null ? rl.burst : '-';
  document.getElementById('rl-per-target').textContent = rl.per_target ? 'YES' : 'NO';
  document.getElementById('rl-per-target').className = 'config-value ' + (rl.per_target ? 'enabled' : '');

  // Secrets
  const secrets = config.secrets || {};
  const secretsList = document.getElementById('secrets-list');
  const rules = secrets.rules || [];
  if (rules.length === 0) {
    secretsList.innerHTML = '<div class="empty-state" style="padding:20px"><p>NO SECRETS CONFIGURED</p></div>';
  } else {
    secretsList.innerHTML = rules.map(r => `
      <div class="secret-item">
        <div class="secret-info">
          <span class="secret-name">${escapeHtml(r.name)}</span>
          <span class="secret-detail">${escapeHtml(r.match_host || '*')}${r.match_path_prefix ? r.match_path_prefix : ''} → ${escapeHtml(r.header)}</span>
        </div>
        <button class="secret-remove-btn" onclick="removeSecret('${escapeHtml(r.name)}')">DEL</button>
      </div>
    `).join('');
  }
}

// Edit toggle
document.querySelectorAll('.config-edit-btn[data-section]').forEach(btn => {
  btn.addEventListener('click', () => {
    const section = btn.dataset.section;
    toggleEdit(section);
  });
});

function toggleEdit(section) {
  const display = document.getElementById(`${section}-display`);
  const form = document.getElementById(`${section}-form`);
  if (!display || !form) return;

  const isEditing = form.style.display !== 'none';
  if (isEditing) {
    cancelEdit(section);
  } else {
    display.style.display = 'none';
    form.style.display = '';
    populateEditForm(section);
  }
}

function cancelEdit(section) {
  document.getElementById(`${section}-display`).style.display = '';
  document.getElementById(`${section}-form`).style.display = 'none';
}

function populateEditForm(section) {
  if (!currentConfig) return;
  const policy = currentConfig.policy || {};

  if (section === 'http') {
    const http = policy.http || {};
    const methods = http.methods || {};
    const payload = http.payload || {};
    document.getElementById('http-safe-input').value = (methods.safe || []).join(', ');
    document.getElementById('http-inspect-input').value = (methods.inspect || []).join(', ');
    document.getElementById('http-block-input').value = (methods.block || []).join(', ');
    document.getElementById('http-block-sql-input').value = (payload.block_sql || []).join(', ');
    document.getElementById('http-allow-sql-input').value = (payload.allow_sql || []).join(', ');
    document.getElementById('http-block-cmds-input').value = (payload.block_commands || []).join(', ');
    document.getElementById('http-max-body-input').value = http.max_request_body || '';
  } else if (section === 'shell') {
    const shell = policy.shell || {};
    document.getElementById('shell-patterns-input').value = (shell.block_patterns || []).join(', ');
    document.getElementById('shell-sql-input').value = shell.block_sql_in_cli ? 'true' : 'false';
  } else if (section === 'rate-limit') {
    const rl = policy.rate_limit || {};
    document.getElementById('rl-rps-input').value = rl.requests_per_second || '';
    document.getElementById('rl-burst-input').value = rl.burst || '';
    document.getElementById('rl-per-target-input').value = rl.per_target ? 'true' : 'false';
  }
}

function parseList(val) {
  return val.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

async function saveHttpPolicy() {
  if (!currentConfig) return;
  const policy = JSON.parse(JSON.stringify(currentConfig.policy || {}));
  policy.http = policy.http || {};
  policy.http.methods = policy.http.methods || {};
  policy.http.payload = policy.http.payload || {};
  policy.http.methods.safe = parseList(document.getElementById('http-safe-input').value);
  policy.http.methods.inspect = parseList(document.getElementById('http-inspect-input').value);
  policy.http.methods.block = parseList(document.getElementById('http-block-input').value);
  policy.http.payload.block_sql = parseList(document.getElementById('http-block-sql-input').value);
  policy.http.payload.allow_sql = parseList(document.getElementById('http-allow-sql-input').value);
  policy.http.payload.block_commands = parseList(document.getElementById('http-block-cmds-input').value);
  const maxBody = parseInt(document.getElementById('http-max-body-input').value);
  policy.http.max_request_body = isNaN(maxBody) ? 0 : maxBody;

  try {
    const resp = await fetch(`${API_BASE}/api/config/policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    const data = await resp.json();
    if (data.ok) {
      cancelEdit('http');
      fetchConfig();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to save: ' + e.message);
  }
}

async function saveShellPolicy() {
  if (!currentConfig) return;
  const policy = JSON.parse(JSON.stringify(currentConfig.policy || {}));
  policy.shell = policy.shell || {};
  policy.shell.block_patterns = parseList(document.getElementById('shell-patterns-input').value);
  policy.shell.block_sql_in_cli = document.getElementById('shell-sql-input').value === 'true';

  try {
    const resp = await fetch(`${API_BASE}/api/config/policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    const data = await resp.json();
    if (data.ok) {
      cancelEdit('shell');
      fetchConfig();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to save: ' + e.message);
  }
}

async function saveRateLimit() {
  const rps = parseInt(document.getElementById('rl-rps-input').value);
  const burst = parseInt(document.getElementById('rl-burst-input').value);
  const perTarget = document.getElementById('rl-per-target-input').value === 'true';

  if (isNaN(rps) || isNaN(burst)) {
    alert('RPS and Burst must be numbers');
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/config/rate-limit`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests_per_second: rps, burst: burst, per_target: perTarget }),
    });
    const data = await resp.json();
    if (data.ok) {
      cancelEdit('rate-limit');
      fetchConfig();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to save: ' + e.message);
  }
}

// Secrets
document.getElementById('add-secret-btn').addEventListener('click', () => {
  const form = document.getElementById('secret-add-form');
  form.style.display = form.style.display === 'none' ? '' : 'none';
});

function cancelSecretAdd() {
  document.getElementById('secret-add-form').style.display = 'none';
  document.getElementById('secret-name-input').value = '';
  document.getElementById('secret-host-input').value = '';
  document.getElementById('secret-path-input').value = '';
  document.getElementById('secret-header-input').value = '';
  document.getElementById('secret-value-input').value = '';
}

async function saveSecret() {
  const name = document.getElementById('secret-name-input').value.trim();
  const host = document.getElementById('secret-host-input').value.trim();
  const path = document.getElementById('secret-path-input').value.trim();
  const header = document.getElementById('secret-header-input').value.trim();
  const value = document.getElementById('secret-value-input').value;

  if (!name || !host || !header || !value) {
    alert('Name, Host, Header, and Value are required');
    return;
  }

  const rule = {
    name: name,
    match_host: host,
    header: header,
    value: value,
  };
  if (path) rule.match_path_prefix = path;

  try {
    const resp = await fetch(`${API_BASE}/api/config/secrets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    const data = await resp.json();
    if (data.ok) {
      cancelSecretAdd();
      fetchConfig();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to save: ' + e.message);
  }
}

async function removeSecret(name) {
  if (!confirm(`Remove secret "${name}"?`)) return;

  try {
    const resp = await fetch(`${API_BASE}/api/config/secrets/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
    const data = await resp.json();
    if (data.ok) {
      fetchConfig();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to remove: ' + e.message);
  }
}

// Preset apply
document.getElementById('apply-preset-btn').addEventListener('click', async () => {
  const preset = document.getElementById('preset-select').value;
  if (!preset) {
    alert('Select a preset first');
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/config/presets/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset: preset }),
    });
    const data = await resp.json();
    if (data.ok) {
      fetchConfig();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to apply preset: ' + e.message);
  }
});

// Initialize — live feed starts at 0, counts only new WebSocket events
connect();
