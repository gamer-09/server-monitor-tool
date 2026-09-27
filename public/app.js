'use strict';

(function () {
  const els = {
    tableBody: null,
    selectAll: null,
    refresh: null,
    killSelected: null,
    killPort: null,
    port: null,
    status: null,
    token: null,
    toggleToken: null,
    saveToken: null,
    clearToken: null,
  };

  const state = {
    servers: [],
    selected: new Set(),
    token: '',
  };

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    els.tableBody = document.querySelector('#table tbody');
    els.selectAll = document.querySelector('#selectAll');
    els.refresh = document.querySelector('#refresh');
    els.killSelected = document.querySelector('#killSelected');
    els.killPort = document.querySelector('#killPort');
    els.port = document.querySelector('#port');
    els.status = document.querySelector('#status');
    els.token = document.querySelector('#token');
    els.toggleToken = document.querySelector('#toggleToken');
    els.saveToken = document.querySelector('#saveToken');
    els.clearToken = document.querySelector('#clearToken');

    // Restore token
    const saved = localStorage.getItem('adminToken') || '';
    if (saved) {
      state.token = saved;
      els.token.value = saved;
    }

    els.selectAll.addEventListener('change', onSelectAll);
    els.refresh.addEventListener('click', () => loadServers());
    els.killSelected.addEventListener('click', onKillSelected);
    els.killPort.addEventListener('click', onKillPort);
    els.toggleToken.addEventListener('click', () => toggleTokenVisibility());
    els.saveToken.addEventListener('click', () => saveToken());
    els.clearToken.addEventListener('click', () => clearToken());

    loadServers();
  }

  function toggleTokenVisibility() {
    if (els.token.type === 'password') {
      els.token.type = 'text';
      els.toggleToken.textContent = 'Hide';
    } else {
      els.token.type = 'password';
      els.toggleToken.textContent = 'Show';
    }
  }

  function saveToken() {
    const val = (els.token.value || '').trim();
    state.token = val;
    if (val) localStorage.setItem('adminToken', val);
    else localStorage.removeItem('adminToken');
    setStatus(val ? 'Token saved.' : 'Token cleared.', 'success');
  }

  function clearToken() {
    els.token.value = '';
    state.token = '';
    localStorage.removeItem('adminToken');
    setStatus('Token cleared.', 'success');
  }

  async function apiFetch(path, options = {}) {
    const headers = options.headers || {};
    if (options.method && options.method.toUpperCase() !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }
    const token = (state.token || (els.token && els.token.value) || '').trim();
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(path, {
      ...options,
      headers,
    });
    const text = await resp.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { raw: text }; }
    if (!resp.ok) {
      const msg = (data && (data.error || data.message)) || `HTTP ${resp.status}`;
      throw new Error(msg);
    }
    return data;
  }

  async function loadServers() {
    try {
      setStatus('Loading servers...', 'info');
      const data = await apiFetch('/servers');
      state.servers = Array.isArray(data.items) ? data.items : [];
      state.selected.clear();
      els.selectAll.checked = false;
      renderTable();
      setStatus(`Loaded ${state.servers.length} listening endpoints.`, 'success');
    } catch (e) {
      setStatus(`Failed to load: ${e.message}`, 'error');
    }
  }

  function renderTable() {
    const rows = state.servers.map((s, idx) => {
      const id = `row_${idx}_${s.pid}_${s.localPort}`;
      const label = (s.label || 'clean').toLowerCase();
      const labelText = label.charAt(0).toUpperCase() + label.slice(1);
      const reasons = Array.isArray(s.reasons) && s.reasons.length ? `Reasons: ${s.reasons.join('; ')}` : 'No issues detected';
      const badgeClass = label === 'virus' ? 'badge virus' : (label === 'suspicious' ? 'badge suspicious' : 'badge clean');
      return `
        <tr>
          <td><input type="checkbox" class="rowcb" data-pid="${s.pid}" id="${id}"></td>
          <td title="${escapeHtml(s.process || '')}"><span class="name">${escapeHtml(s.name || s.process || '')}</span></td>
          <td>${s.pid}</td>
          <td>${s.protocol || ''}</td>
          <td>${s.localAddress || ''}</td>
          <td>${s.localPort}</td>
          <td><span class="${badgeClass}" title="${escapeHtml(reasons)}">${labelText}</span></td>
          <td><button class="mini danger" data-action="kill" data-pid="${s.pid}">Kill</button></td>
        </tr>
      `;
    }).join('');
    els.tableBody.innerHTML = rows || '<tr><td colspan="8" class="muted">No listening endpoints found.</td></tr>';

    // Bind events
    els.tableBody.querySelectorAll('.rowcb').forEach((cb) => {
      cb.addEventListener('change', (ev) => {
        const pid = Number(ev.target.getAttribute('data-pid'));
        if (ev.target.checked) state.selected.add(pid); else state.selected.delete(pid);
      });
    });
    els.tableBody.querySelectorAll('button[data-action="kill"]').forEach((btn) => {
      btn.addEventListener('click', async (ev) => {
        const pid = Number(ev.target.getAttribute('data-pid'));
        if (!Number.isFinite(pid)) return;
        if (!confirm(`Kill process PID ${pid}?`)) return;
        await killByPids([pid]);
      });
    });
  }

  function onSelectAll(ev) {
    const checked = !!ev.target.checked;
    state.selected.clear();
    els.tableBody.querySelectorAll('.rowcb').forEach((cb) => {
      cb.checked = checked;
      const pid = Number(cb.getAttribute('data-pid'));
      if (checked) state.selected.add(pid);
    });
  }

  async function onKillSelected() {
    const pids = Array.from(state.selected.values());
    if (!pids.length) {
      setStatus('No rows selected.', 'info');
      return;
    }
    if (!confirm(`Kill ${pids.length} process(es)?`)) return;
    await killByPids(pids);
  }

  async function killByPids(pids) {
    try {
      setStatus('Killing processes...', 'info');
      const data = await apiFetch('/servers/kill', {
        method: 'POST',
        body: JSON.stringify({ pid: pids }),
      });
      const msg = `Killed: ${data.killed?.join(', ') || 'none'}${data.failed?.length ? `; Failed: ${data.failed.map(f => `${f.pid} (${f.error || 'error'})`).join(', ')}` : ''}`;
      setStatus(msg, data.failed?.length ? 'warn' : 'success');
      await loadServers();
    } catch (e) {
      setStatus(`Kill failed: ${e.message}`, 'error');
    }
  }

  async function onKillPort() {
    const val = Number(els.port.value);
    if (!Number.isFinite(val) || val <= 0) {
      setStatus('Enter a valid port number.', 'info');
      return;
    }
    if (!confirm(`Kill all processes listening on port ${val}?`)) return;
    try {
      setStatus('Killing by port...', 'info');
      const data = await apiFetch('/servers/kill', {
        method: 'POST',
        body: JSON.stringify({ port: val }),
      });
      const msg = `Killed: ${data.killed?.join(', ') || 'none'}${data.failed?.length ? `; Failed: ${data.failed.map(f => `${f.pid} (${f.error || 'error'})`).join(', ')}` : ''}`;
      setStatus(msg, data.failed?.length ? 'warn' : 'success');
      await loadServers();
    } catch (e) {
      setStatus(`Kill by port failed: ${e.message}`, 'error');
    }
  }

  function setStatus(message, type) {
    els.status.textContent = message;
    els.status.className = `status ${type || ''}`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }
})();
