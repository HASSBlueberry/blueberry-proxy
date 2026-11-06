/* Local, same-origin dashboard. No external fonts, scripts, or telemetry. */
(() => {
  const el = id => document.getElementById(id);
  const state = {stats: {}, events: [], maps: [], rules: [], uscan: {}, paused: false, busy: false};
  let socket, reconnect, poll, stopped = false, retry = 1000, rendering = false;
  const number = n => Number(n || 0).toLocaleString();
  const endpoint = path => new URL(path, document.baseURI);
  async function api(path, body) {
    const response = await fetch(endpoint(path), {method: body === undefined ? 'GET' : 'POST', headers: {'Content-Type': 'application/json'}, body: body === undefined ? undefined : JSON.stringify(body)});
    if (!response.ok) { let message = `Proxy returned HTTP ${response.status}`; try { message = (await response.json()).error || message; } catch (_) {} throw new Error(message); }
    return response.json();
  }
  function error(message) { el('error').textContent = message || ''; el('error').hidden = !message; }
  async function action(button, job) {
    button.disabled = true;
    try { const result = await job(); if (result?.results?.some(record => record.error)) throw new Error('Some blocklists could not be updated. Check their source URLs.'); error(''); await refresh(); } catch (err) { error(err.message); }
    finally { button.disabled = false; }
  }
  function button(text, click) { const b = document.createElement('button'); b.className = 'secondary'; b.textContent = text; b.addEventListener('click', () => action(b, click)); return b; }
  async function rule(domain, decision) {
    domain = domain.trim().toLowerCase().replace(/\.$/, '');
    if (domain.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) throw new Error('Enter a valid DNS domain name');
    await api('rules', {id: 'dashboard-' + domain, match_type: 'exact', match: domain, action: decision, priority: 100});
  }
  function ranking(id, records, field, decision) {
    const fragment = document.createDocumentFragment();
    for (const record of records || []) {
      const row = document.createElement('div'); row.className = 'rank';
      const name = document.createElement('span'); name.textContent = record[field];
      const count = document.createElement('span'); count.className = 'count'; count.textContent = number(record.queries);
      row.append(name, count);
      if (decision) row.append(button(decision === 'blackhole' ? 'Block' : 'Allow', () => rule(record.domain, decision)));
      fragment.append(row);
    }
    el(id).replaceChildren(fragment);
  }
  function renderStats(stats) {
    state.stats = stats;
    for (const id of ['queries', 'allowed', 'blocked', 'errors']) el(id).textContent = number(stats[id]);
    el('blocked-rate').textContent = `${stats.queries ? (100 * stats.blocked / stats.queries).toFixed(1) : 0}% of requests`;
    el('blocking').textContent = stats['blocking-enabled'] ? 'Pause blocking' : 'Resume blocking';
    el('protection').textContent = stats['blocking-enabled'] ? 'Blocklists and blocking rules are active' : 'Blocking is paused. DNS answers and proxy routing continue.';
    for (const key of ['entries', 'hits', 'misses']) el('cache-' + key).textContent = number(stats.cache?.[key]);
    el('limits').textContent = `${number(stats['tracked-domains'])} domains and ${number(stats['tracked-clients'])} clients tracked. Rankings stop admitting new names at the tracking limit; total counters continue.`;
    ranking('top-domains', stats['top-domains'], 'domain', 'blackhole');
    ranking('top-blocked', stats['top-blocked'], 'domain', 'passthrough');
    ranking('top-clients', stats['top-clients'], 'client');
  }
  function renderFlow() {
    rendering = false;
    if (state.paused) return;
    const filter = el('filter').value.toLowerCase(), kind = el('kind').value;
    const rows = document.createDocumentFragment();
    for (const event of state.events) {
      const dns = event.type === 'dns';
      if (kind === 'dns' && !dns || kind === 'blocked' && (!dns || !event.blocked) || kind === 'http' && !['request', 'response'].includes(event.type) || kind === 'discovery' && event.type !== 'discovery' || kind === 'scan' && event.type !== 'scan') continue;
      const values = [new Date(event.ts || Date.now()).toLocaleTimeString(), event.client || event.ip || event.map || event.scanner || 'proxy', event.qname || event.uri || event.hostname || event.ip || event.listener || 'HTTP response', event.action || `${event.method || event.type} ${event.status || ''}`];
      if (filter && !values.join(' ').toLowerCase().includes(filter)) continue;
      const row = document.createElement('tr');
      values.forEach((value, index) => { const cell = document.createElement('td'); if (index === 3) { const tag = document.createElement('span'); tag.className = 'decision' + (event.blocked ? ' blocked' : ''); tag.textContent = value; cell.append(tag); } else cell.textContent = value; row.append(cell); });
      rows.append(row);
    }
    el('flow').replaceChildren(rows);
  }
  function pushEvent(event) {
    if (!['dns', 'request', 'response', 'discovery', 'scan'].includes(event.type)) return;
    state.events.unshift(event); state.events.length = Math.min(250, state.events.length);
    if (!rendering) { rendering = true; setTimeout(renderFlow, 200); }
  }
  function renderManagement() {
    for (const [id, records] of [['maps', state.maps], ['rules', state.rules]]) {
      const fragment = document.createDocumentFragment();
      for (const record of records) {
        const row = document.createElement('div'); row.className = 'manage';
        const label = document.createElement('span');
        label.textContent = id === 'maps' ? `${record.host || '*'}${record.path || '/'} → ${record.target}` : `${typeof record.match === 'object' ? record.match.value : record.match} · ${record.action}`;
        const b = id === 'maps' ? button(record.enabled === false ? 'Enable' : 'Disable', () => api('proxy/maps', {...record, enabled: record.enabled === false})) : button('Remove', async () => { const r = await fetch(endpoint('rules?id=' + encodeURIComponent(record.id)), {method: 'DELETE'}); if (!r.ok) throw new Error('Could not remove rule'); });
        row.append(label, b); fragment.append(row);
      }
      if (!records.length) { const p = document.createElement('p'); p.textContent = 'None configured'; fragment.append(p); }
      el(id).replaceChildren(fragment);
    }
  }
  async function refresh() {
    if (state.busy) return;
    state.busy = true;
    try {
      const [stats, maps, rules, uscan] = await Promise.all([api('stats'), api('proxy/maps'), api('rules'), api('uscan')]);
      renderStats(stats); state.maps = maps.maps || []; state.rules = rules.rules || []; state.uscan = uscan; renderUScan(); renderManagement(); error('');
    } catch (err) { error(err.message); } finally { state.busy = false; }
  }
  function parseObject(text) { const value = JSON.parse(text); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Parameters must be a JSON object'); return value; }
  async function deleteScanner(id) {
    const response = await fetch(endpoint('uscan/scanners?id=' + encodeURIComponent(id)), {method: 'DELETE'});
    if (!response.ok) { const value = await response.json(); throw new Error(value.error || 'Could not delete scanner'); }
  }
  async function editScanner(id) {
    const data = await api('uscan/scanners'); const record = data.scanners.find(record => record.id === id);
    if (!record) throw new Error('Scanner no longer exists');
    el('uscan-id').value = record.id; el('uscan-kind').value = record.kind; el('uscan-enabled').checked = record.enabled !== false;
    el('uscan-params').value = JSON.stringify(record.parameters || {}, null, 2); el('uscan-script').value = record.script || '';
    el('uscan-editor').scrollIntoView({behavior: 'smooth', block: 'center'});
  }
  function renderUScan() {
    const data = state.uscan, select = el('uscan-selected');
    const selected = new Set([...select.selectedOptions].map(option => option.value));
    const first = !select.options.length;
    select.replaceChildren(...(data.scanners || []).map(record => { const option = document.createElement('option'); option.value = record.id; option.textContent = `${record.id} · ${record.kind}${record.enabled === false ? ' · disabled' : ''}`; option.selected = first ? record.enabled !== false : selected.has(record.id); return option; }));
    el('uscan-interfaces').textContent = 'Available interfaces · ' + (data.interfaces || []).map(row => `${row.name} ${row.ip} (${row.cidr})`).join(' · ');
    const scanners = (data.scanners || []).map(record => {
      const row = document.createElement('div'); row.className = 'manage'; const name = document.createElement('span'); name.textContent = `${record.id} · ${record.kind}`;
      const actions = document.createElement('div'); actions.className = 'scanner-actions';
      actions.append(button('Edit', () => editScanner(record.id)), button(record.enabled === false ? 'Enable' : 'Disable', async () => { const all = await api('uscan/scanners'); const full = all.scanners.find(item => item.id === record.id); await api('uscan/scanners', {...full, enabled: record.enabled === false}); }));
      if (!['arp', 'tcp', 'mdns', 'wsd', 'onvif', 'avahi'].includes(record.id)) actions.append(button('Delete', () => deleteScanner(record.id)));
      row.append(name, actions); return row;
    });
    el('uscan-scanners').replaceChildren(...scanners);
    el('uscan-jobs').replaceChildren(...(data.jobs || []).slice(0, 8).map(job => {
      const row = document.createElement('div'); row.className = 'job'; const title = document.createElement('span'); title.textContent = `${job.status} · ${job.active_scanner || job.id.slice(0, 8)} · ${job.discoveries || 0} discoveries`; row.append(title);
      for (const result of job.results || []) { if (result.error || result.warning) { const detail = document.createElement('p'); detail.textContent = `${result.scanner} · ${result.error || result.warning}`; row.append(detail); } }
      if (['queued', 'running'].includes(job.status)) row.append(button('Cancel', async () => { const response = await fetch(endpoint('uscan/jobs?id=' + encodeURIComponent(job.id)), {method: 'DELETE'}); if (!response.ok) throw new Error('Could not cancel scan'); }));
      return row;
    }));
    el('uscan-count').textContent = `${data.devices?.length || 0} addresses observed since restart. Showing up to 1,000; download includes all retained records.`;
    el('uscan-devices').replaceChildren(...(data.devices || []).slice(0, 1000).map(device => {
      const row = document.createElement('tr');
      for (const text of [`${device.ip} ${device.mac || ''}`, device.hostname || '', [...(device.protocols || []), ...(device.services || [])].join(', '), (device.ports || []).join(', ')]) { const cell = document.createElement('td'); cell.textContent = text; row.append(cell); }
      return row;
    }));
  }
  el('uscan-run').addEventListener('click', event => action(event.currentTarget, async () => { const scanner_ids = [...el('uscan-selected').selectedOptions].map(option => option.value); if (!scanner_ids.length) throw new Error('Select at least one scanner'); await api('uscan/jobs', {scanner_ids, parameters: parseObject(el('uscan-overrides').value)}); }));
  el('uscan-editor').addEventListener('submit', event => { event.preventDefault(); action(event.currentTarget.querySelector('button'), () => api('uscan/scanners', {id: el('uscan-id').value.trim(), kind: el('uscan-kind').value, enabled: el('uscan-enabled').checked, parameters: parseObject(el('uscan-params').value), ...(el('uscan-kind').value === 'graaljs' ? {script: el('uscan-script').value} : {})})); });
  el('uscan-export').addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(state.uscan.devices || [], null, 2)], {type: 'application/json'})); const link = document.createElement('a'); link.href = url; link.download = 'uscan-devices.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  function connect() {
    const url = endpoint('events'); url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(url);
    socket.onopen = () => { retry = 1000; el('connection').textContent = 'Live'; el('connection').className = 'badge live'; refresh(); };
    socket.onmessage = message => { try { pushEvent(JSON.parse(message.data)); } catch (_) {} };
    socket.onclose = () => { el('connection').textContent = 'Reconnecting'; el('connection').className = 'badge'; if (!stopped) { reconnect = setTimeout(connect, retry); retry = Math.min(30000, retry * 2); } };
    socket.onerror = () => socket.close();
  }
  el('blocking').addEventListener('click', event => action(event.currentTarget, () => api('settings', {'blocking-enabled': !state.stats['blocking-enabled']})));
  el('refresh-lists').addEventListener('click', event => action(event.currentTarget, () => api('blocklists/refresh', {})));
  el('clear-cache').addEventListener('click', event => action(event.currentTarget, () => api('cache/clear', {})));
  el('pause').addEventListener('click', event => { state.paused = !state.paused; event.currentTarget.textContent = state.paused ? 'Resume view' : 'Pause view'; renderFlow(); });
  el('filter').addEventListener('input', renderFlow); el('kind').addEventListener('change', renderFlow);
  el('domain-form').addEventListener('submit', event => { event.preventDefault(); action(event.currentTarget.querySelector('button'), () => rule(el('domain').value, el('decision').value)); });
  api('queries?n=50').then(data => { if (!state.events.length) { state.events = (data.queries || []).map(event => ({...event, type: 'dns', blocked: ['blackhole', 'blocklist'].includes(event.action)})); renderFlow(); } }).catch(() => {});
  refresh(); connect(); poll = setInterval(refresh, 5000);
  window.addEventListener('pagehide', () => { stopped = true; clearInterval(poll); clearTimeout(reconnect); socket?.close(); });
})();
