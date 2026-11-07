/* Home Assistant custom card. All API traffic uses HA's authenticated WebSocket. */
class BlueberryProxyCard extends HTMLElement {
  constructor() { super(); this.attachShadow({mode: 'open'}); this._events = []; this._generation = 0; }
  static getStubConfig() { return {type: 'custom:blueberry-proxy-card', title: 'BlueberryProxy'}; }
  static getConfigElement() { return document.createElement('blueberry-proxy-card-editor'); }
  setConfig(config) {
    this._config = {...config};
    if (this.shadowRoot.querySelector('h2')) this.shadowRoot.querySelector('h2').textContent = config.title || 'BlueberryProxy';
    this._disconnect();
    if (this.isConnected) this._start();
  }
  set hass(hass) {
    const changed = this._hass?.connection !== hass.connection;
    this._hass = hass;
    if (changed) this._disconnect();
    if (this.isConnected && !this._unsubscribe && !this._starting) this._start();
  }
  getCardSize() { return 7; }
  connectedCallback() { this._build(); this._start(); }
  disconnectedCallback() { this._disconnect(); }
  _disconnect() {
    this._generation++;
    this._unsubscribe?.(); this._unsubscribe = null;
    clearTimeout(this._retry); this._starting = false;
  }
  _build() {
    if (this.shadowRoot.querySelector('ha-card')) return;
    this.shadowRoot.innerHTML = `<style>
      :host{display:block}ha-card{padding:20px;color:var(--primary-text-color);overflow:hidden}h2{font-size:20px;margin:0}header,.row,.actions{display:flex;align-items:center;justify-content:space-between;gap:10px}.status{font-size:12px;color:var(--secondary-text-color)}.status.live{color:var(--success-color,#278a6c)}.totals{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:22px 0}.total strong{display:block;font-size:26px;font-variant-numeric:tabular-nums}.total span,.muted{font-size:12px;color:var(--secondary-text-color)}button,select,input{font:inherit;font-size:13px;padding:9px 11px;border:1px solid var(--divider-color,#ddd);border-radius:9px;color:var(--primary-text-color);background:var(--card-background-color,#fff);min-width:0}button{cursor:pointer}button:hover{background:var(--secondary-background-color)}button:disabled{opacity:.5;cursor:wait}button:focus-visible,input:focus,select:focus{outline:2px solid var(--primary-color);outline-offset:2px}.actions{flex-wrap:wrap;justify-content:flex-start}.primary{color:var(--primary-color)}.error{color:var(--error-color,#c33);font-size:13px;line-height:1.5;white-space:normal}.row{border-top:1px solid var(--divider-color,#ddd);padding:9px 0;font-size:13px}.row span:first-child{flex:1;overflow-wrap:anywhere}.count{color:var(--secondary-text-color);font-variant-numeric:tabular-nums}.row button{font-size:12px;padding:5px 8px}h3{font-size:14px;margin:21px 0 10px}.flow{max-height:180px;overflow:auto;font-size:12px}.event{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-top:1px solid var(--divider-color,#ddd)}.event span:first-child{overflow-wrap:anywhere}.blocked{color:var(--error-color,#c33)}.domain-form{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.domain-form input{flex:1;min-width:130px}summary{cursor:pointer;margin-top:17px;font-size:14px}.period{margin:12px 0;color:var(--secondary-text-color);font-size:12px;line-height:1.5}[hidden]{display:none!important}.selector{width:100%;margin-top:12px}@media(max-width:330px){ha-card{padding:14px}.total strong{font-size:22px}}
    </style><ha-card><header><h2>BlueberryProxy</h2><span class="status">Connecting</span></header>
    <select class="selector" aria-label="Proxy instance" hidden></select><p class="error" role="alert" hidden></p>
    <div class="totals"><div class="total"><strong data-total="queries">0</strong><span>DNS requests</span></div><div class="total"><strong data-total="allowed">0</strong><span>Allowed</span></div><div class="total"><strong data-total="blocked">0</strong><span>Blocked</span></div></div>
    <p class="period" data-summary>Statistics since proxy restart</p><div class="actions"><button class="primary" data-action="blocking">Pause blocking</button><button data-action="refresh_blocklists">Update lists</button><button data-action="clear_cache">Clear cache</button><button data-action="uscan_start">Discover devices</button></div>
    <h3>Top requested</h3><div data-ranking="top-domains"></div><h3>Top blocked</h3><div data-ranking="top-blocked"></div>
    <h3>Live flow</h3><div class="flow" aria-label="Recent DNS and HTTP events"></div>
    <details><summary>Domain rules and proxy maps</summary><form class="domain-form"><input name="domain" required aria-label="Domain" placeholder="device.example.com"><select name="decision" aria-label="Decision"><option value="passthrough">Allow</option><option value="blackhole">Block</option></select><button>Add</button></form><div data-maps></div></details></ha-card>`;
    this.shadowRoot.querySelector('h2').textContent = this._config?.title || 'BlueberryProxy';
    this.shadowRoot.querySelector('.selector').addEventListener('change', event => { this._selected = event.target.value; this._events = []; this._disconnect(); this._start(); });
    this.shadowRoot.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => this._command(button.dataset.action, button.dataset.action === 'blocking' ? {enabled: !this._stats?.['blocking-enabled']} : {})));
    this.shadowRoot.querySelector('form').addEventListener('submit', event => { event.preventDefault(); const form = event.currentTarget; this._command('domain_rule', {domain: form.elements.domain.value, decision: form.elements.decision.value}); });
  }
  _error(text) { const error = this.shadowRoot.querySelector('.error'); if (!error) return; error.textContent = text || ''; error.hidden = !text; }
  async _start() {
    if (!this._hass || !this._config || !this.isConnected || this._starting || this._unsubscribe) return;
    this._build(); this._starting = true;
    const generation = this._generation;
    try {
      const entries = await this._hass.callWS({type: 'blueberry_proxy/entries'});
      if (generation !== this._generation || !this.isConnected) return;
      this._entry = this._config.entry_id || this._selected || entries[0]?.entry_id;
      if (!entries.some(entry => entry.entry_id === this._entry)) throw new Error('Add the BlueberryProxy Dashboard integration in Settings → Devices & services.');
      const select = this.shadowRoot.querySelector('.selector');
      select.replaceChildren(...entries.map(entry => { const option = document.createElement('option'); option.value = entry.entry_id; option.textContent = entry.title; return option; }));
      select.value = this._entry; select.hidden = entries.length < 2 || !!this._config.entry_id;
      const unsubscribe = await this._hass.connection.subscribeMessage(event => {
        if (generation !== this._generation) return;
        if (event.kind === 'snapshot') { this._stats = event.data?.stats || {}; this._available = event.available; this._maps = event.data?.maps || []; this._uscan = event.data?.uscan || {}; this._renderStats(); }
        if (event.kind === 'flow') { this._events.unshift(...event.events.slice().reverse()); this._events.length = Math.min(10, this._events.length); this._renderFlow(); }
        if (event.kind === 'stream') { this._live = event.connected; if (event.unloaded) { this._available = false; this._error('Proxy integration unloaded. Reload this card after enabling it.'); } this._renderStatus(); }
      }, {type: 'blueberry_proxy/subscribe', entry_id: this._entry});
      if (generation !== this._generation || !this.isConnected) unsubscribe();
      else { this._unsubscribe = unsubscribe; this._error(''); }
    } catch (err) { if (generation === this._generation) { this._error(err.message || String(err)); this._retry = setTimeout(() => this._start(), 10000); } }
    finally { if (generation === this._generation) this._starting = false; }
  }
  _renderStatus() {
    const status = this.shadowRoot.querySelector('.status');
    status.textContent = this._available === false ? 'Unavailable' : this._live ? 'Live' : 'Reconnecting';
    status.classList.toggle('live', !!this._live && this._available !== false);
    this.shadowRoot.querySelectorAll('button').forEach(button => { button.disabled = !!this._busy || this._available === false; });
  }
  _renderStats() {
    this.shadowRoot.querySelector('[data-action="uscan_start"]').hidden = !this._uscan?.scanners;
    const s = this._stats || {}, format = value => Number(value || 0).toLocaleString();
    for (const key of ['queries', 'allowed', 'blocked']) this.shadowRoot.querySelector(`[data-total="${key}"]`).textContent = format(s[key]);
    this.shadowRoot.querySelector('[data-action="blocking"]').textContent = s['blocking-enabled'] ? 'Pause blocking' : 'Resume blocking';
    this.shadowRoot.querySelector('[data-summary]').textContent = `${s['blocking-enabled'] ? 'Protection active' : 'Blocking paused'} · ${format(s.errors)} failures · ${format(s.cache?.entries)} cache entries · ${format(this._uscan?.device_count)} discovered addresses · since restart`;
    for (const field of ['top-domains', 'top-blocked']) {
      const parent = this.shadowRoot.querySelector(`[data-ranking="${field}"]`);
      const rows = (s[field] || []).slice(0, 5).map(record => {
        const row = document.createElement('div'); row.className = 'row';
        const domain = document.createElement('span'); domain.textContent = record.domain;
        const count = document.createElement('span'); count.className = 'count'; count.textContent = format(record.queries);
        const button = document.createElement('button'); button.textContent = field === 'top-blocked' ? 'Allow' : 'Block';
        button.addEventListener('click', () => this._command('domain_rule', {domain: record.domain, decision: field === 'top-blocked' ? 'passthrough' : 'blackhole'}));
        row.append(domain, count, button); return row;
      });
      if (!rows.length) { const span = document.createElement('span'); span.className = 'muted'; span.textContent = 'No activity yet'; rows.push(span); }
      parent.replaceChildren(...rows);
    }
    const maps = (this._maps || []).map(record => {
      const row = document.createElement('div'); row.className = 'row';
      const name = document.createElement('span'); name.textContent = `${record.host || '*'}${record.path || '/'} · ${record.id}`;
      const button = document.createElement('button'); button.textContent = record.enabled === false ? 'Enable' : 'Disable';
      button.addEventListener('click', () => this._command('toggle_map', {map_id: String(record.id), enabled: record.enabled === false}));
      row.append(name, button); return row;
    });
    this.shadowRoot.querySelector('[data-maps]').replaceChildren(...maps); this._renderStatus();
  }
  _renderFlow() {
    const rows = this._events.map(event => {
      const row = document.createElement('div'); row.className = 'event' + (event.blocked ? ' blocked' : '');
      const domain = document.createElement('span'); domain.textContent = event.qname || event.uri || event.hostname || event.ip || event.map || 'Proxy response';
      const action = document.createElement('span'); action.textContent = event.action || `${event.method || event.type} ${event.status || ''}`;
      row.append(domain, action); return row;
    });
    this.shadowRoot.querySelector('.flow').replaceChildren(...rows);
  }
  async _command(action, values) {
    if (this._busy) return;
    this._busy = true; this._renderStatus();
    try { const result = await this._hass.callWS({type: 'blueberry_proxy/command', entry_id: this._entry, action, values}); if (result?.results?.some(record => record.error)) throw new Error('Some blocklists could not be updated. Check their source URLs.'); this._error(''); }
    catch (err) { this._error(err.message || String(err)); }
    finally { this._busy = false; this._renderStatus(); }
  }
}
class BlueberryProxyCardEditor extends HTMLElement {
  setConfig(config) {
    this._config = config;
    this.replaceChildren();
    for (const [key, label] of [['title', 'Card title'], ['entry_id', 'Proxy entry ID, optional']]) {
      const line = document.createElement('p'); const text = document.createElement('label'); text.textContent = label;
      const input = document.createElement('input'); input.style.cssText = 'display:block;width:100%;box-sizing:border-box;padding:10px;margin-top:7px'; input.value = config[key] || '';
      input.addEventListener('input', () => { this._config = {...this._config, [key]: input.value}; this.dispatchEvent(new CustomEvent('config-changed', {detail: {config: this._config}, bubbles: true, composed: true})); });
      text.append(input); line.append(text); this.append(line);
    }
  }
}
if (!customElements.get('blueberry-proxy-card')) customElements.define('blueberry-proxy-card', BlueberryProxyCard);
if (!customElements.get('blueberry-proxy-card-editor')) customElements.define('blueberry-proxy-card-editor', BlueberryProxyCardEditor);
window.customCards = window.customCards || [];
if (!window.customCards.some(card => card.type === 'blueberry-proxy-card')) window.customCards.push({type: 'blueberry-proxy-card', name: 'BlueberryProxy', description: 'Local DNS statistics, live flow, and proxy controls', preview: false});
