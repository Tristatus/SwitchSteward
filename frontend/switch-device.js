// --- Tab „Gerät“: Identität, Dienste, Zugang, L3, ACLs, QoS ----------------
//
// Liest GET /api/switches/{id}/device-config und schickt jede Änderung als eigene
// Operation über runSwitchChange (Vorschau → Anwenden). Geheimnisse (SNMPv3-Schlüssel,
// RADIUS/TACACS-Keys, Passwörter) sind write-only: Felder vom Typ password, die direkt
// nach dem Auslesen geleert werden; der Server liefert sie nie zurück.

let deviceConfigRequestSequence = 0;
let deviceTabState = null;
let deviceModalState = null;
let deviceChangeInProgress = false;

// RouterOS kennt keinen Domainnamen.
const DEVICE_DOMAIN_NAME_UNSUPPORTED = ['mikrotik_routeros'];
const DEVICE_LOGIN_ORDERS = ['local', 'radius local', 'tacacs local', 'radius tacacs local', 'tacacs radius local'];
const DEVICE_SECRET_FIELDS = [
  'device-snmp-auth-key', 'device-snmp-priv-key', 'device-user-password',
];

function deviceElement(id) {
  return document.getElementById(id);
}

function deviceText(id) {
  return String(deviceElement(id)?.value ?? '').trim();
}

function setDeviceValue(id, value) {
  const element = deviceElement(id);
  if (element) element.value = value === null || value === undefined ? '' : String(value);
}

function setDeviceDisabled(ids, disabled) {
  ids.forEach(id => {
    const element = deviceElement(id);
    if (element) element.disabled = disabled;
  });
}

function deviceList(value) {
  return String(value ?? '').split(/[\s,;]+/).map(entry => entry.trim()).filter(Boolean);
}

function sameDeviceList(left, right) {
  return JSON.stringify(left || []) === JSON.stringify(right || []);
}

function deviceInteger(id, label, min, max, { optional = false } = {}) {
  const raw = deviceText(id);
  if (!raw && optional) return null;
  const value = /^-?\d+$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(t('{field}: Bitte eine ganze Zahl von {min} bis {max} eingeben.', { field: label, min, max }));
  }
  return value;
}

function deviceOptionAllowed(state, option) {
  return state.supported && (!Array.isArray(state.options) || state.options.includes(option));
}

function deviceYesNo(value) {
  if (value === true) return t('ja');
  if (value === false) return t('nein');
  return '—';
}

function deviceBoolText(id) {
  const raw = deviceText(id);
  return raw === 'true' ? true : raw === 'false' ? false : null;
}

// Geheimnisfelder des Bearbeitungsdialogs; `includePanels` leert auch die AAA-Schlüsselfelder im Tab.
function clearDeviceSecrets({ includePanels = false } = {}) {
  DEVICE_SECRET_FIELDS.forEach(id => setDeviceValue(id, ''));
  if (includePanels) document.querySelectorAll('.device-secret').forEach(field => { field.value = ''; });
}

// --- Laden und Darstellen ---------------------------------------------------

async function loadDeviceConfig(switchId) {
  const container = deviceElement('device-container');
  if (!container) return;
  const session = currentSession;
  const sequence = ++deviceConfigRequestSequence;
  const isCurrent = () => sequence === deviceConfigRequestSequence && currentSession === session
    && container === deviceElement('device-container');
  const button = deviceElement('btn-refresh-device');
  if (button) button.disabled = true;
  container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Geräteeinstellungen …'))}</div>`;
  try {
    const config = await api(`/api/switches/${switchId}/device-config`);
    if (!isCurrent()) return;
    if (!config || typeof config !== 'object') throw new Error(t('Der Switch lieferte keine gültigen Geräteeinstellungen.'));
    const sw = switchById(switchId);
    deviceTabState = { switchId: Number(switchId), session, config, sw };
    container.innerHTML = renderDeviceConfig(sw, config);
    fillDeviceForms(deviceTabState);
    wireDeviceConfig(container, Number(switchId));
  } catch (error) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(error.message)}</div>`;
  } finally {
    if (button && isCurrent()) button.disabled = false;
  }
}

// Lädt den Tab nach einer Änderung neu, solange dieselbe Sitzung denselben Switch zeigt.
function reloadDeviceConfigAfterWrite(switchId, session) {
  if (currentSession !== session || Number(currentSwitchId) !== Number(switchId)) return undefined;
  if (!deviceElement('device-container')) return undefined;
  return loadDeviceConfig(switchId);
}

function devicePanel(sw, featureId, title, data, body) {
  const state = featureState(sw, featureId);
  const heading = `<h4 class="device-panel-title">${escapeHtml(title)}${state.supported ? '' : incompatibleBadge()}</h4>`;
  if (!state.supported) {
    return `<div class="panel-box device-panel">${heading}<p class="admin-muted">${escapeHtml(incompatibleTitle(state))}</p></div>`;
  }
  if (data === null || data === undefined) {
    return `<div class="panel-box device-panel">${heading}<p class="admin-muted">${escapeHtml(t('Der Switch hat zu diesem Bereich keine Daten geliefert.'))}</p></div>`;
  }
  return `<div class="panel-box device-panel">${heading}${body}</div>`;
}

function deviceButtonRow(buttons) {
  return currentSessionCanEdit() ? `<div class="flex-row device-actions">${buttons}</div>` : '';
}

function deviceRowAction(action, label, data = {}, danger = false) {
  const attributes = Object.entries(data)
    .map(([key, value]) => ` data-${key}="${escapeHtml(value)}"`).join('');
  return `<button type="button" class="${danger ? 'danger ' : ''}device-row-action" data-device-action="${action}"${attributes}>${escapeHtml(label)}</button>`;
}

function renderDeviceConfig(sw, config) {
  const readOnly = currentSessionCanEdit()
    ? ''
    : `<p class="admin-muted">${escapeHtml(t('Nur Administratoren können Geräteeinstellungen ändern.'))}</p>`;
  return `
    ${readOnly}
    ${renderInventoryWarnings(config.warnings)}
    <div class="device-panels">
      ${renderDeviceIdentity(sw, config.identity)}
      ${renderDeviceServices(sw, config.services)}
      ${renderDeviceSnmp(sw, config.snmp)}
      ${renderDeviceAaa(sw, config.aaa)}
      ${renderDeviceUsers(sw, config.users)}
      ${renderDeviceSsh(sw, config.ssh)}
      ${renderDeviceL3(sw, config.l3)}
      ${renderDeviceAcls(sw, config.acls)}
      ${renderDeviceQos(sw, config.qos)}
    </div>
  `;
}

function renderDeviceIdentity(sw, identity) {
  return devicePanel(sw, 'device_identity', t('Identität'), identity, `
    <div class="device-form-grid">
      <div class="field"><label for="device-identity-hostname">${escapeHtml(t('Hostname'))}</label><input id="device-identity-hostname" maxlength="63" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-identity-location">${escapeHtml(t('SNMP-Standort'))}</label><input id="device-identity-location" maxlength="255" autocomplete="off"></div>
      <div class="field"><label for="device-identity-contact">${escapeHtml(t('SNMP-Kontakt'))}</label><input id="device-identity-contact" maxlength="255" autocomplete="off"></div>
    </div>
    <div class="field"><label for="device-identity-banner">${escapeHtml(t('Anmeldebanner'))}</label><textarea id="device-identity-banner" rows="3" maxlength="1000" spellcheck="false"></textarea></div>
    <p class="admin-muted">${escapeHtml(t('Ein leeres Feld entfernt Banner, Standort bzw. Kontakt.'))}</p>
    <div id="device-identity-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" class="primary" id="device-identity-preview">${escapeHtml(t('Vorschau'))}</button>`)}
  `);
}

function renderDeviceServices(sw, services) {
  return devicePanel(sw, 'device_services', t('Dienste'), services, `
    <div class="device-form-grid">
      <div class="field"><label for="device-services-ntp">${escapeHtml(t('NTP-Server (max. 4)'))}</label><input id="device-services-ntp" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-services-dns">${escapeHtml(t('DNS-Server (max. 3)'))}</label><input id="device-services-dns" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-services-domain">${escapeHtml(t('Domainname'))}</label><input id="device-services-domain" maxlength="253" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-services-tz-name">${escapeHtml(t('Zeitzone (Kürzel)'))}</label><input id="device-services-tz-name" maxlength="6" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-services-tz-offset">${escapeHtml(t('Abweichung von UTC (Minuten)'))}</label><input id="device-services-tz-offset" type="number" min="-720" max="840" step="1"></div>
    </div>
    <div class="field"><label for="device-services-syslog">${escapeHtml(t('Syslog-Server (eine Zeile pro Server: Adresse Schweregrad 0–7, max. 4)'))}</label><textarea id="device-services-syslog" rows="3" spellcheck="false"></textarea></div>
    <p class="admin-muted">${escapeHtml(t('Listen ersetzen die Einträge auf dem Switch; Adressen mit Komma oder Leerzeichen trennen.'))}</p>
    <div id="device-services-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" class="primary" id="device-services-preview">${escapeHtml(t('Vorschau'))}</button>`)}
  `);
}

function renderDeviceSnmp(sw, snmp) {
  const users = Array.isArray(snmp?.users) ? snmp.users : [];
  const canEdit = currentSessionCanEdit();
  const rows = users.map(user => `
      <tr>
        <td>${escapeHtml(user.name)}</td>
        <td>${escapeHtml(user.auth ? String(user.auth).toUpperCase() : '—')}</td>
        <td>${escapeHtml(user.priv ? String(user.priv).toUpperCase() : '—')}</td>
        <td>${escapeHtml(user.access === 'rw' ? t('Lesen und Schreiben') : user.access === 'ro' ? t('Nur lesen') : '—')}</td>
        ${canEdit ? `<td class="table-actions"><div class="table-actions-inner">${deviceRowAction('snmp-edit', t('Ändern'), { name: user.name })}${deviceRowAction('snmp-delete', t('Löschen'), { name: user.name }, true)}</div></td>` : ''}
      </tr>`).join('');
  const table = users.length ? `
    <table>
      <thead><tr><th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Authentifizierung'))}</th><th>${escapeHtml(t('Verschlüsselung'))}</th><th>${escapeHtml(t('Zugriff'))}</th>${canEdit ? '<th></th>' : ''}</tr></thead>
      <tbody>${rows}</tbody>
    </table>` : `<div class="empty-state">${escapeHtml(t('Keine SNMPv3-Benutzer konfiguriert.'))}</div>`;
  return devicePanel(sw, 'device_snmp', t('SNMPv3-Benutzer'), snmp, `
    ${table}
    <div id="device-snmp-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" class="primary" id="device-snmp-add">${escapeHtml(t('SNMPv3-Benutzer anlegen'))}</button>`)}
  `);
}

function deviceAaaRow(kind, server, aaaState) {
  const canEdit = currentSessionCanEdit();
  const disabled = canEdit && aaaState ? '' : ' disabled';
  const configured = server?.key_configured === true;
  const ports = kind === 'radius'
    ? `<td><input data-field="auth_port" type="number" min="1" max="65535" value="${escapeHtml(server?.auth_port ?? 1812)}" aria-label="${escapeHtml(t('Auth-Port'))}"${disabled}></td>
       <td><input data-field="acct_port" type="number" min="1" max="65535" value="${escapeHtml(server?.acct_port ?? 1813)}" aria-label="${escapeHtml(t('Accounting-Port'))}"${disabled}></td>`
    : `<td><input data-field="port" type="number" min="1" max="65535" value="${escapeHtml(server?.port ?? 49)}" aria-label="${escapeHtml(t('Port'))}"${disabled}></td>`;
  return `
      <tr class="device-aaa-row" data-kind="${kind}" data-original-host="${escapeHtml(server?.host ?? '')}" data-key-configured="${configured}">
        <td><input data-field="host" value="${escapeHtml(server?.host ?? '')}" autocomplete="off" spellcheck="false" aria-label="${escapeHtml(t('Server'))}"${disabled}></td>
        ${ports}
        <td><input class="device-secret" data-field="key" type="password" autocomplete="new-password" placeholder="${escapeHtml(configured ? t('unverändert') : t('Schlüssel'))}" aria-label="${escapeHtml(t('Schlüssel'))}"${disabled}></td>
        <td>${server ? `<label class="admin-check"><input data-field="remove" type="checkbox"${disabled}> ${escapeHtml(t('Entfernen'))}</label>` : ''}</td>
      </tr>`;
}

function renderDeviceAaaServers(kind, servers, supported) {
  const portHeaders = kind === 'radius'
    ? `<th>${escapeHtml(t('Auth-Port'))}</th><th>${escapeHtml(t('Accounting-Port'))}</th>`
    : `<th>${escapeHtml(t('Port'))}</th>`;
  const rows = (Array.isArray(servers) ? servers : []).map(server => deviceAaaRow(kind, server, supported)).join('');
  const blank = currentSessionCanEdit() && supported ? deviceAaaRow(kind, null, supported) : '';
  const tbody = kind === 'radius'
    ? `<tbody id="device-aaa-radius-rows">${rows}${blank}</tbody>`
    : `<tbody id="device-aaa-tacacs-rows">${rows}${blank}</tbody>`;
  return `<table class="device-aaa-table"><thead><tr><th>${escapeHtml(t('Server'))}</th>${portHeaders}<th>${escapeHtml(t('Schlüssel'))}</th><th></th></tr></thead>${tbody}</table>`;
}

function renderDeviceAaa(sw, aaa) {
  const state = featureState(sw, 'device_aaa');
  const radius = deviceOptionAllowed(state, 'radius');
  const tacacs = deviceOptionAllowed(state, 'tacacs');
  const loginOrder = deviceOptionAllowed(state, 'login_order');
  const incompatible = text => `<p class="admin-muted">${escapeHtml(text)} ${incompatibleBadge()}</p>`;
  return devicePanel(sw, 'device_aaa', t('AAA (RADIUS/TACACS+)'), aaa, `
    <h5>${escapeHtml(t('RADIUS-Server'))}</h5>
    ${radius ? renderDeviceAaaServers('radius', aaa?.radius, radius) : incompatible(t('RADIUS wird nicht unterstützt.'))}
    ${radius ? deviceButtonRow(`<button type="button" id="device-aaa-add-radius">${escapeHtml(t('RADIUS-Server hinzufügen'))}</button>`) : ''}
    <h5>${escapeHtml(t('TACACS+-Server'))}</h5>
    ${tacacs ? renderDeviceAaaServers('tacacs', aaa?.tacacs, tacacs) : incompatible(t('TACACS+ wird nicht unterstützt.'))}
    ${tacacs ? deviceButtonRow(`<button type="button" id="device-aaa-add-tacacs">${escapeHtml(t('TACACS+-Server hinzufügen'))}</button>`) : ''}
    <div class="field"><label for="device-aaa-login-order">${escapeHtml(t('Anmeldereihenfolge'))}</label>
      <select id="device-aaa-login-order"${loginOrder ? '' : ' disabled'}>
        <option value="local">${escapeHtml(t('Nur lokal'))}</option>
        <option value="radius local">${escapeHtml(t('RADIUS, dann lokal'))}</option>
        <option value="tacacs local">${escapeHtml(t('TACACS+, dann lokal'))}</option>
        <option value="radius tacacs local">${escapeHtml(t('RADIUS, TACACS+, dann lokal'))}</option>
        <option value="tacacs radius local">${escapeHtml(t('TACACS+, RADIUS, dann lokal'))}</option>
      </select>
    </div>
    <p class="admin-muted">${escapeHtml(t('Schlüssel sind nur bei neuen Servern Pflicht; ein leeres Schlüsselfeld lässt den gespeicherten Schlüssel unverändert. Die lokale Anmeldung bleibt immer als Rückfallebene erhalten.'))}</p>
    <div id="device-aaa-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" class="primary" id="device-aaa-preview">${escapeHtml(t('Vorschau'))}</button>`)}
  `);
}

function devicePrivilegeText(privilege) {
  if (privilege === 'admin') return t('Administrator');
  if (privilege === 'read_only') return t('Nur lesen');
  return '—';
}

function renderDeviceUsers(sw, users) {
  const list = Array.isArray(users) ? users : [];
  const canEdit = currentSessionCanEdit();
  const rows = list.map(user => `
      <tr>
        <td>${escapeHtml(user.name)}</td>
        <td>${escapeHtml(devicePrivilegeText(user.privilege))}</td>
        ${canEdit ? `<td class="table-actions"><div class="table-actions-inner">${deviceRowAction('user-edit', t('Ändern'), { name: user.name })}${deviceRowAction('user-delete', t('Löschen'), { name: user.name }, true)}</div></td>` : ''}
      </tr>`).join('');
  const table = list.length ? `
    <table>
      <thead><tr><th>${escapeHtml(t('Benutzername'))}</th><th>${escapeHtml(t('Rechte'))}</th>${canEdit ? '<th></th>' : ''}</tr></thead>
      <tbody>${rows}</tbody>
    </table>` : `<div class="empty-state">${escapeHtml(t('Keine lokalen Benutzer gefunden.'))}</div>`;
  return devicePanel(sw, 'device_users', t('Lokale Benutzer'), users, `
    ${table}
    <div id="device-users-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" class="primary" id="device-users-add">${escapeHtml(t('Benutzer anlegen'))}</button>`)}
  `);
}

function renderDeviceSsh(sw, ssh) {
  return devicePanel(sw, 'device_ssh', t('SSH und Zugang'), ssh, `
    <p class="admin-muted">${escapeHtml(t('SSH-Version: {version}', { version: hasValue(ssh?.version) ? ssh.version : '—' }))}</p>
    <div class="device-form-grid">
      <div class="field"><label for="device-ssh-timeout">${escapeHtml(t('Leerlauf-Timeout (Sekunden, 60–3600)'))}</label><input id="device-ssh-timeout" type="number" min="60" max="3600" step="1"></div>
      <div class="field"><label for="device-ssh-telnet">${escapeHtml(t('Telnet'))}</label>
        <select id="device-ssh-telnet">
          <option value="">${escapeHtml(t('Unverändert'))}</option>
          <option value="true">${escapeHtml(t('Ein'))}</option>
          <option value="false">${escapeHtml(t('Aus'))}</option>
        </select>
      </div>
      <div class="field"><label for="device-ssh-web">${escapeHtml(t('Weboberfläche'))}</label>
        <select id="device-ssh-web">
          <option value="">${escapeHtml(t('Unverändert'))}</option>
          <option value="true">${escapeHtml(t('Ein'))}</option>
          <option value="false">${escapeHtml(t('Aus'))}</option>
        </select>
      </div>
    </div>
    <div id="device-ssh-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" class="primary" id="device-ssh-preview">${escapeHtml(t('Vorschau'))}</button>`)}
  `);
}

function renderDeviceL3(sw, l3) {
  const state = featureState(sw, 'device_l3');
  const canEdit = currentSessionCanEdit();
  const sviAllowed = deviceOptionAllowed(state, 'svi');
  const gatewayAllowed = deviceOptionAllowed(state, 'gateway');
  const routesAllowed = deviceOptionAllowed(state, 'static_routes');
  const svis = Array.isArray(l3?.svis) ? l3.svis : [];
  const routes = Array.isArray(l3?.routes) ? l3.routes : [];
  const sviRows = svis.map(svi => `
      <tr>
        <td>${escapeHtml(svi.vlan)}</td>
        <td>${escapeHtml(hasValue(svi.address) ? `${svi.address}/${svi.prefix_length ?? ''}` : '—')}</td>
        <td>${escapeHtml((Array.isArray(svi.dhcp_relay) && svi.dhcp_relay.length) ? svi.dhcp_relay.join(', ') : '—')}</td>
        <td>${escapeHtml(deviceYesNo(svi.enabled))}</td>
        ${canEdit && sviAllowed ? `<td class="table-actions"><div class="table-actions-inner">${deviceRowAction('svi-edit', t('Ändern'), { vlan: svi.vlan })}${deviceRowAction('svi-delete', t('Löschen'), { vlan: svi.vlan }, true)}</div></td>` : ''}
      </tr>`).join('');
  const routeRows = routes.map(route => `
      <tr>
        <td>${escapeHtml(`${route.prefix}/${route.prefix_length}`)}</td>
        <td>${escapeHtml(route.next_hop ?? '—')}</td>
        <td>${escapeHtml(route.distance ?? '—')}</td>
        ${canEdit && routesAllowed ? `<td class="table-actions"><div class="table-actions-inner">${deviceRowAction('route-delete', t('Löschen'), { prefix: route.prefix, length: route.prefix_length, hop: route.next_hop ?? '' }, true)}</div></td>` : ''}
      </tr>`).join('');
  const sviTable = svis.length ? `
    <table>
      <thead><tr><th>${escapeHtml(t('VLAN'))}</th><th>${escapeHtml(t('Adresse'))}</th><th>${escapeHtml(t('DHCP-Relay'))}</th><th>${escapeHtml(t('Aktiv'))}</th>${canEdit && sviAllowed ? '<th></th>' : ''}</tr></thead>
      <tbody>${sviRows}</tbody>
    </table>` : `<div class="empty-state">${escapeHtml(t('Keine VLAN-Interfaces mit IP-Adresse.'))}</div>`;
  const routeTable = routes.length ? `
    <table>
      <thead><tr><th>${escapeHtml(t('Ziel'))}</th><th>${escapeHtml(t('Next Hop'))}</th><th>${escapeHtml(t('Distanz'))}</th>${canEdit && routesAllowed ? '<th></th>' : ''}</tr></thead>
      <tbody>${routeRows}</tbody>
    </table>` : `<div class="empty-state">${escapeHtml(t('Keine statischen Routen.'))}</div>`;
  const incompatible = `<p class="admin-muted">${incompatibleBadge()}</p>`;
  return devicePanel(sw, 'device_l3', t('Management und Layer 3'), l3, `
    <p class="admin-muted">${escapeHtml(l3?.routing_enabled === true ? t('IP-Routing ist aktiv.') : l3?.routing_enabled === false ? t('IP-Routing ist nicht aktiv.') : t('IP-Routing: unbekannt'))}</p>
    <h5>${escapeHtml(t('VLAN-Interfaces (SVI)'))}</h5>
    ${sviAllowed ? sviTable : incompatible}
    ${sviAllowed ? deviceButtonRow(`<button type="button" id="device-svi-add">${escapeHtml(t('SVI anlegen'))}</button>`) : ''}
    <h5>${escapeHtml(t('Standard-Gateway'))}</h5>
    ${gatewayAllowed ? `
      <div class="flex-row">
        <div class="field"><label for="device-l3-gateway">${escapeHtml(t('Gateway-Adresse'))}</label><input id="device-l3-gateway" maxlength="15" autocomplete="off" spellcheck="false"></div>
        ${deviceButtonRow(`<button type="button" id="device-gateway-preview">${escapeHtml(t('Vorschau'))}</button>`)}
      </div>` : incompatible}
    <h5>${escapeHtml(t('Statische Routen'))}</h5>
    ${routesAllowed ? routeTable : incompatible}
    ${routesAllowed && canEdit ? `
      <div class="device-form-grid">
        <div class="field"><label for="device-route-prefix">${escapeHtml(t('Zielnetz'))}</label><input id="device-route-prefix" maxlength="15" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="device-route-length">${escapeHtml(t('Präfixlänge'))}</label><input id="device-route-length" type="number" min="0" max="32" step="1"></div>
        <div class="field"><label for="device-route-next-hop">${escapeHtml(t('Next Hop'))}</label><input id="device-route-next-hop" maxlength="15" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="device-route-distance">${escapeHtml(t('Distanz (optional)'))}</label><input id="device-route-distance" type="number" min="1" max="255" step="1"></div>
      </div>
      ${deviceButtonRow(`<button type="button" id="device-route-add">${escapeHtml(t('Route hinzufügen'))}</button>`)}` : ''}
    <div id="device-l3-error" class="wlan-form-error" role="alert"></div>
  `);
}

function deviceAclEntryText(entry) {
  const address = (host, length) => (hasValue(host) ? (Number(length) === 32 ? host : `${host}/${length ?? ''}`) : 'any');
  const port = entry.dst_port_op === 'eq' ? ` eq ${entry.dst_port}`
    : entry.dst_port_op === 'range' ? ` range ${entry.dst_port}-${entry.dst_port_end}` : '';
  return `${entry.action} ${entry.protocol} ${address(entry.src, entry.src_len)} → ${address(entry.dst, entry.dst_len)}${port}`;
}

function renderDeviceAcls(sw, acls) {
  const list = Array.isArray(acls) ? acls : [];
  const canEdit = currentSessionCanEdit();
  const blocks = list.map(acl => {
    const entries = Array.isArray(acl.entries) ? acl.entries : [];
    const bindings = Array.isArray(acl.bindings) ? acl.bindings : [];
    const entryRows = entries.map(entry => `
        <tr>
          <td>${escapeHtml(entry.seq)}</td>
          <td><code>${escapeHtml(deviceAclEntryText(entry))}</code></td>
          ${canEdit ? `<td class="table-actions"><div class="table-actions-inner">${deviceRowAction('acl-entry-delete', t('Löschen'), { acl: acl.name, seq: entry.seq }, true)}</div></td>` : ''}
        </tr>`).join('');
    const bindingItems = bindings.map(binding => `
        <li>${escapeHtml(`${binding.interface} (${binding.direction === 'out' ? t('ausgehend') : t('eingehend')})`)}
          ${canEdit ? deviceRowAction('acl-unbind', t('Lösen'), { acl: acl.name, interface: binding.interface, direction: binding.direction }) : ''}</li>`).join('');
    return `
      <div class="device-acl">
        <div class="flex-row" style="justify-content: space-between;">
          <strong>${escapeHtml(acl.name)} <span class="admin-muted">(${escapeHtml(acl.type === 'standard' ? t('Standard') : t('Erweitert'))})</span></strong>
          ${canEdit ? `<div class="flex-row">${deviceRowAction('acl-entry-add', t('Eintrag hinzufügen'), { acl: acl.name })}${deviceRowAction('acl-bind', t('Binden'), { acl: acl.name })}${deviceRowAction('acl-delete', t('ACL löschen'), { acl: acl.name }, true)}</div>` : ''}
        </div>
        ${entries.length ? `<table><thead><tr><th>${escapeHtml(t('Nr.'))}</th><th>${escapeHtml(t('Regel'))}</th>${canEdit ? '<th></th>' : ''}</tr></thead><tbody>${entryRows}</tbody></table>` : `<p class="admin-muted">${escapeHtml(t('Keine Einträge.'))}</p>`}
        <div class="admin-muted">${escapeHtml(t('Gebunden an:'))} ${bindings.length ? `<ul>${bindingItems}</ul>` : escapeHtml(t('nichts'))}</div>
      </div>`;
  }).join('');
  return devicePanel(sw, 'acl', t('ACLs (IPv4)'), acls, `
    ${list.length ? blocks : `<div class="empty-state">${escapeHtml(t('Keine ACLs konfiguriert.'))}</div>`}
    ${canEdit ? `
      <div class="flex-row device-acl-create">
        <div class="field"><label for="device-acl-name">${escapeHtml(t('Neue ACL'))}</label><input id="device-acl-name" maxlength="31" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="device-acl-type">${escapeHtml(t('Typ'))}</label>
          <select id="device-acl-type">
            <option value="extended">${escapeHtml(t('Erweitert'))}</option>
            <option value="standard">${escapeHtml(t('Standard'))}</option>
          </select>
        </div>
        <button type="button" id="device-acl-create">${escapeHtml(t('ACL anlegen'))}</button>
      </div>` : ''}
    <div id="device-acl-error" class="wlan-form-error" role="alert"></div>
  `);
}

function deviceTrustText(trust) {
  if (trust === 'none') return t('Nicht vertrauen');
  if (trust === 'cos') return t('CoS vertrauen');
  if (trust === 'dscp') return t('DSCP vertrauen');
  return '—';
}

function renderDeviceQos(sw, qos) {
  const canEdit = currentSessionCanEdit();
  const voiceState = featureState(sw, 'qos_voice');
  const ports = qos?.ports && typeof qos.ports === 'object' ? qos.ports : {};
  const voice = qos?.voice_preset && typeof qos.voice_preset === 'object' ? qos.voice_preset : {};
  const interfaces = [...new Set([...Object.keys(ports), ...Object.keys(voice)])];
  const rows = interfaces.map(name => `
      <tr>
        <td>${escapeHtml(name)}</td>
        <td>${escapeHtml(deviceTrustText(ports[name]?.trust))}</td>
        <td>${voiceState.supported ? escapeHtml(deviceYesNo(voice[name])) : incompatibleBadge()}</td>
        ${canEdit ? `<td class="table-actions"><div class="table-actions-inner">${deviceRowAction('qos-edit', t('Ändern'), { interface: name })}</div></td>` : ''}
      </tr>`).join('');
  const table = interfaces.length ? `
    <table>
      <thead><tr><th>${escapeHtml(t('Port'))}</th><th>${escapeHtml(t('Trust'))}</th><th>${escapeHtml(t('Voice-Vorlage'))}</th>${canEdit ? '<th></th>' : ''}</tr></thead>
      <tbody>${rows}</tbody>
    </table>` : `<div class="empty-state">${escapeHtml(t('Keine Ports mit QoS-Einstellungen gefunden.'))}</div>`;
  return devicePanel(sw, 'qos', t('QoS'), qos, `
    ${table}
    <div id="device-qos-error" class="wlan-form-error" role="alert"></div>
    ${deviceButtonRow(`<button type="button" id="device-qos-add">${escapeHtml(t('Port einstellen'))}</button>`)}
  `);
}

// Werte und Sperren werden per Script gesetzt, nicht über Markup-Attribute.
function fillDeviceForms({ sw, config }) {
  const readOnly = !currentSessionCanEdit();
  const identity = config.identity || {};
  setDeviceValue('device-identity-hostname', identity.hostname);
  setDeviceValue('device-identity-banner', identity.banner);
  setDeviceValue('device-identity-location', identity.snmp_location);
  setDeviceValue('device-identity-contact', identity.snmp_contact);
  setDeviceDisabled(['device-identity-hostname', 'device-identity-banner', 'device-identity-location', 'device-identity-contact'], readOnly);

  const services = config.services || {};
  setDeviceValue('device-services-ntp', (services.ntp_servers || []).join(', '));
  setDeviceValue('device-services-dns', (services.dns_servers || []).join(', '));
  setDeviceValue('device-services-domain', services.domain_name);
  setDeviceValue('device-services-tz-name', services.timezone?.name);
  setDeviceValue('device-services-tz-offset', services.timezone?.offset_minutes);
  setDeviceValue('device-services-syslog', (services.syslog || []).map(entry => `${entry.host} ${entry.severity ?? ''}`.trim()).join('\n'));
  setDeviceDisabled(['device-services-ntp', 'device-services-dns', 'device-services-tz-name', 'device-services-tz-offset', 'device-services-syslog'], readOnly);
  setDeviceDisabled(['device-services-domain'], readOnly || !deviceDomainNameSupported(sw));

  const sshState = featureState(sw, 'device_ssh');
  const ssh = config.ssh || {};
  setDeviceValue('device-ssh-timeout', ssh.timeout_seconds);
  setDeviceValue('device-ssh-telnet', typeof ssh.telnet_enabled === 'boolean' ? String(ssh.telnet_enabled) : '');
  setDeviceValue('device-ssh-web', typeof ssh.web_enabled === 'boolean' ? String(ssh.web_enabled) : '');
  setDeviceDisabled(['device-ssh-timeout'], readOnly || !deviceOptionAllowed(sshState, 'timeout'));
  setDeviceDisabled(['device-ssh-telnet'], readOnly || !deviceOptionAllowed(sshState, 'telnet'));
  setDeviceDisabled(['device-ssh-web'], readOnly || !deviceOptionAllowed(sshState, 'web'));

  const aaaState = featureState(sw, 'device_aaa');
  const order = Array.isArray(config.aaa?.login_order) ? config.aaa.login_order.join(' ') : '';
  const orderSelect = deviceElement('device-aaa-login-order');
  if (orderSelect) {
    if (order && !DEVICE_LOGIN_ORDERS.includes(order) && !Array.from(orderSelect.options).some(option => option.value === order)) {
      const option = document.createElement('option');
      option.value = order;
      option.textContent = config.aaa.login_order.join(', ');
      option.dataset.preservedValue = order;
      orderSelect.appendChild(option);
    }
    markIncompatibleOptions(orderSelect, DEVICE_LOGIN_ORDERS.filter(value => value.split(' ')
      .every(method => method === 'local' || deviceOptionAllowed(aaaState, method))));
    orderSelect.value = order;
    orderSelect.disabled = readOnly || !deviceOptionAllowed(aaaState, 'login_order');
  }

  setDeviceValue('device-l3-gateway', config.l3?.default_gateway);
  setDeviceDisabled(['device-l3-gateway'], readOnly);
}

function deviceDomainNameSupported(sw) {
  return !DEVICE_DOMAIN_NAME_UNSUPPORTED.includes(String(sw?.device_type || ''));
}

function wireDeviceConfig(container, switchId) {
  const on = (id, handler) => deviceElement(id)?.addEventListener('click', handler);
  on('device-identity-preview', () => submitDeviceIdentity(switchId));
  on('device-services-preview', () => submitDeviceServices(switchId));
  on('device-snmp-add', () => openDeviceSnmpUserModal(switchId, null));
  on('device-aaa-add-radius', () => deviceElement('device-aaa-radius-rows')?.insertAdjacentHTML('beforeend', deviceAaaRow('radius', null, true)));
  on('device-aaa-add-tacacs', () => deviceElement('device-aaa-tacacs-rows')?.insertAdjacentHTML('beforeend', deviceAaaRow('tacacs', null, true)));
  on('device-aaa-preview', () => submitDeviceAaa(switchId));
  on('device-users-add', () => openDeviceUserModal(switchId, null));
  on('device-ssh-preview', () => submitDeviceSsh(switchId));
  on('device-svi-add', () => openDeviceSviModal(switchId, null));
  on('device-gateway-preview', () => submitDeviceGateway(switchId));
  on('device-route-add', () => submitDeviceRouteAdd(switchId));
  on('device-acl-create', () => submitDeviceAclCreate(switchId));
  on('device-qos-add', () => openDeviceQosModal(switchId, null));
  container.querySelectorAll('[data-device-action]').forEach(button => {
    button.addEventListener('click', () => handleDeviceRowAction(switchId, button.dataset));
  });
}

function handleDeviceRowAction(switchId, data) {
  const config = deviceTabState?.config || {};
  switch (data.deviceAction) {
    case 'snmp-edit':
      return openDeviceSnmpUserModal(switchId, (config.snmp?.users || []).find(user => user.name === data.name) || null);
    case 'snmp-delete':
      return runDeviceChange(switchId, 'device-snmp-user-delete', { name: data.name }, {
        title: t('SNMPv3-Benutzer {name} löschen', { name: data.name }), errorId: 'device-snmp-error',
      });
    case 'user-edit':
      return openDeviceUserModal(switchId, (config.users || []).find(user => user.name === data.name) || null);
    case 'user-delete':
      return runDeviceChange(switchId, 'device-user-delete', { name: data.name }, {
        title: t('Benutzer {name} löschen', { name: data.name }), errorId: 'device-users-error',
      });
    case 'svi-edit':
      return openDeviceSviModal(switchId, (config.l3?.svis || []).find(svi => String(svi.vlan) === String(data.vlan)) || null);
    case 'svi-delete':
      return runDeviceChange(switchId, 'l3-svi-delete', { vlan: Number(data.vlan) }, {
        title: t('SVI für VLAN {vlan} löschen', { vlan: data.vlan }), errorId: 'device-l3-error',
      });
    case 'route-delete':
      return runDeviceChange(switchId, 'l3-route-delete', {
        prefix: data.prefix, prefix_length: Number(data.length), next_hop: data.hop,
      }, { title: t('Route {prefix} löschen', { prefix: `${data.prefix}/${data.length}` }), errorId: 'device-l3-error' });
    case 'acl-entry-add':
      return openDeviceAclEntryModal(switchId, (config.acls || []).find(acl => acl.name === data.acl) || { name: data.acl });
    case 'acl-entry-delete':
      return runDeviceChange(switchId, 'acl-entry-delete', { name: data.acl, seq: Number(data.seq) }, {
        title: t('ACL {name}: Eintrag {seq} löschen', { name: data.acl, seq: data.seq }), errorId: 'device-acl-error',
      });
    case 'acl-bind':
      return openDeviceAclBindModal(switchId, data.acl);
    case 'acl-unbind':
      return runDeviceChange(switchId, 'acl-unbind', { name: data.acl, interface: data.interface, direction: data.direction }, {
        title: t('ACL {name} von {interface} lösen', { name: data.acl, interface: data.interface }), errorId: 'device-acl-error',
      });
    case 'acl-delete':
      return runDeviceChange(switchId, 'acl-delete', { name: data.acl }, {
        title: t('ACL {name} löschen', { name: data.acl }), errorId: 'device-acl-error',
      });
    case 'qos-edit':
      return openDeviceQosModal(switchId, data.interface);
    default:
      return undefined;
  }
}

// --- Änderungen ----------------------------------------------------------------

// Startet eine Operation über die Änderungsvorschau; Fehler landen im Panel.
async function runDeviceChange(switchId, kind, params, { title, errorId, buttonId } = {}) {
  if (!requireEditPermission() || deviceChangeInProgress) return null;
  const session = currentSession;
  const errorElement = errorId ? deviceElement(errorId) : null;
  const button = buttonId ? deviceElement(buttonId) : null;
  deviceChangeInProgress = true;
  if (button) button.disabled = true;
  if (errorElement) errorElement.textContent = '';
  let result = null;
  try {
    result = await runSwitchChange(switchId, kind, params, { title });
    if (result && !result.ok && currentSession === session && errorElement) errorElement.textContent = result.message || '';
  } catch (error) {
    if (currentSession === session && errorElement) errorElement.textContent = error.message;
  } finally {
    deviceChangeInProgress = false;
    if (button) button.disabled = false;
  }
  if (result) await reloadDeviceConfigAfterWrite(switchId, session);
  return result;
}

function deviceFormError(errorId, message) {
  const element = deviceElement(errorId);
  if (element) element.textContent = message;
  return null;
}

function submitDeviceIdentity(switchId) {
  const identity = deviceTabState?.config?.identity || {};
  const params = {};
  const fields = [
    ['hostname', 'device-identity-hostname'], ['banner', 'device-identity-banner'],
    ['snmp_location', 'device-identity-location'], ['snmp_contact', 'device-identity-contact'],
  ];
  fields.forEach(([key, id]) => {
    const value = key === 'banner' ? String(deviceElement(id)?.value ?? '').replace(/\r\n?/g, '\n').trim() : deviceText(id);
    if (value !== String(identity[key] ?? '').trim()) params[key] = value;
  });
  if ('hostname' in params && !params.hostname) return deviceFormError('device-identity-error', t('Der Hostname darf nicht leer sein.'));
  if (!Object.keys(params).length) return deviceFormError('device-identity-error', t('Es wurde nichts geändert.'));
  return runDeviceChange(switchId, 'device-identity', params, {
    title: t('Identität ändern'), errorId: 'device-identity-error', buttonId: 'device-identity-preview',
  });
}

function parseDeviceSyslog(text) {
  return String(text ?? '').split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
    const [host, severity, extra] = line.split(/\s+/);
    const level = severity === undefined ? 6 : (/^\d$/.test(severity) ? Number(severity) : NaN);
    if (extra !== undefined || !Number.isInteger(level) || level > 7) {
      throw new Error(t('Syslog: Bitte pro Zeile eine Adresse und optional einen Schweregrad 0–7 angeben.'));
    }
    return { host, severity: level };
  });
}

function submitDeviceServices(switchId) {
  const sw = deviceTabState?.sw;
  const services = deviceTabState?.config?.services || {};
  const params = {};
  try {
    const ntp = deviceList(deviceText('device-services-ntp'));
    if (!sameDeviceList(ntp, services.ntp_servers)) params.ntp_servers = ntp;
    const dns = deviceList(deviceText('device-services-dns'));
    if (!sameDeviceList(dns, services.dns_servers)) params.dns_servers = dns;
    if (deviceDomainNameSupported(sw)) {
      const domain = deviceText('device-services-domain');
      if (domain !== String(services.domain_name ?? '')) params.domain_name = domain;
    }
    const tzName = deviceText('device-services-tz-name');
    const tzRaw = deviceText('device-services-tz-offset');
    if (tzName !== String(services.timezone?.name ?? '') || tzRaw !== String(services.timezone?.offset_minutes ?? '')) {
      params.timezone = {
        name: tzName, offset_minutes: deviceInteger('device-services-tz-offset', t('Abweichung von UTC (Minuten)'), -720, 840),
      };
    }
    const syslog = parseDeviceSyslog(deviceElement('device-services-syslog')?.value);
    const current = (services.syslog || []).map(entry => ({ host: entry.host, severity: entry.severity }));
    if (!sameDeviceList(syslog, current)) params.syslog = syslog;
  } catch (error) {
    return deviceFormError('device-services-error', error.message);
  }
  if (!Object.keys(params).length) return deviceFormError('device-services-error', t('Es wurde nichts geändert.'));
  return runDeviceChange(switchId, 'device-services', params, {
    title: t('Dienste ändern'), errorId: 'device-services-error', buttonId: 'device-services-preview',
  });
}

function readDeviceAaaRows(kind) {
  const rows = [...document.querySelectorAll(`.device-aaa-row[data-kind="${kind}"]`)];
  let changed = false;
  const servers = [];
  rows.forEach(row => {
    const field = name => row.querySelector(`[data-field="${name}"]`);
    const host = String(field('host')?.value ?? '').trim();
    const key = String(field('key')?.value ?? '');
    const original = row.dataset.originalHost || '';
    if (field('remove')?.checked) {
      changed = true;
      return;
    }
    if (!host) {
      if (original) changed = true;
      return;
    }
    const port = name => {
      const value = Number(field(name)?.value);
      if (!Number.isInteger(value) || value < 1 || value > 65535) {
        throw new Error(t('{field}: Bitte eine ganze Zahl von {min} bis {max} eingeben.', { field: host, min: 1, max: 65535 }));
      }
      return value;
    };
    const server = kind === 'radius'
      ? { host, auth_port: port('auth_port'), acct_port: port('acct_port') }
      : { host, port: port('port') };
    if (key) {
      server.key = key;
      changed = true;
    } else if (host !== original) {
      throw new Error(t('Für den neuen Server {host} ist ein Schlüssel erforderlich.', { host }));
    }
    servers.push(server);
  });
  return { servers, changed };
}

function submitDeviceAaa(switchId) {
  const sw = deviceTabState?.sw;
  const aaa = deviceTabState?.config?.aaa || {};
  const state = featureState(sw, 'device_aaa');
  const params = {};
  try {
    for (const kind of ['radius', 'tacacs']) {
      if (!deviceOptionAllowed(state, kind)) continue;
      const { servers, changed } = readDeviceAaaRows(kind);
      const strip = list => (list || []).map(server => (kind === 'radius'
        ? { host: server.host, auth_port: server.auth_port, acct_port: server.acct_port }
        : { host: server.host, port: server.port }));
      if (changed || !sameDeviceList(strip(servers), strip(aaa[kind]))) params[kind] = servers;
    }
  } catch (error) {
    return deviceFormError('device-aaa-error', error.message);
  } finally {
    document.querySelectorAll('.device-aaa-row .device-secret').forEach(field => { field.value = ''; });
  }
  if (deviceOptionAllowed(state, 'login_order')) {
    const order = deviceText('device-aaa-login-order');
    if (order && order !== (aaa.login_order || []).join(' ')) params.login_order = order.split(' ');
  }
  if (!Object.keys(params).length) return deviceFormError('device-aaa-error', t('Es wurde nichts geändert.'));
  return runDeviceChange(switchId, 'device-aaa', params, {
    title: t('AAA ändern'), errorId: 'device-aaa-error', buttonId: 'device-aaa-preview',
  });
}

function submitDeviceSsh(switchId) {
  const sw = deviceTabState?.sw;
  const ssh = deviceTabState?.config?.ssh || {};
  const state = featureState(sw, 'device_ssh');
  const params = {};
  try {
    if (deviceOptionAllowed(state, 'timeout') && deviceText('device-ssh-timeout') !== String(ssh.timeout_seconds ?? '')) {
      const timeout = deviceInteger('device-ssh-timeout', t('Leerlauf-Timeout (Sekunden, 60–3600)'), 60, 3600, { optional: true });
      if (timeout !== null) params.timeout_seconds = timeout;
    }
  } catch (error) {
    return deviceFormError('device-ssh-error', error.message);
  }
  const telnet = deviceBoolText('device-ssh-telnet');
  if (deviceOptionAllowed(state, 'telnet') && telnet !== null && telnet !== ssh.telnet_enabled) params.telnet_enabled = telnet;
  const web = deviceBoolText('device-ssh-web');
  if (deviceOptionAllowed(state, 'web') && web !== null && web !== ssh.web_enabled) params.web_enabled = web;
  if (!Object.keys(params).length) return deviceFormError('device-ssh-error', t('Es wurde nichts geändert.'));
  return runDeviceChange(switchId, 'device-ssh', params, {
    title: t('SSH und Zugang ändern'), errorId: 'device-ssh-error', buttonId: 'device-ssh-preview',
  });
}

function submitDeviceGateway(switchId) {
  const gateway = deviceText('device-l3-gateway');
  if (!gateway) return deviceFormError('device-l3-error', t('Bitte eine Gateway-Adresse eingeben.'));
  if (gateway === String(deviceTabState?.config?.l3?.default_gateway ?? '')) {
    return deviceFormError('device-l3-error', t('Es wurde nichts geändert.'));
  }
  return runDeviceChange(switchId, 'l3-gateway', { gateway }, {
    title: t('Standard-Gateway ändern'), errorId: 'device-l3-error', buttonId: 'device-gateway-preview',
  });
}

function submitDeviceRouteAdd(switchId) {
  let params;
  try {
    params = {
      prefix: deviceText('device-route-prefix'),
      prefix_length: deviceInteger('device-route-length', t('Präfixlänge'), 0, 32),
      next_hop: deviceText('device-route-next-hop'),
    };
    const distance = deviceInteger('device-route-distance', t('Distanz (optional)'), 1, 255, { optional: true });
    if (distance !== null) params.distance = distance;
  } catch (error) {
    return deviceFormError('device-l3-error', error.message);
  }
  if (!params.prefix || !params.next_hop) return deviceFormError('device-l3-error', t('Bitte Zielnetz und Next Hop angeben.'));
  return runDeviceChange(switchId, 'l3-route-add', params, {
    title: t('Route hinzufügen'), errorId: 'device-l3-error', buttonId: 'device-route-add',
  });
}

function submitDeviceAclCreate(switchId) {
  const name = deviceText('device-acl-name');
  if (!name) return deviceFormError('device-acl-error', t('Bitte einen ACL-Namen eingeben.'));
  const type = deviceText('device-acl-type') === 'standard' ? 'standard' : 'extended';
  return runDeviceChange(switchId, 'acl-create', { name, type }, {
    title: t('ACL {name} anlegen', { name }), errorId: 'device-acl-error', buttonId: 'device-acl-create',
  });
}

// --- Bearbeitungsdialog (SNMPv3, Benutzer, SVI, ACL-Eintrag, ACL-Bindung, QoS) ----

// `submit` liest die Felder, leert Geheimnisfelder und liefert {kind, params, title} oder wirft.
function openDeviceModal(switchId, { title, body, fill, submit }) {
  if (!requireEditPermission() || modalOperations.has('device-edit-modal')) return;
  clearDeviceSecrets();
  deviceModalState = { switchId: Number(switchId), session: currentSession, submit };
  deviceElement('device-edit-title').textContent = title;
  deviceElement('device-edit-body').innerHTML = body;
  deviceElement('device-edit-error').textContent = '';
  fill?.();
  setElementHidden('device-edit-modal', false);
}

function closeDeviceModal() {
  clearDeviceSecrets();
  setElementHidden('device-edit-modal', true);
  deviceModalState = null;
}

async function saveDeviceModal() {
  if (!requireEditPermission()) return;
  const state = deviceModalState;
  if (!state || state.session !== currentSession || modalOperations.has('device-edit-modal')) return;
  const errorElement = deviceElement('device-edit-error');
  let change;
  try {
    change = state.submit();
  } catch (error) {
    errorElement.textContent = error.message;
    return;
  } finally {
    clearDeviceSecrets();
  }
  const operation = beginModalOperation('device-edit-modal');
  if (!operation) return;
  errorElement.textContent = '';
  let result = null;
  try {
    result = await runSwitchChange(state.switchId, change.kind, change.params, { title: change.title });
    if (!modalOperationIsCurrent(operation) || !result) return;
    if (result.ok) {
      if (deviceModalState === state) closeDeviceModal();
    } else {
      errorElement.textContent = result.message || '';
    }
  } catch (error) {
    if (modalOperationIsCurrent(operation)) errorElement.textContent = error.message;
  } finally {
    finishModalOperation(operation);
    if (result) await reloadDeviceConfigAfterWrite(state.switchId, state.session);
  }
}

function openDeviceSnmpUserModal(switchId, user) {
  openDeviceModal(switchId, {
    title: user ? t('SNMPv3-Benutzer {name} ändern', { name: user.name }) : t('SNMPv3-Benutzer anlegen'),
    body: `
      <div class="field"><label for="device-snmp-name">${escapeHtml(t('Name'))}</label><input id="device-snmp-name" maxlength="32" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-snmp-auth">${escapeHtml(t('Authentifizierung'))}</label>
        <select id="device-snmp-auth"><option value="sha">SHA</option><option value="sha256">SHA-256</option></select>
      </div>
      <div class="field"><label for="device-snmp-auth-key">${escapeHtml(t('Auth-Schlüssel'))}</label><input id="device-snmp-auth-key" type="password" maxlength="64" autocomplete="new-password"></div>
      <div class="field"><label for="device-snmp-priv">${escapeHtml(t('Verschlüsselung'))}</label>
        <select id="device-snmp-priv"><option value="aes128">AES-128</option><option value="none">${escapeHtml(t('Keine'))}</option></select>
      </div>
      <div class="field"><label for="device-snmp-priv-key">${escapeHtml(t('Priv-Schlüssel'))}</label><input id="device-snmp-priv-key" type="password" maxlength="64" autocomplete="new-password"></div>
      <div class="field"><label for="device-snmp-access">${escapeHtml(t('Zugriff'))}</label>
        <select id="device-snmp-access"><option value="ro">${escapeHtml(t('Nur lesen'))}</option><option value="rw">${escapeHtml(t('Lesen und Schreiben'))}</option></select>
      </div>
      <p class="admin-muted">${escapeHtml(t('Schlüssel: 8–64 Zeichen. Sie werden nie angezeigt und müssen bei jeder Änderung neu eingegeben werden.'))}</p>`,
    fill() {
      setDeviceValue('device-snmp-name', user?.name);
      setDeviceDisabled(['device-snmp-name'], Boolean(user));
      setDeviceValue('device-snmp-auth', user?.auth === 'sha256' ? 'sha256' : 'sha');
      setDeviceValue('device-snmp-priv', user && !user.priv ? 'none' : 'aes128');
      setDeviceValue('device-snmp-access', user?.access === 'rw' ? 'rw' : 'ro');
    },
    submit() {
      const name = deviceText('device-snmp-name');
      const authKey = String(deviceElement('device-snmp-auth-key')?.value ?? '');
      const priv = deviceText('device-snmp-priv') === 'none' ? null : 'aes128';
      const privKey = String(deviceElement('device-snmp-priv-key')?.value ?? '');
      if (!name) throw new Error(t('Bitte einen Namen eingeben.'));
      if (!authKey) throw new Error(t('Bitte den Auth-Schlüssel eingeben.'));
      if (priv && !privKey) throw new Error(t('Bitte den Priv-Schlüssel eingeben.'));
      const params = {
        name, auth: deviceText('device-snmp-auth') === 'sha256' ? 'sha256' : 'sha', auth_key: authKey,
        priv, access: deviceText('device-snmp-access') === 'rw' ? 'rw' : 'ro',
      };
      if (priv) params.priv_key = privKey;
      return { kind: 'device-snmp-user-set', params, title: t('SNMPv3-Benutzer {name} setzen', { name }) };
    },
  });
}

function openDeviceUserModal(switchId, user) {
  openDeviceModal(switchId, {
    title: user ? t('Benutzer {name} ändern', { name: user.name }) : t('Benutzer anlegen'),
    body: `
      <div class="field"><label for="device-user-name">${escapeHtml(t('Benutzername'))}</label><input id="device-user-name" maxlength="32" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-user-privilege">${escapeHtml(t('Rechte'))}</label>
        <select id="device-user-privilege"><option value="admin">${escapeHtml(t('Administrator'))}</option><option value="read_only">${escapeHtml(t('Nur lesen'))}</option></select>
      </div>
      <div class="field"><label for="device-user-password">${escapeHtml(t('Passwort'))}</label><input id="device-user-password" type="password" maxlength="64" autocomplete="new-password"></div>
      <p class="admin-muted">${escapeHtml(t('Passwort: 8–64 Zeichen, bei neuen Benutzern Pflicht. Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden.'))}</p>`,
    fill() {
      setDeviceValue('device-user-name', user?.name);
      setDeviceDisabled(['device-user-name'], Boolean(user));
      setDeviceValue('device-user-privilege', user?.privilege === 'admin' ? 'admin' : 'read_only');
      const password = deviceElement('device-user-password');
      if (password) password.placeholder = user ? t('unverändert') : '';
    },
    submit() {
      const name = deviceText('device-user-name');
      const password = String(deviceElement('device-user-password')?.value ?? '');
      if (!name) throw new Error(t('Bitte einen Benutzernamen eingeben.'));
      if (!user && !password) throw new Error(t('Für neue Benutzer ist ein Passwort erforderlich.'));
      const params = { name, privilege: deviceText('device-user-privilege') === 'admin' ? 'admin' : 'read_only' };
      if (password) params.password = password;
      return { kind: 'device-user-set', params, title: t('Benutzer {name} setzen', { name }) };
    },
  });
}

function openDeviceSviModal(switchId, svi) {
  const relayAllowed = deviceOptionAllowed(featureState(switchById(switchId), 'device_l3'), 'dhcp_relay');
  openDeviceModal(switchId, {
    title: svi ? t('SVI für VLAN {vlan} ändern', { vlan: svi.vlan }) : t('SVI anlegen'),
    body: `
      <div class="field"><label for="device-svi-vlan">${escapeHtml(t('VLAN-ID'))}</label><input id="device-svi-vlan" type="number" min="1" max="4094" step="1"></div>
      <div class="field"><label for="device-svi-address">${escapeHtml(t('IP-Adresse'))}</label><input id="device-svi-address" maxlength="15" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-svi-length">${escapeHtml(t('Präfixlänge'))}</label><input id="device-svi-length" type="number" min="1" max="32" step="1"></div>
      <div class="field"><label for="device-svi-relay">${escapeHtml(t('DHCP-Relay-Server (max. 4)'))}</label><input id="device-svi-relay" autocomplete="off" spellcheck="false"></div>`,
    fill() {
      setDeviceValue('device-svi-vlan', svi?.vlan);
      setDeviceDisabled(['device-svi-vlan'], Boolean(svi));
      setDeviceValue('device-svi-address', svi?.address);
      setDeviceValue('device-svi-length', svi?.prefix_length);
      setDeviceValue('device-svi-relay', (svi?.dhcp_relay || []).join(', '));
      setDeviceDisabled(['device-svi-relay'], !relayAllowed);
    },
    submit() {
      const vlan = deviceInteger('device-svi-vlan', t('VLAN-ID'), 1, 4094);
      const address = deviceText('device-svi-address');
      if (!address) throw new Error(t('Bitte eine IP-Adresse eingeben.'));
      const params = {
        vlan, address, prefix_length: deviceInteger('device-svi-length', t('Präfixlänge'), 1, 32),
        dhcp_relay: relayAllowed ? deviceList(deviceText('device-svi-relay')) : (svi?.dhcp_relay || []),
      };
      return { kind: 'l3-svi-set', params, title: t('SVI für VLAN {vlan} setzen', { vlan }) };
    },
  });
}

function openDeviceAclEntryModal(switchId, acl) {
  const standard = acl?.type === 'standard';
  const nextSeq = Math.max(0, ...(acl?.entries || []).map(entry => Number(entry.seq) || 0)) + 10;
  openDeviceModal(switchId, {
    title: t('ACL {name}: Eintrag hinzufügen', { name: acl.name }),
    body: `
      <div class="device-form-grid">
        <div class="field"><label for="device-acl-entry-seq">${escapeHtml(t('Nr.'))}</label><input id="device-acl-entry-seq" type="number" min="1" max="2147483647" step="1"></div>
        <div class="field"><label for="device-acl-entry-action">${escapeHtml(t('Aktion'))}</label>
          <select id="device-acl-entry-action"><option value="permit">permit</option><option value="deny">deny</option></select>
        </div>
        <div class="field"><label for="device-acl-entry-protocol">${escapeHtml(t('Protokoll'))}</label>
          <select id="device-acl-entry-protocol"><option value="ip">ip</option><option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option></select>
        </div>
        <div class="field"><label for="device-acl-entry-src">${escapeHtml(t('Quelle'))}</label><input id="device-acl-entry-src" maxlength="15" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="device-acl-entry-src-len">${escapeHtml(t('Quell-Präfixlänge'))}</label><input id="device-acl-entry-src-len" type="number" min="0" max="32" step="1"></div>
        <div class="field"><label for="device-acl-entry-dst">${escapeHtml(t('Ziel (leer = any)'))}</label><input id="device-acl-entry-dst" maxlength="15" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="device-acl-entry-dst-len">${escapeHtml(t('Ziel-Präfixlänge'))}</label><input id="device-acl-entry-dst-len" type="number" min="0" max="32" step="1"></div>
        <div class="field"><label for="device-acl-entry-port-op">${escapeHtml(t('Zielport'))}</label>
          <select id="device-acl-entry-port-op"><option value="">${escapeHtml(t('beliebig'))}</option><option value="eq">eq</option><option value="range">range</option></select>
        </div>
        <div class="field"><label for="device-acl-entry-port">${escapeHtml(t('Port'))}</label><input id="device-acl-entry-port" type="number" min="1" max="65535" step="1"></div>
        <div class="field"><label for="device-acl-entry-port-end">${escapeHtml(t('Port bis'))}</label><input id="device-acl-entry-port-end" type="number" min="1" max="65535" step="1"></div>
      </div>
      <p class="admin-muted">${escapeHtml(standard ? t('Standard-ACLs prüfen nur die Quelladresse.') : t('Quelle 0.0.0.0 mit Präfixlänge 0 = any.'))}</p>`,
    fill() {
      setDeviceValue('device-acl-entry-seq', nextSeq);
      setDeviceValue('device-acl-entry-src', '0.0.0.0');
      setDeviceValue('device-acl-entry-src-len', 0);
      setDeviceDisabled(['device-acl-entry-protocol', 'device-acl-entry-dst', 'device-acl-entry-dst-len',
        'device-acl-entry-port-op', 'device-acl-entry-port', 'device-acl-entry-port-end'], standard);
    },
    submit() {
      const params = {
        name: acl.name,
        seq: deviceInteger('device-acl-entry-seq', t('Nr.'), 1, 2147483647),
        action: deviceText('device-acl-entry-action') === 'deny' ? 'deny' : 'permit',
        protocol: standard ? 'ip' : (deviceText('device-acl-entry-protocol') || 'ip'),
        src: deviceText('device-acl-entry-src'),
        src_len: deviceInteger('device-acl-entry-src-len', t('Quell-Präfixlänge'), 0, 32),
      };
      if (!params.src) throw new Error(t('Bitte eine Quelladresse eingeben.'));
      if (!standard) {
        const dst = deviceText('device-acl-entry-dst');
        if (dst) {
          params.dst = dst;
          params.dst_len = deviceInteger('device-acl-entry-dst-len', t('Ziel-Präfixlänge'), 0, 32);
        }
        const op = deviceText('device-acl-entry-port-op');
        if (op) {
          params.dst_port_op = op;
          params.dst_port = deviceInteger('device-acl-entry-port', t('Port'), 1, 65535);
          if (op === 'range') params.dst_port_end = deviceInteger('device-acl-entry-port-end', t('Port bis'), 1, 65535);
        }
      }
      return { kind: 'acl-entry-add', params, title: t('ACL {name}: Eintrag hinzufügen', { name: acl.name }) };
    },
  });
}

// Bindungsziel aus dem Interface-Namen: VLAN-Interface oder Port.
function deviceAclTarget(name) {
  return /^(?:interface\s+)?vlan\s*\d+$/i.test(String(name).trim()) ? 'vlan' : 'port';
}

function openDeviceAclBindModal(switchId, aclName) {
  const state = featureState(switchById(switchId), 'acl');
  openDeviceModal(switchId, {
    title: t('ACL {name} binden', { name: aclName }),
    body: `
      <div class="field"><label for="device-acl-bind-interface">${escapeHtml(t('Interface (Port oder VLAN-Interface, z. B. vlan10)'))}</label><input id="device-acl-bind-interface" maxlength="64" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-acl-bind-direction">${escapeHtml(t('Richtung'))}</label>
        <select id="device-acl-bind-direction"><option value="in">${escapeHtml(t('eingehend'))}</option><option value="out">${escapeHtml(t('ausgehend'))}</option></select>
      </div>
      <p class="admin-muted">${escapeHtml(t('Unterstützte Bindungen: {targets}', { targets: Array.isArray(state.options) ? state.options.join(', ') : t('alle') }))}</p>`,
    submit() {
      const name = deviceText('device-acl-bind-interface');
      const direction = deviceText('device-acl-bind-direction') === 'out' ? 'out' : 'in';
      if (!name) throw new Error(t('Bitte ein Interface eingeben.'));
      if (!deviceOptionAllowed(state, `${deviceAclTarget(name)}_${direction}`)) {
        throw new Error(t('Diese Bindung wird vom Switch nicht unterstützt.'));
      }
      return {
        kind: 'acl-bind', params: { name: aclName, interface: name, direction },
        title: t('ACL {name} an {interface} binden', { name: aclName, interface: name }),
      };
    },
  });
}

function openDeviceQosModal(switchId, interfaceName) {
  const sw = switchById(switchId);
  const qos = deviceTabState?.config?.qos || {};
  const voiceSupported = featureState(sw, 'qos_voice').supported;
  openDeviceModal(switchId, {
    title: interfaceName ? t('QoS für {interface}', { interface: interfaceName }) : t('QoS für einen Port einstellen'),
    body: `
      <div class="field"><label for="device-qos-interface">${escapeHtml(t('Port'))}</label><input id="device-qos-interface" maxlength="64" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="device-qos-trust">${escapeHtml(t('Trust'))}</label>
        <select id="device-qos-trust">
          <option value="">${escapeHtml(t('Unverändert'))}</option>
          <option value="none">${escapeHtml(t('Nicht vertrauen'))}</option>
          <option value="cos">${escapeHtml(t('CoS vertrauen'))}</option>
          <option value="dscp">${escapeHtml(t('DSCP vertrauen'))}</option>
        </select>
      </div>
      <div class="field"><label for="device-qos-voice">${escapeHtml(t('Voice-Vorlage'))}</label>
        <select id="device-qos-voice">
          <option value="">${escapeHtml(t('Unverändert'))}</option>
          <option value="true">${escapeHtml(t('Ein'))}</option>
          <option value="false">${escapeHtml(t('Aus'))}</option>
        </select>
      </div>`,
    fill() {
      setDeviceValue('device-qos-interface', interfaceName);
      setDeviceDisabled(['device-qos-interface'], Boolean(interfaceName));
      const trust = deviceElement('device-qos-trust');
      if (trust) markIncompatibleOptions(trust, featureState(sw, 'qos').options);
      setDeviceValue('device-qos-trust', '');
      setDeviceValue('device-qos-voice', '');
      setDeviceDisabled(['device-qos-voice'], !voiceSupported);
    },
    submit() {
      const name = deviceText('device-qos-interface');
      if (!name) throw new Error(t('Bitte ein Interface eingeben.'));
      const params = { interface: name };
      const trust = deviceText('device-qos-trust');
      if (trust && trust !== qos.ports?.[name]?.trust) params.trust = trust;
      const voice = deviceBoolText('device-qos-voice');
      if (voiceSupported && voice !== null && voice !== qos.voice_preset?.[name]) params.voice_preset = voice;
      if (Object.keys(params).length === 1) throw new Error(t('Es wurde nichts geändert.'));
      return { kind: 'qos-port', params, title: t('QoS für {interface}', { interface: name }) };
    },
  });
}

document.getElementById('device-edit-cancel').addEventListener('click', closeDeviceModal);
document.getElementById('device-edit-save').addEventListener('click', saveDeviceModal);

registerSessionHooks({
  closePrivilegedModals: () => closeDeviceModal(),
  clearSensitiveFields: () => clearDeviceSecrets({ includePanels: true }),
  reset: () => {
    deviceConfigRequestSequence += 1;
    deviceTabState = null;
    deviceChangeInProgress = false;
    closeDeviceModal();
  },
});
