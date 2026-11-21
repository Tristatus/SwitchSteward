// --- Tab "Port-Sicherheit" and port-profile application ---

let securityRequestSequence = 0;
// switchId -> {global, ports} of the last rendered security tab; row buttons look their port up here.
const securityTabData = new Map();
let securityModalState = null;
let interfaceProfileState = null;

// Fields of the shared security form (`#security-modal` with prefix "sec", admin port-profile modal with
// prefix "profile-sec"). `feature`/`option` gate the control on the selected switch.
const SECURITY_FORM_FIELDS = Object.freeze([
  { block: 'port_security', key: 'enabled', id: 'ps-enabled', type: 'bool', feature: 'port_security' },
  { block: 'port_security', key: 'max_macs', id: 'ps-max', type: 'int', min: 1, max: 1024, feature: 'port_security', label: () => t('Maximale MAC-Adressen') },
  { block: 'port_security', key: 'sticky', id: 'ps-sticky', type: 'bool', feature: 'port_security_sticky' },
  { block: 'port_security', key: 'violation', id: 'ps-violation', type: 'choice', feature: 'port_security', options: true },
  { block: 'dot1x', key: 'mode', id: 'dot1x-mode', type: 'choice', feature: 'dot1x', options: true, always: ['off'] },
  { block: 'dot1x', key: 'host_mode', id: 'dot1x-host-mode', type: 'choice', feature: 'dot1x_host_mode', options: true },
  { block: 'dot1x', key: 'guest_vlan', id: 'dot1x-guest', type: 'int', min: 0, max: 4094, feature: 'dot1x_fallback_vlans', label: () => t('Gast-VLAN') },
  { block: 'dot1x', key: 'auth_fail_vlan', id: 'dot1x-authfail', type: 'int', min: 0, max: 4094, feature: 'dot1x_fallback_vlans', label: () => t('VLAN bei fehlgeschlagener Anmeldung') },
  { block: 'stp_guard', key: 'bpdu_guard', id: 'bpdu-guard', type: 'bool', feature: 'stp_guard', option: 'bpdu_guard' },
  { block: 'stp_guard', key: 'root_guard', id: 'root-guard', type: 'bool', feature: 'stp_guard', option: 'root_guard' },
  { block: 'stp_guard', key: 'loop_guard', id: 'loop-guard', type: 'bool', feature: 'stp_guard', option: 'loop_guard' },
  { block: 'storm_control', key: 'broadcast', id: 'storm-broadcast', type: 'percent', feature: 'storm_control', option: 'broadcast', label: () => t('Broadcast') },
  { block: 'storm_control', key: 'multicast', id: 'storm-multicast', type: 'percent', feature: 'storm_control', option: 'multicast', label: () => t('Multicast') },
  { block: 'storm_control', key: 'unknown_unicast', id: 'storm-unknown-unicast', type: 'percent', feature: 'storm_control', option: 'unknown_unicast', label: () => t('Unbekannter Unicast') },
  { block: 'storm_control', key: 'action', id: 'storm-action', type: 'choice', feature: 'storm_control_action', options: true },
  { block: null, key: 'dhcp_snooping_trust', id: 'dhcp-trust', type: 'bool', feature: 'dhcp_snooping' },
  { block: null, key: 'arp_inspection_trust', id: 'arp-trust', type: 'bool', feature: 'arp_inspection' },
  { block: null, key: 'ip_source_guard', id: 'ipsg', type: 'bool', feature: 'ip_source_guard' },
]);

const securityFormElement = (prefix, field) => document.getElementById(`${prefix}-${field.id}`);

// Fills the form from a settings object (body shape of port-security-configure); missing values stay empty.
function fillSecurityForm(prefix, values) {
  const source = values && typeof values === 'object' ? values : {};
  for (const field of SECURITY_FORM_FIELDS) {
    const block = field.block ? source[field.block] : source;
    const value = block && typeof block === 'object' ? block[field.key] : undefined;
    const element = securityFormElement(prefix, field);
    if (field.type === 'bool') element.value = typeof value === 'boolean' ? String(value) : '';
    else element.value = value === null || value === undefined ? '' : String(value);
  }
}

function readSecurityFieldValue(prefix, field) {
  const raw = String(securityFormElement(prefix, field).value ?? '').trim();
  if (!raw) return undefined;
  if (field.type === 'bool') return raw === 'true';
  if (field.type === 'choice') return raw;
  const number = Number(raw);
  if (field.type === 'int') {
    if (!/^\d+$/.test(raw) || number < field.min || number > field.max) {
      throw new Error(t('{field}: Bitte eine ganze Zahl von {min} bis {max} eingeben.', { field: field.label(), min: field.min, max: field.max }));
    }
    return number;
  }
  if (!/^\d+(?:\.\d{1,2})?$/.test(raw) || number > 100) {
    throw new Error(t('{field}: Bitte einen Prozentwert von 0 bis 100 eingeben.', { field: field.label() }));
  }
  return number;
}

// Settings object of every filled field; throws an Error with a German message for invalid input.
function readSecurityForm(prefix) {
  const settings = {};
  for (const field of SECURITY_FORM_FIELDS) {
    const value = readSecurityFieldValue(prefix, field);
    if (value === undefined) continue;
    if (!field.block) settings[field.key] = value;
    else settings[field.block] = { ...(settings[field.block] || {}), [field.key]: value };
  }
  if (settings.port_security && settings.port_security.enabled === undefined) {
    throw new Error(t('Port-Security: Bitte ausdrücklich ein- oder ausschalten.'));
  }
  if (settings.dot1x && settings.dot1x.mode === undefined) {
    throw new Error(t('802.1X: Bitte den Modus ausdrücklich wählen.'));
  }
  return settings;
}

// Capability state of one form field on a switch (option-level gates included).
function securityFieldState(sw, field) {
  const state = featureState(sw, field.feature);
  if (state.supported && field.option && Array.isArray(state.options) && !state.options.includes(field.option)) {
    return { ...state, supported: false };
  }
  return state;
}

function gateSecurityForm(prefix, sw, disabled) {
  for (const field of SECURITY_FORM_FIELDS) {
    const element = securityFormElement(prefix, field);
    const state = securityFieldState(sw, field);
    if (field.options) {
      markIncompatibleOptions(element, Array.isArray(state.options) ? [...(field.always || []), ...state.options] : null);
    }
    element.disabled = disabled || !state.supported;
    applyIncompatibleState(element, state);
  }
}

// --- VLAN lists of the global panel ---------------------------------------

function formatVlanIds(ids) {
  const sorted = [...new Set((Array.isArray(ids) ? ids : []).map(Number).filter(Number.isInteger))].sort((a, b) => a - b);
  const ranges = [];
  for (const id of sorted) {
    const last = ranges.at(-1);
    if (last && id === last[1] + 1) last[1] = id;
    else ranges.push([id, id]);
  }
  return ranges.map(([first, last]) => (first === last ? String(first) : `${first}-${last}`)).join(',');
}

// Normalised VLAN list ("" = none); throws for anything but IDs 1–4094 and ranges.
function normalizeSecurityVlans(value, label) {
  const normalized = String(value ?? '').trim().replace(/\s*,\s*/g, ',').replace(/\s*-\s*/g, '-');
  if (!normalized) return '';
  const invalid = () => new Error(t('{field}: Bitte VLAN-IDs von 1 bis 4094 oder Bereiche (z. B. 10,20-30) eingeben.', { field: label }));
  if (!/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/.test(normalized)) throw invalid();
  const ids = [];
  for (const item of normalized.split(',')) {
    const [first, last = first] = item.split('-').map(Number);
    if (first < 1 || last > 4094 || first > last) throw invalid();
    for (let id = first; id <= last; id += 1) ids.push(id);
  }
  return formatVlanIds(ids);
}

// --- Tab rendering ----------------------------------------------------------

function securityYesNo(value) {
  if (value === true) return t('ja');
  if (value === false) return t('nein');
  return '—';
}

function securityPortSecurityText(block) {
  if (!block || typeof block !== 'object' || typeof block.enabled !== 'boolean') return '—';
  if (!block.enabled) return t('aus');
  const parts = [t('an')];
  if (block.max_macs != null) parts.push(t('max. {count}', { count: block.max_macs }));
  if (block.sticky === true) parts.push('sticky');
  if (hasValue(block.violation)) parts.push(String(block.violation));
  if (block.violation_count != null) parts.push(t('Verstöße: {count}', { count: block.violation_count }));
  return parts.join(' · ');
}

function securityDot1xText(block) {
  if (!block || typeof block !== 'object' || !hasValue(block.mode)) return '—';
  if (block.mode === 'off') return t('aus');
  return [block.mode, block.host_mode, block.status].filter(hasValue).map(String).join(' · ');
}

function securityGuardsText(block) {
  if (!block || typeof block !== 'object') return '—';
  const active = [['bpdu_guard', 'BPDU Guard'], ['root_guard', 'Root Guard'], ['loop_guard', 'Loop Guard']]
    .filter(([key]) => block[key] === true).map(([, label]) => label);
  if (active.length) return active.join(', ');
  return ['bpdu_guard', 'root_guard', 'loop_guard'].some(key => block[key] === false) ? t('aus') : '—';
}

function securityStormText(block) {
  if (!block || typeof block !== 'object') return '—';
  const parts = [['broadcast', 'BC'], ['multicast', 'MC'], ['unknown_unicast', 'UU']]
    .filter(([key]) => block[key] != null && Number(block[key]) > 0).map(([key, label]) => `${label} ${block[key]} %`);
  if (!parts.length) return t('aus');
  if (hasValue(block.action)) parts.push(String(block.action));
  return parts.join(' · ');
}

function renderSecurityGlobalPanel(sw, global, canEdit) {
  const dhcp = global?.dhcp_snooping && typeof global.dhcp_snooping === 'object' ? global.dhcp_snooping : null;
  const arp = global?.arp_inspection && typeof global.arp_inspection === 'object' ? global.arp_inspection : null;
  const dot1x = global?.dot1x && typeof global.dot1x === 'object' ? global.dot1x : null;
  const dhcpState = featureState(sw, 'dhcp_snooping');
  const arpState = featureState(sw, 'arp_inspection');
  const dot1xState = featureState(sw, 'dot1x');
  const control = state => (canEdit && state.supported ? '' : ' disabled') + (state.supported ? '' : ` class="is-incompatible" title="${escapeHtml(incompatibleTitle(state))}"`);
  return `
    <div class="panel-box">
      <strong>${escapeHtml(t('Global'))}</strong>
      <label style="display: block; font-size: 12px; margin: 8px 0;"><input id="security-global-dhcp-enabled" type="checkbox" style="width: auto;"${dhcp?.enabled === true ? ' checked' : ''}${control(dhcpState)}> ${escapeHtml(t('DHCP-Snooping aktiv'))}</label>
      <div class="field"><label for="security-global-dhcp-vlans">${escapeHtml(t('DHCP-Snooping-VLANs'))}</label><input id="security-global-dhcp-vlans" value="${escapeHtml(formatVlanIds(dhcp?.vlans))}" placeholder="${escapeHtml(t('z. B. 10,20-30'))}"${control(dhcpState)}></div>
      <div class="field"><label for="security-global-arp-vlans">${escapeHtml(t('Dynamic-ARP-Inspection-VLANs'))}</label><input id="security-global-arp-vlans" value="${escapeHtml(formatVlanIds(arp?.vlans))}" placeholder="${escapeHtml(t('z. B. 10,20-30'))}"${control(arpState)}></div>
      <label style="display: block; font-size: 12px; margin: 8px 0;"><input id="security-global-dot1x-enabled" type="checkbox" style="width: auto;"${dot1x?.enabled === true ? ' checked' : ''}${control(dot1xState)}> ${escapeHtml(t('802.1X global aktiv'))}</label>
      <div id="security-global-error" class="wlan-form-error" role="alert"></div>
      ${canEdit ? `<div class="flex-row" style="justify-content: flex-end;"><button id="btn-security-global-save" class="primary">${escapeHtml(t('Vorschau'))}</button></div>` : ''}
    </div>`;
}

function renderSecurityTable(switchId, data, warnings) {
  const sw = switchById(switchId);
  const canEdit = currentSessionCanEdit();
  const panel = renderSecurityGlobalPanel(sw, data.global, canEdit);
  if (data.ports.length === 0) {
    return `${renderInventoryWarnings(warnings)}${panel}<div class="empty-state">${escapeHtml(t('Keine Ports gefunden.'))}</div>`;
  }
  const rows = data.ports.map(port => {
    const name = escapeHtml(port.interface);
    const actions = canEdit
      ? `<td class="table-actions"><div class="table-actions-inner"><button class="security-edit-btn" data-interface="${name}">${escapeHtml(t('Bearbeiten'))}</button></div></td>`
      : '';
    return `
        <tr class="security-row" data-interface="${name}">
          <td>${name}</td>
          <td>${escapeHtml(port.status || '—')}</td>
          <td>${escapeHtml(port.mode || '—')}</td>
          <td>${escapeHtml(securityPortSecurityText(port.port_security))}</td>
          <td>${escapeHtml(securityDot1xText(port.dot1x))}</td>
          <td>${escapeHtml(securityGuardsText(port.stp_guard))}</td>
          <td>${escapeHtml(securityStormText(port.storm_control))}</td>
          <td>${escapeHtml(`${securityYesNo(port.dhcp_snooping_trust)} / ${securityYesNo(port.arp_inspection_trust)}`)}</td>
          <td>${escapeHtml(securityYesNo(port.ip_source_guard))}</td>
          ${actions}
        </tr>`;
  }).join('');
  const headers = [t('Port'), t('Status'), t('Modus'), t('Port-Security'), t('802.1X'), t('Guards'), t('Storm-Control'), t('Trust DHCP/DAI'), t('IP Source Guard')];
  const filter = (column, label) => `<th><input class="table-filter" type="search" data-column="${column}" placeholder="${escapeHtml(t('{column} suchen', { column: label }))}" aria-label="${escapeHtml(t('{column} suchen', { column: label }))}"></th>`;
  return `
    ${renderInventoryWarnings(warnings)}
    ${panel}
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>${headers.map(label => `<th>${escapeHtml(label)}</th>`).join('')}${canEdit ? '<th></th>' : ''}</tr>
          <tr class="filter-row">${headers.map((label, index) => filter(index, label)).join('')}${canEdit ? '<th></th>' : ''}</tr>
        </thead>
        <tbody>
          ${rows}
          <tr id="no-security-results" class="hidden"><td colspan="${headers.length + (canEdit ? 1 : 0)}" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden Ports gefunden.'))}</td></tr>
        </tbody>
      </table>
    </div>`;
}

async function loadPortSecurity(switchId) {
  const container = document.getElementById('security-container');
  if (!container) return;
  const session = currentSession;
  const sequence = ++securityRequestSequence;
  const isCurrent = () => sequence === securityRequestSequence && currentSession === session
    && container === document.getElementById('security-container');
  container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Port-Sicherheit …'))}</div>`;
  try {
    const result = await api(`/api/switches/${switchId}/port-security`);
    if (!isCurrent()) return;
    if (!Array.isArray(result?.ports)) throw new Error(t('Der Switch lieferte keine gültigen Sicherheitsdaten.'));
    const data = {
      global: result.global && typeof result.global === 'object' ? result.global : {},
      ports: result.ports.filter(port => port && typeof port === 'object' && hasValue(port.interface)),
    };
    securityTabData.set(Number(switchId), data);
    container.innerHTML = renderSecurityTable(switchId, data, result.warnings);
    if (data.ports.length) attachTableFilters(container, '.security-row', '#no-security-results');
    document.getElementById('btn-security-global-save')?.addEventListener('click', () => saveSecurityGlobal(switchId));
    container.querySelectorAll('.security-edit-btn').forEach(button => {
      button.addEventListener('click', () => openSecurityModal(switchId, button.dataset.interface));
    });
  } catch (error) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(error.message)}</div>`;
  }
}

function reloadSecurityAfterWrite(switchId, session) {
  if (currentSession !== session || Number(currentSwitchId) !== Number(switchId)) return;
  if (document.getElementById('security-container')) void loadPortSecurity(switchId);
}

// --- Global settings ----------------------------------------------------------

// Body of security-global-configure with the changed parts only (null = nothing changed).
function securityGlobalChanges(sw, global) {
  const original = {
    dhcpEnabled: global?.dhcp_snooping?.enabled === true,
    dhcpVlans: formatVlanIds(global?.dhcp_snooping?.vlans),
    arpVlans: formatVlanIds(global?.arp_inspection?.vlans),
    dot1x: global?.dot1x?.enabled === true,
  };
  const body = {};
  if (featureState(sw, 'dhcp_snooping').supported) {
    const enabled = document.getElementById('security-global-dhcp-enabled').checked === true;
    const vlans = normalizeSecurityVlans(document.getElementById('security-global-dhcp-vlans').value, t('DHCP-Snooping-VLANs'));
    if (enabled !== original.dhcpEnabled || vlans !== original.dhcpVlans) {
      body.dhcp_snooping = { enabled };
      if (vlans !== original.dhcpVlans) body.dhcp_snooping.vlans = vlans;
    }
  }
  if (featureState(sw, 'arp_inspection').supported) {
    const vlans = normalizeSecurityVlans(document.getElementById('security-global-arp-vlans').value, t('Dynamic-ARP-Inspection-VLANs'));
    if (vlans !== original.arpVlans) body.arp_inspection = { vlans };
  }
  if (featureState(sw, 'dot1x').supported) {
    const enabled = document.getElementById('security-global-dot1x-enabled').checked === true;
    if (enabled !== original.dot1x) body.dot1x = { enabled };
  }
  return Object.keys(body).length ? body : null;
}

async function saveSecurityGlobal(switchId) {
  if (!requireEditPermission()) return;
  const data = securityTabData.get(Number(switchId));
  if (!data) return;
  const error = document.getElementById('security-global-error');
  error.textContent = '';
  let body;
  try {
    body = securityGlobalChanges(switchById(switchId), data.global);
  } catch (failure) {
    error.textContent = failure.message;
    return;
  }
  if (!body) {
    error.textContent = t('Es wurde nichts geändert.');
    return;
  }
  const session = currentSession;
  try {
    const result = await runSwitchChange(switchId, 'security-global-configure', body, { title: t('Globale Port-Sicherheit ändern') });
    if (result?.ok) reloadSecurityAfterWrite(switchId, session);
  } catch (failure) {
    if (currentSession === session && document.getElementById('security-global-error') === error) error.textContent = failure.message;
  }
}

// --- Port modal ---------------------------------------------------------------

function openSecurityModal(switchId, port) {
  if (!requireEditPermission() || modalOperations.has('security-modal')) return;
  const entry = (securityTabData.get(Number(switchId))?.ports || []).find(row => String(row.interface) === String(port));
  if (!entry) return;
  const sw = switchById(switchId);
  document.getElementById('security-modal-title').textContent = t('Port-Sicherheit {port}', { port: entry.interface });
  document.getElementById('security-modal-error').textContent = '';
  fillSecurityForm('sec', entry);
  gateSecurityForm('sec', sw, false);
  let original = {};
  try {
    original = readSecurityForm('sec');
  } catch {
    original = {};
  }
  securityModalState = { switchId: Number(switchId), port: String(entry.interface), session: currentSession, original };
  setElementHidden('security-modal', false);
}

function closeSecurityModal() {
  const operation = modalOperations.get('security-modal');
  if (operation) finishModalOperation(operation);
  securityModalState = null;
  setElementHidden('security-modal', true);
}

// Body of port-security-configure: only sub-objects/fields that differ from the loaded values.
function securityModalChanges(state) {
  const current = readSecurityForm('sec');
  const body = { interface: state.port };
  for (const key of new Set([...Object.keys(current), ...Object.keys(state.original)])) {
    if (current[key] === undefined) continue;
    if (JSON.stringify(current[key]) !== JSON.stringify(state.original[key])) body[key] = current[key];
  }
  return Object.keys(body).length > 1 ? body : null;
}

async function saveSecurityModal() {
  const state = securityModalState;
  if (!state || state.session !== currentSession || !requireEditPermission()) return;
  const error = document.getElementById('security-modal-error');
  let body;
  try {
    body = securityModalChanges(state);
  } catch (failure) {
    error.textContent = failure.message;
    return;
  }
  if (!body) {
    error.textContent = t('Es wurde nichts geändert.');
    return;
  }
  error.textContent = '';
  const operation = beginModalOperation('security-modal');
  if (!operation) return;
  try {
    const result = await runSwitchChange(state.switchId, 'port-security-configure', body, {
      title: t('Port-Sicherheit {port}', { port: state.port }),
    });
    if (!modalOperationIsCurrent(operation) || securityModalState !== state || !result) return;
    if (!result.ok) {
      error.textContent = result.message || t('Der Switch hat die Konfiguration abgelehnt.');
      return;
    }
    closeSecurityModal();
    reloadSecurityAfterWrite(state.switchId, state.session);
  } catch (failure) {
    if (modalOperationIsCurrent(operation) && securityModalState === state) error.textContent = failure.message;
  } finally {
    finishModalOperation(operation);
  }
}

document.getElementById('security-cancel').addEventListener('click', () => {
  if (!modalOperations.has('security-modal')) closeSecurityModal();
});
document.getElementById('security-save').addEventListener('click', saveSecurityModal);

// --- Port profiles in the port dialog (admin only) -----------------------------

// Called by openInterfaceModal; the list is loaded on first use of the selector.
function initInterfaceProfileSelector(switchId, port, session) {
  interfaceProfileState = { switchId: Number(switchId), port, session, loaded: false, loading: false, busy: false };
  const select = document.getElementById('intf-profile');
  select.innerHTML = `<option value="">${escapeHtml(t('Profil wählen …'))}</option>`;
  select.value = '';
  setElementHidden('intf-profile-row', !currentSessionCanEdit());
}

// Called by updateInterfaceModalControls.
function updateInterfaceProfileControls(fieldsDisabled) {
  const state = interfaceProfileState;
  const canEdit = currentSessionCanEdit() && state?.session === currentSession;
  setElementHidden('intf-profile-row', !canEdit);
  const select = document.getElementById('intf-profile');
  select.disabled = !canEdit || fieldsDisabled || state.busy;
  document.getElementById('intf-profile-apply').disabled = select.disabled || !select.value || state.loading;
}

async function loadInterfaceProfiles() {
  const state = interfaceProfileState;
  if (!state || state.loaded || state.loading || state.session !== currentSession || !currentSessionCanEdit()) return;
  state.loading = true;
  const select = document.getElementById('intf-profile');
  try {
    const result = await api('/api/port-profiles');
    if (interfaceProfileState !== state || state.session !== currentSession) return;
    const profiles = Array.isArray(result?.profiles) ? result.profiles.filter(profile => profile && hasValue(profile.id)) : [];
    select.innerHTML = `<option value="">${escapeHtml(profiles.length ? t('Profil wählen …') : t('Keine Port-Profile vorhanden.'))}</option>`
      + profiles.map(profile => `<option value="${escapeHtml(profile.id)}">${escapeHtml(profile.name)}${hasValue(profile.description) ? ` – ${escapeHtml(profile.description)}` : ''}</option>`).join('');
    state.loaded = true;
  } catch (error) {
    if (interfaceProfileState === state) document.getElementById('intf-modal-error').textContent = error.message;
  } finally {
    if (interfaceProfileState === state) {
      state.loading = false;
      updateInterfaceModalControls();
    }
  }
}

async function applyInterfaceProfile() {
  const state = interfaceProfileState;
  if (!state || state.session !== currentSession || !requireEditPermission() || interfaceMutationInProgress) return;
  const profileId = Number(document.getElementById('intf-profile').value);
  if (!Number.isInteger(profileId) || profileId <= 0) return;
  const modalSequence = interfaceModalSequence;
  const mutationSequence = ++interfaceMutationSequence;
  interfaceMutationInProgress = true;
  state.busy = true;
  document.getElementById('intf-modal-error').textContent = '';
  updateInterfaceModalControls();
  setInterfaceActionControlsBusy(true);
  try {
    const result = await runSwitchChange(state.switchId, 'profile-apply', { interface: state.port, profile_id: profileId }, {
      title: t('Profil auf {port} anwenden', { port: state.port }),
    });
    if (currentSession !== state.session || !result) return;
    if (!result.ok) {
      if (modalSequence === interfaceModalSequence) document.getElementById('intf-modal-error').textContent = result.message || t('Der Switch hat die Konfiguration abgelehnt.');
    } else if (modalSequence === interfaceModalSequence) {
      interfaceModalSequence += 1;
      document.getElementById('interface-modal').classList.add('hidden');
    }
    await refreshInterfaceInventoryAfterMutation(state.switchId);
  } catch (error) {
    if (currentSession !== state.session) return;
    if (modalSequence === interfaceModalSequence) document.getElementById('intf-modal-error').textContent = error.message;
    else toast(error.message, true);
  } finally {
    if (mutationSequence === interfaceMutationSequence) {
      interfaceMutationInProgress = false;
      setInterfaceActionControlsBusy(false);
    }
    state.busy = false;
    if (modalSequence === interfaceModalSequence) updateInterfaceModalControls();
  }
}

document.getElementById('intf-profile').addEventListener('focus', () => { void loadInterfaceProfiles(); });
document.getElementById('intf-profile').addEventListener('change', () => updateInterfaceModalControls());
document.getElementById('intf-profile-apply').addEventListener('click', applyInterfaceProfile);

registerSessionHooks({
  closePrivilegedModals: closeSecurityModal,
  reset() {
    securityRequestSequence += 1;
    securityTabData.clear();
    interfaceProfileState = null;
  },
});
