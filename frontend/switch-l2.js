// Layer 2: Tabs „Link-Aggregation“, „Spanning Tree“ und „VTP“, die VTP-Domänenübersicht sowie der
// VLAN-Rollout auf eine Switch-Gruppe.
// Alle Schreibvorgänge an einem Switch laufen über runSwitchChange (Vorschau → Anwenden) aus switches.js.

const L2_MODAL_IDS = [
  'lag-modal', 'stp-priority-modal', 'stp-mst-modal', 'stp-port-modal', 'vlan-rollout-modal', 'vtp-primary-modal',
  'vtp-domains-modal',
];

// Normalisierte VLAN-Liste („10,20-30“); wirft bei ungültiger Eingabe, leer → ''.
function normalizeL2VlanList(value) {
  const invalid = () => new Error(t('Bitte VLAN-IDs von 1 bis 4094 oder Bereiche angeben (z. B. 10,20-30).'));
  const normalized = String(value ?? '').trim().replace(/ *, */g, ',').replace(/ *- */g, '-');
  if (!normalized) return '';
  if (normalized.length > 4096 || !/^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$/.test(normalized)) throw invalid();
  return normalized.split(',').map(item => {
    const bounds = item.split('-').map(Number);
    if (bounds.some(bound => !Number.isInteger(bound) || bound < 1 || bound > 4094)
        || (bounds.length === 2 && bounds[0] > bounds[1])) throw invalid();
    return bounds.join('-');
  }).join(',');
}

// Ganze Zahl aus einem Eingabefeld; leer → null, ungültig → NaN.
function l2IntegerInput(id) {
  const raw = String(document.getElementById(id).value ?? '').trim();
  if (!raw) return null;
  return /^-?\d+$/.test(raw) ? Number(raw) : NaN;
}

function l2RangeError(field, min, max) {
  return t('{field}: Bitte eine ganze Zahl von {min} bis {max} eingeben.', { field, min, max });
}

function l2TableFilter(column, placeholder) {
  return `<th><input class="table-filter" type="search" data-column="${column}" placeholder="${escapeHtml(placeholder)}" aria-label="${escapeHtml(placeholder)}"></th>`;
}

// Lädt den Tab nach einer Schreibänderung neu, solange dieselbe Sitzung ihn noch anzeigt.
function reloadL2TabAfterWrite(switchId, session, containerId, load) {
  if (currentSession !== session || Number(currentSwitchId) !== Number(switchId)) return undefined;
  if (!document.getElementById(containerId)) return undefined;
  return load(switchId, { force: true });
}

// Gemeinsamer Ablauf für Modal-Formulare: Modal sperren, Änderung über die Vorschau ausführen,
// bei Erfolg schließen, sonst Meldung im Modal; danach Tab neu laden.
async function runL2ModalChange({ modalId, errorId, switchId, session, kind, params, title, close, reload }) {
  const operation = beginModalOperation(modalId);
  if (!operation) return;
  const errorElement = document.getElementById(errorId);
  errorElement.textContent = '';
  let applied = false;
  try {
    const result = await runSwitchChange(switchId, kind, params, { title });
    applied = Boolean(result);
    if (!modalOperationIsCurrent(operation) || !result) return;
    if (result.ok) close();
    else errorElement.textContent = result.message || '';
  } catch (e) {
    applied = true;
    if (modalOperationIsCurrent(operation)) errorElement.textContent = e.message;
  } finally {
    finishModalOperation(operation);
    if (applied) await reload(switchId, session);
  }
}

// Ausführung ohne eigenes Modal (Löschen, Moduswechsel); key verhindert Doppelklicks.
async function runL2DirectChange({ key, switchId, kind, params, title, reload }) {
  if (pendingSwitchActions.has(key)) return;
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  let applied = false;
  try {
    const result = await runSwitchChange(switchId, kind, params, { title });
    applied = Boolean(result);
  } catch (e) {
    applied = true;
    if (currentSession === session) toast(e.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
    if (applied) await reload(switchId, session);
  }
}

// --- Link-Aggregation --------------------------------------------------------

const LAG_MODE_LABELS = {
  static: () => t('Statisch'),
  lacp_active: () => t('LACP aktiv'),
  lacp_passive: () => t('LACP passiv'),
};
const LAG_MEMBER_STATE_LABELS = {
  bundled: () => t('gebündelt'),
  down: () => t('down'),
  standby: () => t('Standby'),
  suspended: () => t('gesperrt'),
};
const LAG_MAX_MEMBERS = 8;
// Logische Interfaces, die nie LAG-Mitglied sein können (der Server prüft zusätzlich physische Ports).
const LAG_LOGICAL_INTERFACE_PATTERN = /^(?:vlan|port-channel|po\d|lag|trk|bond|bridge|loopback|lo\d|tunnel|mgmt|null|stackport|cpu)/i;
let lagRequestSequence = 0;
// switchId -> {lags, maxLagId} des zuletzt gezeigten Tabs; Zeilenknöpfe suchen ihr LAG hier.
const lagTabData = new Map();
let lagModalState = null;

function lagModeText(mode) {
  return LAG_MODE_LABELS[mode]?.() ?? (hasValue(mode) ? String(mode) : '—');
}

function lagMembers(lag) {
  return Array.isArray(lag?.members) ? lag.members.filter(member => member && hasValue(member.interface)) : [];
}

function lagLabel(lag) {
  return hasValue(lag?.interface) ? String(lag.interface) : String(lag?.id ?? '');
}

function renderLagMembers(lag) {
  const members = lagMembers(lag);
  if (members.length === 0) return '—';
  return members.map(member => {
    const state = LAG_MEMBER_STATE_LABELS[member.state]?.() ?? (hasValue(member.state) ? String(member.state) : '');
    const detail = state ? ` <span class="interface-state-detail l2-inline">(${escapeHtml(state)})</span>` : '';
    return `<div>${escapeHtml(member.interface)}${detail}</div>`;
  }).join('');
}

function renderLagTable(switchId, lags, warnings) {
  const sw = switchById(switchId);
  const canEdit = currentSessionCanEdit();
  const lagState = featureState(sw, 'lag');
  const badge = lagState.supported ? '' : incompatibleBadge();
  const toolbar = canEdit ? `
    <div class="flex-row" style="justify-content: flex-end; margin-bottom: 8px;">
      <button id="btn-create-lag"${vlanActionAttributes(['primary'], lagState)}>${escapeHtml(t('LAG anlegen'))}${badge}</button>
    </div>
  ` : '';
  if (lags.length === 0) {
    return `${toolbar}${renderInventoryWarnings(warnings)}<div class="empty-state">${escapeHtml(t('Keine Link-Aggregationen konfiguriert.'))}</div>`;
  }
  const rows = lags.map(lag => {
    const id = escapeHtml(lag.id);
    const actions = canEdit ? `
          <td class="table-actions"><div class="table-actions-inner">
            <button data-lag-id="${id}"${vlanActionAttributes(['edit-lag-btn'], lagState)}>${escapeHtml(t('Bearbeiten'))}${badge}</button>
            <button data-lag-id="${id}"${vlanActionAttributes(['delete-lag-btn', lagState.supported ? 'danger' : ''], lagState)}>${escapeHtml(t('Löschen'))}${badge}</button>
          </div></td>
    ` : '';
    return `
        <tr class="lag-row" data-lag-id="${id}">
          <td>${escapeHtml(lagLabel(lag))}</td>
          <td>${escapeHtml(lagModeText(lag.mode))}</td>
          <td>${renderLagMembers(lag)}</td>
          <td>${escapeHtml(hasValue(lag.status) ? String(lag.status) : '—')}</td>
          ${actions}
        </tr>
    `;
  }).join('');
  return `
    ${toolbar}
    ${renderInventoryWarnings(warnings)}
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr><th>${escapeHtml(t('LAG'))}</th><th>${escapeHtml(t('Modus'))}</th><th>${escapeHtml(t('Mitglieder'))}</th><th>${escapeHtml(t('Status'))}</th>${canEdit ? '<th></th>' : ''}</tr>
          <tr class="filter-row">
            ${l2TableFilter(0, t('LAG suchen'))}
            ${l2TableFilter(1, t('Modus suchen'))}
            ${l2TableFilter(2, t('Port suchen'))}
            ${l2TableFilter(3, t('Status suchen'))}
            ${canEdit ? '<th></th>' : ''}
          </tr>
        </thead>
        <tbody>
          ${rows}
          <tr id="no-lag-results" class="hidden"><td colspan="${canEdit ? 5 : 4}" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden LAGs gefunden.'))}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}

function lagFromTab(switchId, lagId) {
  return (lagTabData.get(Number(switchId))?.lags || []).find(lag => String(lag.id) === String(lagId)) || null;
}

async function loadLags(switchId, { force = false } = {}) {
  const container = document.getElementById('lags-container');
  const button = document.getElementById('btn-refresh-lags');
  if (!container || (button?.disabled && !force)) return;
  const session = currentSession;
  const sequence = ++lagRequestSequence;
  const isCurrentView = () => sequence === lagRequestSequence && container === document.getElementById('lags-container');
  const isCurrent = () => isCurrentView() && currentSession === session;
  if (button) button.disabled = true;
  try {
    const result = await api(`/api/switches/${switchId}/lags`);
    if (!isCurrent()) return;
    if (!Array.isArray(result?.lags)) throw new Error(t('Der Switch lieferte keine gültige LAG-Liste.'));
    const lags = result.lags.filter(lag => lag && typeof lag === 'object');
    const maxLagId = Number.isInteger(Number(result.max_lag_id)) && Number(result.max_lag_id) > 0 ? Number(result.max_lag_id) : null;
    lagTabData.set(Number(switchId), { lags, maxLagId });
    container.innerHTML = renderLagTable(switchId, lags, result.warnings);
    if (lags.length) attachTableFilters(container, '.lag-row', '#no-lag-results');
    document.getElementById('btn-create-lag')?.addEventListener('click', () => openLagModal(switchId, null));
    container.querySelectorAll('.edit-lag-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const lag = lagFromTab(switchId, btn.dataset.lagId);
        if (lag) openLagModal(switchId, lag);
      });
    });
    container.querySelectorAll('.delete-lag-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const lag = lagFromTab(switchId, btn.dataset.lagId);
        if (lag) deleteLag(switchId, lag);
      });
    });
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (isCurrentView() && button && button === document.getElementById('btn-refresh-lags')) button.disabled = false;
  }
}

function reloadLagsAfterWrite(switchId, session) {
  return reloadL2TabAfterWrite(switchId, session, 'lags-container', loadLags);
}

// Ports, die das Modal als Mitglied anbietet: physische Ports, die in keinem anderen LAG stecken.
function lagMemberCandidates(state) {
  const data = lagTabData.get(state.switchId);
  const lagInterfaces = new Set((data?.lags || []).map(lag => String(lag.interface ?? '')).filter(Boolean));
  const otherMembers = new Set((data?.lags || [])
    .filter(lag => !state.lag || String(lag.id) !== String(state.lag.id))
    .flatMap(lag => lagMembers(lag).map(member => String(member.interface))));
  const candidates = (state.interfaces || [])
    .filter(intf => intf && hasValue(intf.port))
    .map(intf => ({ port: String(intf.port), description: hasValue(intf.description) ? String(intf.description) : '' }))
    .filter(({ port }) => !lagInterfaces.has(port) && !otherMembers.has(port) && !LAG_LOGICAL_INTERFACE_PATTERN.test(port));
  const known = new Set(candidates.map(candidate => candidate.port));
  state.original.forEach(port => {
    if (!known.has(port)) candidates.push({ port, description: '' });
  });
  return candidates;
}

function renderLagMemberChoices(state) {
  const container = document.getElementById('lag-members');
  if (state.interfacesError) {
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(state.interfacesError)}</div>`;
    return;
  }
  if (!state.interfaces) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Ports …'))}</div>`;
    return;
  }
  const candidates = lagMemberCandidates(state);
  state.order = candidates.map(candidate => candidate.port);
  container.innerHTML = candidates.length === 0
    ? `<div class="empty-state">${escapeHtml(t('Keine freien Ports gefunden.'))}</div>`
    : candidates.map(({ port, description }) => `
      <label class="admin-check"><input type="checkbox" data-port="${escapeHtml(port)}"${state.selected.has(port) ? ' checked' : ''}> ${escapeHtml(port)}${description ? ` <span class="interface-state-detail l2-inline">${escapeHtml(description)}</span>` : ''}</label>
    `).join('');
}

async function openLagModal(switchId, lag = null) {
  if (!requireEditPermission()) return;
  if (modalOperations.has('lag-modal')) return;
  const sw = switchById(switchId);
  const original = lagMembers(lag).map(member => String(member.interface));
  const state = {
    switchId: Number(switchId), lag, session: currentSession, original, selected: new Set(original),
    interfaces: null, interfacesError: '', order: [],
  };
  lagModalState = state;
  const maxLagId = lagTabData.get(state.switchId)?.maxLagId;
  document.getElementById('lag-modal-title').textContent = lag
    ? t('LAG {lag} bearbeiten', { lag: lagLabel(lag) }) : t('LAG anlegen');
  const idInput = document.getElementById('lag-id');
  idInput.value = lag ? String(lag.id) : '';
  idInput.max = maxLagId ? String(maxLagId) : '';
  idInput.disabled = Boolean(lag);
  const modeSelect = document.getElementById('lag-mode');
  const allowedModes = featureState(sw, 'lag').options;
  markIncompatibleOptions(modeSelect, allowedModes);
  const firstAllowed = Array.from(modeSelect.options).find(option => !option.disabled)?.value ?? 'static';
  modeSelect.value = lag && hasValue(lag.mode) ? String(lag.mode) : firstAllowed;
  modeSelect.disabled = Boolean(lag);
  document.getElementById('lag-modal-error').textContent = '';
  renderLagMemberChoices(state);
  setElementHidden('lag-modal', false);
  (lag ? document.getElementById('lag-cancel') : idInput).focus();
  try {
    const inventory = await api(`/api/switches/${state.switchId}/interface-inventory`);
    if (lagModalState !== state || currentSession !== state.session) return;
    if (!Array.isArray(inventory?.interfaces)) throw new Error(t('Der Switch lieferte kein gültiges Interface-Inventar.'));
    state.interfaces = inventory.interfaces;
  } catch (e) {
    if (lagModalState !== state || currentSession !== state.session) return;
    state.interfacesError = e.message;
  }
  renderLagMemberChoices(state);
}

function closeLagModal() {
  setElementHidden('lag-modal', true);
  lagModalState = null;
}

// Mitglieder in Anzeigereihenfolge der Ports.
function lagOrdered(state, ports) {
  const position = port => {
    const index = state.order.indexOf(port);
    return index === -1 ? Number.MAX_SAFE_INTEGER : index;
  };
  return [...ports].sort((a, b) => position(a) - position(b));
}

async function submitLagModal() {
  if (!requireEditPermission()) return;
  const state = lagModalState;
  if (!state || state.session !== currentSession) return;
  const errorElement = document.getElementById('lag-modal-error');
  const fail = message => { errorElement.textContent = message; };
  if (!state.interfaces) {
    fail(state.interfacesError || t('Die Portliste wird noch geladen.'));
    return;
  }
  const selected = lagOrdered(state, state.selected);
  if (selected.length > LAG_MAX_MEMBERS) {
    fail(t('Ein LAG kann höchstens {count} Mitglieder haben.', { count: LAG_MAX_MEMBERS }));
    return;
  }
  let kind;
  let params;
  let title;
  if (state.lag) {
    const add = selected.filter(port => !state.original.includes(port));
    const remove = lagOrdered(state, state.original.filter(port => !state.selected.has(port)));
    if (add.length === 0 && remove.length === 0) {
      fail(t('Es wurde nichts geändert.'));
      return;
    }
    if (selected.length === 0) {
      fail(t('Ein LAG braucht mindestens ein Mitglied. Zum Entfernen „Löschen“ verwenden.'));
      return;
    }
    kind = 'lag-update';
    params = { lag_id: Number(state.lag.id), add, remove };
    title = t('LAG {lag} bearbeiten', { lag: lagLabel(state.lag) });
  } else {
    const maxLagId = lagTabData.get(state.switchId)?.maxLagId || 4096;
    const lagId = l2IntegerInput('lag-id');
    if (!Number.isInteger(lagId) || lagId < 1 || lagId > maxLagId) {
      fail(l2RangeError(t('LAG-ID'), 1, maxLagId));
      return;
    }
    const modeSelect = document.getElementById('lag-mode');
    const mode = modeSelect.value;
    const option = Array.from(modeSelect.options).find(candidate => candidate.value === mode);
    if (!mode || option?.disabled) {
      fail(t('Dieser LAG-Modus wird vom Switch nicht unterstützt.'));
      return;
    }
    if (selected.length === 0) {
      fail(t('Bitte mindestens einen Port als Mitglied auswählen.'));
      return;
    }
    kind = 'lag-create';
    params = { lag_id: lagId, mode, members: selected };
    title = t('LAG anlegen');
  }
  await runL2ModalChange({
    modalId: 'lag-modal', errorId: 'lag-modal-error', switchId: state.switchId, session: state.session,
    kind, params, title, reload: reloadLagsAfterWrite,
    close: () => { if (lagModalState === state) closeLagModal(); },
  });
}

function deleteLag(switchId, lag) {
  if (!requireEditPermission()) return undefined;
  const lagId = Number(lag.id);
  if (!Number.isInteger(lagId)) return undefined;
  return runL2DirectChange({
    key: `${switchId}:lag-delete:${lagId}`, switchId, kind: 'lag-delete', params: { lag_id: lagId },
    title: t('LAG {lag} löschen', { lag: lagLabel(lag) }), reload: reloadLagsAfterWrite,
  });
}

document.getElementById('lag-members').addEventListener('change', event => {
  const state = lagModalState;
  const port = event.target?.dataset?.port;
  if (!state || !port) return;
  if (event.target.checked) state.selected.add(port);
  else state.selected.delete(port);
});
document.getElementById('lag-cancel').addEventListener('click', closeLagModal);
document.getElementById('lag-save').addEventListener('click', submitLagModal);

// --- Spanning Tree -----------------------------------------------------------

const STP_MODE_LABELS = { stp: 'STP', rstp: 'RSTP', pvst: 'PVST+', rapid_pvst: 'Rapid PVST+', mstp: 'MSTP' };
const STP_PER_VLAN_MODES = new Set(['pvst', 'rapid_pvst']);
const STP_MST_NAME_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
let stpRequestSequence = 0;
// switchId -> zuletzt gelesener STP-Zustand des Tabs.
const stpTabData = new Map();
let stpModalState = null;

function stpModeText(mode) {
  return STP_MODE_LABELS[mode] ?? (hasValue(mode) ? String(mode) : t('Unbekannt'));
}

function stpTargetText(mode, value) {
  if (!hasValue(value)) return '—';
  return STP_PER_VLAN_MODES.has(mode) ? t('VLAN {vlan}', { vlan: value }) : t('Instanz {instance}', { instance: value });
}

function stpCell(value) {
  return escapeHtml(hasValue(value) ? String(value) : '—');
}

// Root-Infos und Bridge-Prioritäten, zusammengeführt nach VLAN bzw. Instanz.
function stpBridgeRows(data) {
  const rows = new Map();
  const row = key => {
    if (!rows.has(key)) rows.set(key, { key, priority: null, root: null });
    return rows.get(key);
  };
  (data.priority || []).forEach(entry => {
    const key = entry?.vlan ?? entry?.instance;
    if (hasValue(key)) row(String(key)).priority = entry.priority;
  });
  (data.roots || []).forEach(root => {
    if (hasValue(root?.vlan_or_instance)) row(String(root.vlan_or_instance)).root = root;
  });
  return [...rows.values()].sort((a, b) => Number(a.key) - Number(b.key) || a.key.localeCompare(b.key));
}

function renderStpModeSection(switchId, data, canEdit) {
  const sw = switchById(switchId);
  const stpState = featureState(sw, 'stp');
  const modes = stpState.options || Object.keys(STP_MODE_LABELS);
  const control = canEdit ? `
      <select id="stp-mode-select" aria-label="${escapeHtml(t('Spanning-Tree-Modus'))}"${stpState.supported ? '' : ' disabled'}>
        ${modes.map(mode => `<option value="${escapeHtml(mode)}"${mode === data.mode ? ' selected' : ''}>${escapeHtml(stpModeText(mode))}</option>`).join('')}
      </select>
      <button id="btn-stp-mode"${vlanActionAttributes([], stpState)}>${escapeHtml(t('Modus ändern'))}${stpState.supported ? '' : incompatibleBadge()}</button>
  ` : '';
  return `
    <div class="flex-row" style="justify-content: space-between; margin-bottom: 10px;">
      <div>${escapeHtml(t('Modus'))}: <strong>${escapeHtml(stpModeText(data.mode))}</strong></div>
      <div class="flex-row">${control}</div>
    </div>
  `;
}

function renderStpBridgeSection(data, canEdit, stpState) {
  const rows = stpBridgeRows(data);
  const toolbar = canEdit ? `
      <button id="btn-stp-priority"${vlanActionAttributes([], stpState)}>${escapeHtml(t('Priorität setzen'))}${stpState.supported ? '' : incompatibleBadge()}</button>
  ` : '';
  const body = rows.length === 0
    ? `<div class="empty-state">${escapeHtml(t('Keine Root-Informationen vorhanden.'))}</div>`
    : `
      <div style="overflow-x: auto;">
        <table>
          <thead><tr><th>${escapeHtml(STP_PER_VLAN_MODES.has(data.mode) ? t('VLAN') : t('Instanz'))}</th><th>${escapeHtml(t('Bridge-Priorität'))}</th><th>${escapeHtml(t('Root-Bridge'))}</th><th>${escapeHtml(t('Root-Port'))}</th><th>${escapeHtml(t('Root-Kosten'))}</th><th>${escapeHtml(t('Dieser Switch ist Root'))}</th>${canEdit ? '<th></th>' : ''}</tr></thead>
          <tbody>
            ${rows.map(row => `
            <tr class="stp-bridge-row">
              <td>${escapeHtml(row.key)}</td>
              <td>${stpCell(row.priority)}</td>
              <td>${stpCell(row.root?.root_bridge)}</td>
              <td>${stpCell(row.root?.root_port)}</td>
              <td>${stpCell(row.root?.root_cost)}</td>
              <td>${row.root?.is_root === true ? escapeHtml(t('ja')) : row.root?.is_root === false ? escapeHtml(t('nein')) : '—'}</td>
              ${canEdit ? `<td class="table-actions"><div class="table-actions-inner"><button data-stp-key="${escapeHtml(row.key)}"${vlanActionAttributes(['edit-stp-priority-btn'], stpState)}>${escapeHtml(t('Bearbeiten'))}</button></div></td>` : ''}
            </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  return `
    <h3 class="l2-section-title">${escapeHtml(t('Root-Bridge und Prioritäten'))}</h3>
    <div class="flex-row" style="justify-content: flex-end; margin-bottom: 8px;">${toolbar}</div>
    ${body}
  `;
}

function renderStpMstSection(switchId, data, canEdit) {
  if (data.mode !== 'mstp') return '';
  const mstState = featureState(switchById(switchId), 'stp_mst');
  const mst = data.mst && typeof data.mst === 'object' ? data.mst : null;
  const instances = Array.isArray(mst?.instances) ? mst.instances.filter(instance => instance && hasValue(instance.id)) : [];
  const button = canEdit ? `
      <button id="btn-stp-mst"${vlanActionAttributes([], mstState)}>${escapeHtml(t('Region bearbeiten'))}${mstState.supported ? '' : incompatibleBadge()}</button>
  ` : '';
  return `
    <h3 class="l2-section-title">${escapeHtml(t('MST-Region'))}</h3>
    <div class="flex-row" style="justify-content: space-between; margin-bottom: 8px;">
      <div>${escapeHtml(t('Name'))}: <strong>${stpCell(mst?.name)}</strong> · ${escapeHtml(t('Revision'))}: <strong>${stpCell(mst?.revision)}</strong></div>
      <div class="flex-row">${button}</div>
    </div>
    ${instances.length === 0
    ? `<div class="empty-state">${escapeHtml(t('Keine MST-Instanzen konfiguriert.'))}</div>`
    : `<table><thead><tr><th>${escapeHtml(t('Instanz'))}</th><th>${escapeHtml(t('VLANs'))}</th></tr></thead><tbody>
        ${instances.map(instance => `<tr><td>${escapeHtml(instance.id)}</td><td>${stpCell(instance.vlans)}</td></tr>`).join('')}
      </tbody></table>`}
  `;
}

function renderStpPortSection(data, canEdit, stpState) {
  const ports = data.ports || [];
  if (ports.length === 0) {
    return `<h3 class="l2-section-title">${escapeHtml(t('Ports'))}</h3><div class="empty-state">${escapeHtml(t('Keine Ports gefunden.'))}</div>`;
  }
  const rows = ports.map((port, index) => `
        <tr class="stp-port-row">
          <td>${escapeHtml(port.interface)}</td>
          <td>${escapeHtml(stpTargetText(data.mode, port.instance_or_vlan))}</td>
          <td>${stpCell(port.cost)}</td>
          <td>${stpCell(port.priority)}</td>
          <td>${stpCell(port.role)}</td>
          <td>${stpCell(port.state)}</td>
          ${canEdit ? `<td class="table-actions"><div class="table-actions-inner"><button data-stp-port-index="${index}"${vlanActionAttributes(['edit-stp-port-btn'], stpState)}>${escapeHtml(t('Bearbeiten'))}</button></div></td>` : ''}
        </tr>`).join('');
  return `
    <h3 class="l2-section-title">${escapeHtml(t('Ports'))}</h3>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr><th>${escapeHtml(t('Port'))}</th><th>${escapeHtml(STP_PER_VLAN_MODES.has(data.mode) ? t('VLAN') : t('Instanz'))}</th><th>${escapeHtml(t('Kosten'))}</th><th>${escapeHtml(t('Priorität'))}</th><th>${escapeHtml(t('Rolle'))}</th><th>${escapeHtml(t('Zustand'))}</th>${canEdit ? '<th></th>' : ''}</tr>
          <tr class="filter-row">
            ${l2TableFilter(0, t('Port suchen'))}
            ${l2TableFilter(1, t('VLAN suchen'))}
            <th></th><th></th>
            ${l2TableFilter(4, t('Rolle suchen'))}
            ${l2TableFilter(5, t('Zustand suchen'))}
            ${canEdit ? '<th></th>' : ''}
          </tr>
        </thead>
        <tbody>
          ${rows}
          <tr id="no-stp-port-results" class="hidden"><td colspan="${canEdit ? 7 : 6}" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden Ports gefunden.'))}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}

function renderStp(switchId, data) {
  const canEdit = currentSessionCanEdit();
  const stpState = featureState(switchById(switchId), 'stp');
  return `
    ${renderInventoryWarnings(data.warnings)}
    ${renderStpModeSection(switchId, data, canEdit)}
    ${renderStpBridgeSection(data, canEdit, stpState)}
    ${renderStpMstSection(switchId, data, canEdit)}
    ${renderStpPortSection(data, canEdit, stpState)}
  `;
}

function normalizeStpData(result) {
  if (!result || typeof result !== 'object') throw new Error(t('Der Switch lieferte keine gültigen Spanning-Tree-Daten.'));
  const list = value => (Array.isArray(value) ? value.filter(item => item && typeof item === 'object') : []);
  return {
    mode: hasValue(result.mode) ? String(result.mode) : null,
    priority: list(result.priority),
    mst: result.mst && typeof result.mst === 'object' ? result.mst : null,
    roots: list(result.roots),
    ports: list(result.ports).filter(port => hasValue(port.interface)),
    warnings: result.warnings,
  };
}

async function loadStp(switchId, { force = false } = {}) {
  const container = document.getElementById('stp-container');
  const button = document.getElementById('btn-refresh-stp');
  if (!container || (button?.disabled && !force)) return;
  const session = currentSession;
  const sequence = ++stpRequestSequence;
  const isCurrentView = () => sequence === stpRequestSequence && container === document.getElementById('stp-container');
  const isCurrent = () => isCurrentView() && currentSession === session;
  if (button) button.disabled = true;
  try {
    const data = normalizeStpData(await api(`/api/switches/${switchId}/stp`));
    if (!isCurrent()) return;
    stpTabData.set(Number(switchId), data);
    container.innerHTML = renderStp(switchId, data);
    if (data.ports.length) attachTableFilters(container, '.stp-port-row', '#no-stp-port-results');
    document.getElementById('btn-stp-mode')?.addEventListener('click', () => changeStpMode(switchId));
    document.getElementById('btn-stp-priority')?.addEventListener('click', () => openStpPriorityModal(switchId, null));
    document.getElementById('btn-stp-mst')?.addEventListener('click', () => openStpMstModal(switchId));
    container.querySelectorAll('.edit-stp-priority-btn').forEach(btn => {
      btn.addEventListener('click', () => openStpPriorityModal(switchId, btn.dataset.stpKey));
    });
    container.querySelectorAll('.edit-stp-port-btn').forEach(btn => {
      btn.addEventListener('click', () => openStpPortModal(switchId, Number(btn.dataset.stpPortIndex)));
    });
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (isCurrentView() && button && button === document.getElementById('btn-refresh-stp')) button.disabled = false;
  }
}

function reloadStpAfterWrite(switchId, session) {
  return reloadL2TabAfterWrite(switchId, session, 'stp-container', loadStp);
}

function changeStpMode(switchId) {
  if (!requireEditPermission()) return undefined;
  const data = stpTabData.get(Number(switchId));
  const mode = document.getElementById('stp-mode-select')?.value;
  if (!mode) return undefined;
  if (data && mode === data.mode) {
    toast(t('Es wurde nichts geändert.'), true);
    return undefined;
  }
  return runL2DirectChange({
    key: `${switchId}:stp-mode`, switchId, kind: 'stp-mode', params: { mode },
    title: t('Spanning-Tree-Modus ändern'), reload: reloadStpAfterWrite,
  });
}

function closeStpModals() {
  ['stp-priority-modal', 'stp-mst-modal', 'stp-port-modal'].forEach(id => setElementHidden(id, true));
  stpModalState = null;
}

function stpModalStart(modalId, switchId, extra) {
  if (!requireEditPermission()) return null;
  if (modalOperations.has(modalId)) return null;
  const data = stpTabData.get(Number(switchId));
  if (!data) return null;
  stpModalState = { modalId, switchId: Number(switchId), session: currentSession, data, ...extra };
  return stpModalState;
}

function stpModalCurrent(modalId) {
  const state = stpModalState;
  if (!requireEditPermission() || !state || state.modalId !== modalId || state.session !== currentSession) return null;
  return state;
}

function stpPriorityOptions(step, max, current) {
  const options = [`<option value="">${escapeHtml(t('Unverändert'))}</option>`];
  for (let value = 0; value <= max; value += step) {
    options.push(`<option value="${value}"${String(value) === String(current) ? ' selected' : ''}>${value}</option>`);
  }
  return options.join('');
}

function openStpPriorityModal(switchId, key) {
  const state = stpModalStart('stp-priority-modal', switchId, { key });
  if (!state) return;
  const perVlan = STP_PER_VLAN_MODES.has(state.data.mode);
  const row = key === null ? null : stpBridgeRows(state.data).find(candidate => candidate.key === String(key));
  document.getElementById('stp-priority-modal-title').textContent = row
    ? t('Priorität für {target} setzen', { target: stpTargetText(state.data.mode, row.key) })
    : t('Bridge-Priorität setzen');
  document.getElementById('stp-priority-target-label').textContent = perVlan ? t('VLANs') : t('Instanz');
  const target = document.getElementById('stp-priority-target');
  target.value = row ? row.key : (perVlan ? '' : '0');
  target.placeholder = perVlan ? t('z. B. 1,10-20') : '0';
  document.getElementById('stp-priority-value').innerHTML = stpPriorityOptions(4096, 61440, row?.priority ?? 32768);
  document.getElementById('stp-priority-help').textContent = perVlan
    ? t('Priorität für eine oder mehrere VLANs (Vielfaches von 4096, kleiner = bevorzugte Root-Bridge).')
    : t('Priorität für eine Instanz (0 = gemeinsame Instanz/CIST; Vielfaches von 4096, kleiner = bevorzugte Root-Bridge).');
  document.getElementById('stp-priority-error').textContent = '';
  setElementHidden('stp-priority-modal', false);
  target.focus();
}

async function submitStpPriority() {
  const state = stpModalCurrent('stp-priority-modal');
  if (!state) return;
  const errorElement = document.getElementById('stp-priority-error');
  const perVlan = STP_PER_VLAN_MODES.has(state.data.mode);
  const priorityRaw = document.getElementById('stp-priority-value').value;
  if (priorityRaw === '') {
    errorElement.textContent = t('Bitte eine Priorität auswählen.');
    return;
  }
  const params = { vlans: null, instance: null, priority: Number(priorityRaw) };
  if (perVlan) {
    try {
      params.vlans = normalizeL2VlanList(document.getElementById('stp-priority-target').value);
    } catch (e) {
      errorElement.textContent = e.message;
      return;
    }
    if (!params.vlans) {
      errorElement.textContent = t('Bitte VLAN-IDs von 1 bis 4094 oder Bereiche angeben (z. B. 10,20-30).');
      return;
    }
  } else {
    const instance = l2IntegerInput('stp-priority-target');
    if (!Number.isInteger(instance) || instance < 0 || instance > 64) {
      errorElement.textContent = l2RangeError(t('Instanz'), 0, 64);
      return;
    }
    params.instance = instance;
  }
  await runL2ModalChange({
    modalId: 'stp-priority-modal', errorId: 'stp-priority-error', switchId: state.switchId, session: state.session,
    kind: 'stp-priority', params, title: t('Bridge-Priorität setzen'), reload: reloadStpAfterWrite,
    close: () => { if (stpModalState === state) closeStpModals(); },
  });
}

function openStpMstModal(switchId) {
  const state = stpModalStart('stp-mst-modal', switchId, {});
  if (!state) return;
  const mst = state.data.mst || {};
  document.getElementById('stp-mst-name').value = hasValue(mst.name) ? String(mst.name) : '';
  document.getElementById('stp-mst-revision').value = hasValue(mst.revision) ? String(mst.revision) : '0';
  const instances = Array.isArray(mst.instances) ? mst.instances.filter(instance => instance && Number(instance.id) > 0) : [];
  document.getElementById('stp-mst-instances').value = instances
    .map(instance => `${instance.id}: ${hasValue(instance.vlans) ? instance.vlans : ''}`).join('\n');
  document.getElementById('stp-mst-error').textContent = '';
  setElementHidden('stp-mst-modal', false);
  document.getElementById('stp-mst-name').focus();
}

// „ID: VLANs“ pro Zeile → [{id, vlans}]; wirft mit Zeilennummer.
function parseStpMstInstances(text) {
  const seen = new Set();
  return String(text ?? '').split(/\r?\n/).map((line, index) => ({ line: line.trim(), number: index + 1 }))
    .filter(({ line }) => line)
    .map(({ line, number }) => {
      const match = line.match(/^(\d+)\s*:\s*(.+)$/);
      const id = match ? Number(match[1]) : NaN;
      if (!match || !Number.isInteger(id) || id < 1 || id > 64) {
        throw new Error(t('Zeile {line}: Bitte „ID: VLANs“ mit einer Instanz-ID von 1 bis 64 angeben.', { line: number }));
      }
      if (seen.has(id)) throw new Error(t('Zeile {line}: Instanz {instance} ist doppelt.', { line: number, instance: id }));
      seen.add(id);
      let vlans;
      try {
        vlans = normalizeL2VlanList(match[2]);
      } catch (e) {
        throw new Error(t('Zeile {line}: {error}', { line: number, error: e.message }));
      }
      return { id, vlans };
    });
}

async function submitStpMst() {
  const state = stpModalCurrent('stp-mst-modal');
  if (!state) return;
  const errorElement = document.getElementById('stp-mst-error');
  const name = document.getElementById('stp-mst-name').value.trim();
  if (!STP_MST_NAME_PATTERN.test(name)) {
    errorElement.textContent = t('Regionsname: 1–32 Zeichen aus Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich.');
    return;
  }
  const revision = l2IntegerInput('stp-mst-revision');
  if (!Number.isInteger(revision) || revision < 0 || revision > 65535) {
    errorElement.textContent = l2RangeError(t('Revision'), 0, 65535);
    return;
  }
  let instances;
  try {
    instances = parseStpMstInstances(document.getElementById('stp-mst-instances').value);
  } catch (e) {
    errorElement.textContent = e.message;
    return;
  }
  await runL2ModalChange({
    modalId: 'stp-mst-modal', errorId: 'stp-mst-error', switchId: state.switchId, session: state.session,
    kind: 'stp-mst', params: { name, revision, instances }, title: t('MST-Region ändern'), reload: reloadStpAfterWrite,
    close: () => { if (stpModalState === state) closeStpModals(); },
  });
}

function openStpPortModal(switchId, index) {
  const port = stpTabData.get(Number(switchId))?.ports?.[index];
  if (!port) return;
  const state = stpModalStart('stp-port-modal', switchId, { port });
  if (!state) return;
  document.getElementById('stp-port-modal-title').textContent = hasValue(port.instance_or_vlan)
    ? t('Spanning Tree an {port} ({target})', { port: port.interface, target: stpTargetText(state.data.mode, port.instance_or_vlan) })
    : t('Spanning Tree an {port}', { port: port.interface });
  document.getElementById('stp-port-cost').value = hasValue(port.cost) ? String(port.cost) : '';
  document.getElementById('stp-port-priority').innerHTML = stpPriorityOptions(16, 240, port.priority);
  document.getElementById('stp-port-error').textContent = '';
  setElementHidden('stp-port-modal', false);
  document.getElementById('stp-port-cost').focus();
}

async function submitStpPort() {
  const state = stpModalCurrent('stp-port-modal');
  if (!state) return;
  const errorElement = document.getElementById('stp-port-error');
  const { port } = state;
  const cost = l2IntegerInput('stp-port-cost');
  if (cost !== null && (!Number.isInteger(cost) || cost < 1 || cost > 200000000)) {
    errorElement.textContent = l2RangeError(t('Kosten'), 1, 200000000);
    return;
  }
  const priorityRaw = document.getElementById('stp-port-priority').value;
  const priority = priorityRaw === '' ? null : Number(priorityRaw);
  const changedCost = cost !== null && String(cost) !== String(port.cost ?? '') ? cost : null;
  const changedPriority = priority !== null && String(priority) !== String(port.priority ?? '') ? priority : null;
  if (changedCost === null && changedPriority === null) {
    errorElement.textContent = t('Es wurde nichts geändert.');
    return;
  }
  const instanceOrVlan = hasValue(port.instance_or_vlan) ? Number(port.instance_or_vlan) : null;
  await runL2ModalChange({
    modalId: 'stp-port-modal', errorId: 'stp-port-error', switchId: state.switchId, session: state.session,
    kind: 'stp-port',
    params: { interface: String(port.interface), instance_or_vlan: instanceOrVlan, cost: changedCost, priority: changedPriority },
    title: t('Spanning Tree an {port}', { port: port.interface }), reload: reloadStpAfterWrite,
    close: () => { if (stpModalState === state) closeStpModals(); },
  });
}

['stp-priority-cancel', 'stp-mst-cancel', 'stp-port-cancel'].forEach(id => {
  document.getElementById(id).addEventListener('click', closeStpModals);
});
document.getElementById('stp-priority-save').addEventListener('click', submitStpPriority);
document.getElementById('stp-mst-save').addEventListener('click', submitStpMst);
document.getElementById('stp-port-save').addEventListener('click', submitStpPort);

// --- VLAN-Rollout auf eine Switch-Gruppe ------------------------------------

let rolloutState = null;

function rolloutIsCurrent(state) {
  return rolloutState === state && currentSession === state.session;
}

function openVlanRolloutModal(group) {
  if (!requireEditPermission()) return;
  if (modalOperations.has('vlan-rollout-modal')) return;
  rolloutState = {
    groupId: Number(group.id), groupName: String(group.name ?? ''), session: currentSession,
    token: null, switches: [], selections: new Map(), results: null,
  };
  document.getElementById('vlan-rollout-title').textContent = t('VLAN auf Gruppe „{name}“ ausrollen', { name: rolloutState.groupName });
  document.getElementById('rollout-vlan-id').value = '';
  document.getElementById('rollout-vlan-name').value = '';
  document.getElementById('rollout-error').textContent = '';
  renderRollout(rolloutState);
  setElementHidden('vlan-rollout-modal', false);
  document.getElementById('rollout-vlan-id').focus();
}

function closeVlanRolloutModal() {
  setElementHidden('vlan-rollout-modal', true);
  rolloutState = null;
}

const ROLLOUT_STATUS_TEXT = {
  ok: () => t('bereit'),
  skipped: () => t('übersprungen'),
  error: () => t('Fehler'),
};

function renderRolloutSwitch(entry) {
  const status = ROLLOUT_STATUS_TEXT[entry.status]?.() ?? String(entry.status ?? '');
  const reason = hasValue(entry.reason) ? `: ${escapeHtml(entry.reason)}` : '';
  const vlanNote = entry.status === 'ok'
    ? ` · ${escapeHtml(entry.vlan_exists ? t('VLAN vorhanden') : t('VLAN wird angelegt'))}` : '';
  const candidates = Array.isArray(entry.candidates) ? entry.candidates.filter(candidate => hasValue(candidate?.interface)) : [];
  const selected = rolloutState?.selections.get(String(entry.switch_id)) || new Set();
  const body = entry.status !== 'ok' ? '' : candidates.length === 0
    ? `<div class="interface-state-detail">${escapeHtml(t('Keine Trunk-Ports, denen das VLAN fehlt.'))}</div>`
    : candidates.map(candidate => `
      <label class="admin-check"><input type="checkbox" data-switch-id="${escapeHtml(entry.switch_id)}" data-port="${escapeHtml(candidate.interface)}"${selected.has(String(candidate.interface)) ? ' checked' : ''}> ${escapeHtml(candidate.interface)}${candidate.uplink ? ` <span class="client-badge infrastructure">${escapeHtml(t('Uplink'))}</span>` : ''}${hasValue(candidate.reason) ? ` <span class="interface-state-detail l2-inline">${escapeHtml(candidate.reason)}</span>` : ''}</label>
    `).join('');
  return `
    <details class="rollout-switch rollout-${escapeHtml(entry.status)}"${entry.status === 'ok' ? ' open' : ''}>
      <summary><strong>${escapeHtml(entry.name ?? entry.switch_id)}</strong> – ${escapeHtml(status)}${reason}${vlanNote}</summary>
      ${renderInventoryWarnings(entry.warnings)}
      <div class="l2-check-list">${body}</div>
    </details>
  `;
}

function renderRolloutResults(results) {
  const rows = results.map(result => `
      <tr>
        <td>${escapeHtml(result.name ?? result.switch_id)}</td>
        <td class="${result.ok ? 'status-connected' : 'status-disabled'}">${escapeHtml(result.ok ? t('Erfolgreich') : t('Fehlgeschlagen'))}</td>
        <td>${escapeHtml(result.message || '—')}${Array.isArray(result.lines) && result.lines.length
    ? `<pre class="command-preview">${escapeHtml(result.lines.join('\n'))}</pre>` : ''}</td>
      </tr>`).join('');
  return `
    <table>
      <thead><tr><th>${escapeHtml(t('Switch'))}</th><th>${escapeHtml(t('Ergebnis'))}</th><th>${escapeHtml(t('Meldung'))}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderRollout(state) {
  const preview = document.getElementById('rollout-preview');
  if (state.results) {
    preview.innerHTML = renderRolloutResults(state.results);
  } else if (state.token) {
    preview.innerHTML = state.switches.length === 0
      ? `<div class="empty-state">${escapeHtml(t('Die Gruppe enthält keine Switches.'))}</div>`
      : state.switches.map(renderRolloutSwitch).join('');
  } else {
    preview.innerHTML = `<div class="empty-state">${escapeHtml(t('VLAN eingeben und Vorschau erstellen.'))}</div>`;
  }
  const applicable = state.switches.some(entry => entry.status === 'ok');
  document.getElementById('rollout-apply').disabled = !state.token || !applicable;
}

// Neue Eingaben machen eine bestehende Vorschau ungültig.
function invalidateRolloutPreview() {
  const state = rolloutState;
  if (!state || modalOperations.has('vlan-rollout-modal') || (!state.token && !state.results)) return;
  state.token = null;
  state.switches = [];
  state.selections = new Map();
  state.results = null;
  renderRollout(state);
}

async function requestRolloutPreview() {
  if (!requireEditPermission()) return;
  const state = rolloutState;
  if (!state || !rolloutIsCurrent(state)) return;
  const errorElement = document.getElementById('rollout-error');
  const vlanId = l2IntegerInput('rollout-vlan-id');
  if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) {
    errorElement.textContent = t('Bitte eine VLAN-ID von 1 bis 4094 eingeben.');
    return;
  }
  const name = document.getElementById('rollout-vlan-name').value.trim();
  if (name && (!VLAN_NAME_PATTERN.test(name) || /^\d+$/.test(name))) {
    errorElement.textContent = t('Ungültiger VLAN-Name: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich (nicht nur Ziffern).');
    return;
  }
  const operation = beginModalOperation('vlan-rollout-modal');
  if (!operation) return;
  errorElement.textContent = '';
  state.token = null;
  state.results = null;
  document.getElementById('rollout-preview').innerHTML = `<div class="empty-state">${escapeHtml(t('Vorschau wird erstellt …'))}</div>`;
  const body = { vlan_id: vlanId };
  if (name) body.name = name;
  try {
    const result = await api(`/api/switch-groups/${state.groupId}/vlan-rollout/preview`, {
      method: 'POST', body: JSON.stringify(body),
    });
    if (!modalOperationIsCurrent(operation) || !rolloutIsCurrent(state)) return;
    if (!hasValue(result?.rollout_token) || !Array.isArray(result?.switches)) {
      throw new Error(t('Der Server lieferte keine gültige Rollout-Vorschau.'));
    }
    state.switches = result.switches.filter(entry => entry && typeof entry === 'object');
    state.selections = new Map(state.switches.filter(entry => entry.status === 'ok').map(entry => [
      String(entry.switch_id),
      new Set((Array.isArray(entry.candidates) ? entry.candidates : [])
        .filter(candidate => candidate?.selected === true && hasValue(candidate.interface))
        .map(candidate => String(candidate.interface))),
    ]));
    state.token = String(result.rollout_token);
  } catch (e) {
    if (!modalOperationIsCurrent(operation) || !rolloutIsCurrent(state)) return;
    state.switches = [];
    state.selections = new Map();
    errorElement.textContent = e.message;
  } finally {
    finishModalOperation(operation);
    if (rolloutIsCurrent(state)) renderRollout(state);
  }
}

// Ausgewählte Ports pro bereitem Switch in Anzeigereihenfolge.
function rolloutSelections(state) {
  const selections = {};
  state.switches.filter(entry => entry.status === 'ok').forEach(entry => {
    const chosen = state.selections.get(String(entry.switch_id)) || new Set();
    selections[String(entry.switch_id)] = (Array.isArray(entry.candidates) ? entry.candidates : [])
      .map(candidate => String(candidate?.interface ?? ''))
      .filter(port => port && chosen.has(port));
  });
  return selections;
}

async function applyRollout() {
  if (!requireEditPermission()) return;
  const state = rolloutState;
  if (!state || !state.token || !rolloutIsCurrent(state)) return;
  const operation = beginModalOperation('vlan-rollout-modal');
  if (!operation) return;
  const errorElement = document.getElementById('rollout-error');
  errorElement.textContent = '';
  const token = state.token;
  // Das Token gilt nur einmal, auch wenn die Antwort ausbleibt.
  state.token = null;
  let affected = [];
  try {
    const result = await api(`/api/switch-groups/${state.groupId}/vlan-rollout/apply`, {
      method: 'POST', body: JSON.stringify({ rollout_token: token, selections: rolloutSelections(state) }),
    });
    if (!rolloutIsCurrent(state)) return;
    const results = Array.isArray(result?.results) ? result.results.filter(entry => entry && typeof entry === 'object') : [];
    state.results = results;
    affected = results.map(entry => Number(entry.switch_id));
    const failed = results.filter(entry => !entry.ok).length;
    toast(t('VLAN-Rollout abgeschlossen: {ok} erfolgreich, {failed} fehlgeschlagen.', {
      ok: results.length - failed, failed,
    }), failed > 0);
  } catch (e) {
    if (!rolloutIsCurrent(state)) return;
    state.switches = [];
    state.selections = new Map();
    errorElement.textContent = e.status === 409
      ? `${e.message} ${t('Bitte die Vorschau neu erstellen.')}`
      : e.message;
  } finally {
    finishModalOperation(operation);
    if (rolloutIsCurrent(state)) renderRollout(state);
  }
  const shown = Number(currentSwitchId);
  if (affected.includes(shown)) {
    loadSwitchConfigStatus(shown);
    await reloadVlansAfterWrite(shown, state.session);
  }
}

document.getElementById('rollout-preview').addEventListener('change', event => {
  const state = rolloutState;
  const switchId = event.target?.dataset?.switchId;
  const port = event.target?.dataset?.port;
  if (!state || !switchId || !port || !state.selections.has(String(switchId))) return;
  const selected = state.selections.get(String(switchId));
  if (event.target.checked) selected.add(String(port));
  else selected.delete(String(port));
});
['rollout-vlan-id', 'rollout-vlan-name'].forEach(id => {
  const input = document.getElementById(id);
  input.addEventListener('input', invalidateRolloutPreview);
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter') requestRolloutPreview();
  });
});
document.getElementById('rollout-preview-btn').addEventListener('click', requestRolloutPreview);
document.getElementById('rollout-apply').addEventListener('click', applyRollout);
document.getElementById('rollout-cancel').addEventListener('click', closeVlanRolloutModal);

// --- VTP (Cisco) -------------------------------------------------------------

const VTP_MODE_LABELS = {
  server: () => t('Server'),
  client: () => t('Client'),
  transparent: () => t('Transparent'),
  off: () => t('Aus'),
};
const VTP_DOMAIN_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
let vtpRequestSequence = 0;
// switchId -> zuletzt gelesener VTP-Status des Tabs (Vergleichsbasis des Einstellungsformulars).
const vtpTabData = new Map();
let vtpPrimaryState = null;
let vtpDomainsRequestSequence = 0;

function vtpText(value) {
  return hasValue(value) ? String(value) : '—';
}

// Modus inkl. Primary/Secondary bei VTPv3-Servern.
function vtpModeText(entry) {
  const label = VTP_MODE_LABELS[entry?.mode]?.() ?? vtpText(entry?.mode);
  if (entry?.version !== 3 || entry?.mode !== 'server') return label;
  return `${label} (${entry.primary_server === true ? t('Primary') : t('Secondary')})`;
}

function vtpPasswordText(configured) {
  if (configured === true) return t('gesetzt');
  if (configured === false) return t('nicht gesetzt');
  return t('unbekannt');
}

function vtpPrimaryText(entry) {
  return vtpText(entry?.primary_description || entry?.primary_id);
}

// Hinweis der VTP-Sperre mit „Primary übernehmen“, wenn die Übernahme die Sperre aufhebt.
function renderVtpLock(switchId, lock, boxId, buttonId) {
  if (!lock || !hasValue(lock.reason)) return '';
  const takeover = lock.takeover === true && currentSessionCanEdit() && featureState(switchById(switchId), 'vtp').supported
    ? ` <button id="${buttonId}" class="primary" type="button">${escapeHtml(t('Primary übernehmen'))}</button>`
    : '';
  return `<div class="wlan-warning-box" id="${boxId}">${escapeHtml(lock.reason)}${takeover}</div>`;
}

function renderVtpStatus(data) {
  const item = (label, value) => `<div class="detail-item"><span class="detail-label">${escapeHtml(label)}</span><div class="detail-value">${escapeHtml(value)}</div></div>`;
  const capable = hasValue(data.version_capable) ? ` ${t('(unterstützt: {versions})', { versions: data.version_capable })}` : '';
  const primary = data.primary_description
    ? `${data.primary_description}${data.primary_id ? ` (${data.primary_id})` : ''}`
    : vtpText(data.primary_id);
  return `
    <h3 class="l2-section-title">${escapeHtml(t('Status'))}</h3>
    <div class="detail-grid">
      ${item(t('Domäne'), vtpText(data.domain))}
      ${item(t('VTP-Version'), `${vtpText(data.version)}${capable}`)}
      ${item(t('Modus'), vtpModeText(data))}
      ${item(t('Konfigurationsrevision'), vtpText(data.revision))}
      ${data.version === 3 ? item(t('Primary Server'), primary) : ''}
      ${item(t('Pruning'), data.pruning === true ? t('Aktiv') : data.pruning === false ? t('Aus') : '—')}
      ${item(t('Passwort'), vtpPasswordText(data.password_configured))}
      ${item(t('Device ID'), vtpText(data.device_id))}
      ${item(t('VLANs'), `${vtpText(data.vlan_count)} / ${vtpText(data.max_vlans)}`)}
      ${item(t('Zuletzt geändert'), vtpText(data.last_modified))}
      ${item(t('MD5'), vtpText(data.md5_digest))}
      ${hasValue(data.mst_mode) ? item(t('MST-Modus'), VTP_MODE_LABELS[data.mst_mode]?.() ?? String(data.mst_mode)) : ''}
    </div>
  `;
}

function renderVtpSettings(switchId, data) {
  const vtpState = featureState(switchById(switchId), 'vtp');
  const capable = /(\d)\s*$/.exec(String(data.version_capable ?? ''));
  const maxVersion = capable ? Number(capable[1]) : 3;
  const versions = [];
  for (let version = 1; version <= maxVersion; version += 1) versions.push(version);
  const versionOptions = (hasValue(data.version) ? '' : '<option value="">—</option>')
    + versions.map(version => `<option value="${version}"${version === data.version ? ' selected' : ''}>${version}</option>`).join('');
  const modes = vtpState.options || Object.keys(VTP_MODE_LABELS);
  const modeOptions = modes.map(mode => `<option value="${escapeHtml(mode)}"${mode === data.mode ? ' selected' : ''}>${escapeHtml(VTP_MODE_LABELS[mode]?.() ?? mode)}</option>`).join('');
  const pruning = data.pruning === null
    ? ''
    : `<div class="field"><label class="admin-check"><input id="vtp-pruning" type="checkbox"${data.pruning ? ' checked' : ''}> ${escapeHtml(t('VTP-Pruning'))}</label></div>`;
  return `
    <h3 class="l2-section-title">${escapeHtml(t('Einstellungen'))}</h3>
    <div class="device-form-grid">
      <div class="field"><label for="vtp-domain">${escapeHtml(t('Domäne'))}</label><input id="vtp-domain" maxlength="32" autocomplete="off" spellcheck="false" value="${escapeHtml(data.domain ?? '')}"></div>
      <div class="field"><label for="vtp-version">${escapeHtml(t('VTP-Version'))}</label><select id="vtp-version">${versionOptions}</select></div>
      <div class="field"><label for="vtp-mode">${escapeHtml(t('Modus'))}</label><select id="vtp-mode">${modeOptions}</select></div>
      ${pruning}
      <div class="field"><label for="vtp-password">${escapeHtml(t('Neues VTP-Passwort'))}</label><input id="vtp-password" type="password" autocomplete="new-password" placeholder="${escapeHtml(t('unverändert'))}"></div>
      <div class="field">
        <label class="admin-check"><input id="vtp-password-hidden" type="checkbox"> ${escapeHtml(t('verschlüsselt speichern (hidden, nur VTP 3)'))}</label>
        <label class="admin-check"><input id="vtp-password-clear" type="checkbox"${data.password_configured === false ? ' disabled' : ''}> ${escapeHtml(t('Passwort entfernen'))}</label>
      </div>
    </div>
    <div id="vtp-settings-error" class="wlan-form-error" role="alert"></div>
    <div class="flex-row" style="justify-content: flex-end;">
      <button id="vtp-settings-preview" class="primary" type="button">${escapeHtml(t('Vorschau'))}</button>
    </div>
  `;
}

function renderVtp(switchId, data) {
  return `
    ${renderInventoryWarnings(data.warnings)}
    ${renderVtpLock(switchId, data.vlan_lock, 'vtp-lock', 'btn-vtp-primary')}
    ${renderVtpStatus(data)}
    ${currentSessionCanEdit() ? renderVtpSettings(switchId, data) : ''}
  `;
}

async function loadVtp(switchId, { force = false } = {}) {
  const container = document.getElementById('vtp-container');
  const button = document.getElementById('btn-refresh-vtp');
  if (!container || (button?.disabled && !force)) return;
  const session = currentSession;
  const sequence = ++vtpRequestSequence;
  const isCurrentView = () => sequence === vtpRequestSequence && container === document.getElementById('vtp-container');
  const isCurrent = () => isCurrentView() && currentSession === session;
  if (button) button.disabled = true;
  try {
    const data = await api(`/api/switches/${switchId}/vtp`);
    if (!isCurrent()) return;
    if (!data || typeof data !== 'object') throw new Error(t('Ungültige VTP-Antwort.'));
    vtpTabData.set(Number(switchId), data);
    container.innerHTML = renderVtp(switchId, data);
    document.getElementById('btn-vtp-primary')?.addEventListener('click', () => openVtpPrimaryModal(switchId, reloadVtpAfterWrite));
    document.getElementById('vtp-settings-preview')?.addEventListener('click', () => submitVtpSettings(switchId));
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (isCurrentView() && button && button === document.getElementById('btn-refresh-vtp')) button.disabled = false;
  }
}

function reloadVtpAfterWrite(switchId, session) {
  return reloadL2TabAfterWrite(switchId, session, 'vtp-container', loadVtp);
}

// Nur geänderte Felder; das Passwort verlässt das Eingabefeld sofort und wird nie angezeigt.
function vtpSettingsParams(data) {
  const passwordInput = document.getElementById('vtp-password');
  const password = passwordInput.value;
  passwordInput.value = '';
  const params = {};
  const domain = document.getElementById('vtp-domain').value.trim();
  if (domain && domain !== (data.domain ?? '')) {
    if (!VTP_DOMAIN_PATTERN.test(domain)) {
      throw new Error(t('Ungültiger VTP-Domänenname: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich.'));
    }
    params.domain = domain;
  }
  const version = document.getElementById('vtp-version').value;
  if (version && Number(version) !== data.version) params.version = Number(version);
  const mode = document.getElementById('vtp-mode').value;
  if (mode && mode !== data.mode) params.mode = mode;
  const pruning = document.getElementById('vtp-pruning');
  if (pruning && pruning.checked !== data.pruning) params.pruning = pruning.checked;
  const clear = document.getElementById('vtp-password-clear').checked;
  if (password) {
    if (clear) throw new Error(t('Passwort setzen und entfernen schließen sich aus.'));
    if (password.length < 8 || password.length > 32) throw new Error(t('Das VTP-Passwort braucht 8–32 Zeichen.'));
    params.password = password;
    params.password_hidden = document.getElementById('vtp-password-hidden').checked;
  } else if (clear) {
    params.clear_password = true;
  }
  if (Object.keys(params).length === 0) throw new Error(t('Es wurde nichts geändert.'));
  return params;
}

async function submitVtpSettings(switchId) {
  if (!requireEditPermission()) return;
  const key = `${switchId}:vtp-configure`;
  const data = vtpTabData.get(Number(switchId));
  if (!data || pendingSwitchActions.has(key)) return;
  const showError = message => {
    const element = document.getElementById('vtp-settings-error');
    if (element) element.textContent = message;
  };
  showError('');
  let params;
  try {
    params = vtpSettingsParams(data);
  } catch (e) {
    showError(e.message);
    return;
  }
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  let applied = false;
  let message = '';
  try {
    const result = await runSwitchChange(switchId, 'vtp-configure', params, { title: t('VTP-Einstellungen ändern') });
    applied = Boolean(result);
    if (result && result.ok === false) message = result.message || '';
  } catch (e) {
    applied = true;
    message = e.message;
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
    if (applied) await reloadVtpAfterWrite(switchId, session);
    // Nach dem Neuladen, sonst ersetzt das neu gezeichnete Formular die Meldung.
    if (message && currentSession === session) showError(message);
  }
}

// reload: reloadVtpAfterWrite (VTP-Tab) oder reloadVlansAfterWrite (VLAN-Tab).
function openVtpPrimaryModal(switchId, reload) {
  if (!requireEditPermission()) return;
  if (modalOperations.has('vtp-primary-modal')) return;
  vtpPrimaryState = { switchId: Number(switchId), session: currentSession, reload };
  const input = document.getElementById('vtp-primary-password');
  input.value = '';
  document.getElementById('vtp-primary-error').textContent = '';
  setElementHidden('vtp-primary-modal', false);
  input.focus();
}

function closeVtpPrimaryModal() {
  setElementHidden('vtp-primary-modal', true);
  vtpPrimaryState = null;
}

async function submitVtpPrimary() {
  if (!requireEditPermission()) return;
  const state = vtpPrimaryState;
  if (!state || state.session !== currentSession) return;
  const input = document.getElementById('vtp-primary-password');
  const password = input.value;
  input.value = '';
  if (password && (password.length < 8 || password.length > 32)) {
    document.getElementById('vtp-primary-error').textContent = t('Das VTP-Passwort braucht 8–32 Zeichen.');
    return;
  }
  await runL2ModalChange({
    modalId: 'vtp-primary-modal', errorId: 'vtp-primary-error', switchId: state.switchId, session: state.session,
    kind: 'vtp-primary', params: password ? { password } : {}, title: t('Primary Server übernehmen'),
    reload: state.reload, close: () => { if (vtpPrimaryState === state) closeVtpPrimaryModal(); },
  });
}

document.getElementById('vtp-primary-cancel').addEventListener('click', closeVtpPrimaryModal);
document.getElementById('vtp-primary-save').addEventListener('click', submitVtpPrimary);
document.getElementById('vtp-primary-password').addEventListener('keydown', event => {
  if (event.key === 'Enter') submitVtpPrimary();
});

// --- VTP-Domänenübersicht ----------------------------------------------------

function renderVtpReasonTable(title, entries) {
  if (entries.length === 0) return '';
  return `
    <h3 class="l2-section-title">${escapeHtml(title)}</h3>
    <div style="overflow-x: auto;">
      <table>
        <thead><tr><th>${escapeHtml(t('Switch'))}</th><th>${escapeHtml(t('Grund'))}</th></tr></thead>
        <tbody>${entries.map(entry => `<tr><td>${escapeHtml(vtpText(entry.name))}</td><td>${escapeHtml(vtpText(entry.reason))}</td></tr>`).join('')}</tbody>
      </table>
    </div>
  `;
}

function renderVtpDomain(domain) {
  const members = Array.isArray(domain.members) ? domain.members.filter(member => member && typeof member === 'object') : [];
  const issues = Array.isArray(domain.issues) ? domain.issues.filter(issue => issue && hasValue(issue.message)) : [];
  const name = hasValue(domain.domain) ? String(domain.domain) : t('(keine Domäne)');
  const pruning = value => (value === true ? t('Aktiv') : value === false ? t('Aus') : '—');
  return `
    <h3 class="l2-section-title">${escapeHtml(t('Domäne {name}', { name }))}</h3>
    ${issues.map(issue => `<div class="${issue.severity === 'warning' ? 'wlan-warning-box' : 'admin-muted'}">${escapeHtml(issue.message)}</div>`).join('')}
    <div style="overflow-x: auto;">
      <table>
        <thead><tr><th>${escapeHtml(t('Switch'))}</th><th>${escapeHtml(t('Modus'))}</th><th>${escapeHtml(t('Version'))}</th><th>${escapeHtml(t('Revision'))}</th><th>${escapeHtml(t('Primary Server'))}</th><th>${escapeHtml(t('Passwort'))}</th><th>${escapeHtml(t('Pruning'))}</th></tr></thead>
        <tbody>
          ${members.map(member => `
            <tr>
              <td>${escapeHtml(vtpText(member.name))}</td>
              <td>${escapeHtml(vtpModeText(member))}</td>
              <td>${escapeHtml(vtpText(member.version))}</td>
              <td>${escapeHtml(vtpText(member.revision))}</td>
              <td>${escapeHtml(vtpPrimaryText(member))}</td>
              <td>${escapeHtml(vtpPasswordText(member.password_configured))}</td>
              <td>${escapeHtml(pruning(member.pruning))}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderVtpDomains(data) {
  const list = value => (Array.isArray(value) ? value.filter(item => item && typeof item === 'object') : []);
  const domains = list(data?.domains);
  const unreadable = list(data?.unreadable);
  const skipped = list(data?.skipped);
  if (domains.length === 0 && unreadable.length === 0 && skipped.length === 0) {
    return `<div class="empty-state">${escapeHtml(t('Keine Switches mit VTP-Unterstützung.'))}</div>`;
  }
  return domains.map(renderVtpDomain).join('')
    + renderVtpReasonTable(t('Nicht lesbar'), unreadable)
    + renderVtpReasonTable(t('Übersprungen'), skipped);
}

async function loadVtpDomains() {
  const body = document.getElementById('vtp-domains-body');
  const button = document.getElementById('vtp-domains-refresh');
  const session = currentSession;
  const sequence = ++vtpDomainsRequestSequence;
  const isCurrent = () => sequence === vtpDomainsRequestSequence && currentSession === session;
  body.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade VTP-Status aller Cisco-Switches …'))}</div>`;
  button.disabled = true;
  try {
    const data = await api('/api/vtp/domains');
    if (!isCurrent()) return;
    body.innerHTML = renderVtpDomains(data);
  } catch (e) {
    if (!isCurrent()) return;
    body.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (sequence === vtpDomainsRequestSequence) button.disabled = false;
  }
}

function openVtpDomainsModal() {
  setElementHidden('vtp-domains-modal', false);
  return loadVtpDomains();
}

function closeVtpDomainsModal() {
  vtpDomainsRequestSequence += 1;
  setElementHidden('vtp-domains-modal', true);
  document.getElementById('vtp-domains-refresh').disabled = false;
}

document.getElementById('btn-vtp-domains').addEventListener('click', openVtpDomainsModal);
document.getElementById('vtp-domains-refresh').addEventListener('click', loadVtpDomains);
document.getElementById('vtp-domains-close').addEventListener('click', closeVtpDomainsModal);

registerSessionHooks({
  closePrivilegedModals: () => {
    L2_MODAL_IDS.forEach(id => setElementHidden(id, true));
    lagModalState = null;
    stpModalState = null;
    rolloutState = null;
    vtpPrimaryState = null;
    vtpDomainsRequestSequence += 1;
  },
});
