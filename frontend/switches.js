// --- Switch-Liste ------------------------------------------------------

async function loadSwitches({ reuseInFlight = false } = {}) {
  const sessionAtStart = currentSession;
  if (reuseInFlight && switchListRequest?.session === sessionAtStart
      && switchListRequest.sequence === switchListSequence) {
    return switchListRequest.promise;
  }
  const sequence = ++switchListSequence;
  const request = { session: sessionAtStart, sequence, promise: null };
  request.promise = (async () => {
    try {
      const [loadedSwitches, loadedGroups] = await Promise.all([
        api('/api/switches'),
        api('/api/switch-groups'),
      ]);
      if (currentSession && currentSession === sessionAtStart && sequence === switchListSequence) {
        switches = loadedSwitches;
        switchGroups = loadedGroups;
        renderSwitchList();
      }
    } catch (error) {
      if (currentSession === sessionAtStart && sequence === switchListSequence) throw error;
    }
    // A mutation may supersede a navigation read while it is in flight.
    // Its callers must wait for the newer inventory before showing details.
    if (currentSession === sessionAtStart && switchListRequest?.session === sessionAtStart
        && switchListRequest.sequence > sequence) return switchListRequest.promise;
  })();
  switchListRequest = request;
  try {
    return await request.promise;
  } finally {
    if (switchListRequest === request) switchListRequest = null;
  }
}

function renderSwitchItem(sw) {
  const el = document.createElement('div');
  el.className = 'switch-item' + (Number(sw.id) === currentSwitchId ? ' active' : '');
  el.innerHTML = `${escapeHtml(sw.name)}<div class="ip">${escapeHtml(sw.ip)} ${sw.site ? '· ' + escapeHtml(sw.site) : ''}</div>
    <div class="ip">${escapeHtml(switchCredentialsLabel(sw))}</div>
    ${currentSessionCanEdit() ? `<button class="switch-credentials-action" type="button" style="font-size:11px; padding:2px 6px; margin-top:5px" aria-label="${escapeHtml(t('Zugangsdaten für {name} konfigurieren', { name: sw.name }))}">${escapeHtml(t('Zugangsdaten'))}</button>` : ''}`;
  el.querySelector('.switch-credentials-action')?.addEventListener('click', event => {
    event.stopPropagation();
    void openSwitchCredentialsModal(sw);
  });
  el.addEventListener('click', () => selectSwitch(sw.id));
  return el;
}

function toggleSwitchGroup(groupKey) {
  if (collapsedGroups.has(groupKey)) {
    collapsedGroups.delete(groupKey);
  } else {
    collapsedGroups.add(groupKey);
  }
  persistCollapsedGroups();
  renderSwitchList();
}

function persistCollapsedGroups() {
  try {
    localStorage.setItem(collapsedGroupsStorageKey, JSON.stringify([...collapsedGroups]));
  } catch {
    // Die Liste bleibt auch ohne verfuegbaren Browser-Speicher bedienbar.
  }
}

function renderSwitchList() {
  const list = document.getElementById('switch-list');
  list.innerHTML = '';
  const query = document.getElementById('switch-search').value.trim().toLocaleLowerCase('de');
  const groupsById = new Map(switchGroups.map(group => [group.id, group]));
  const filteredSwitches = query ? switches.filter(sw => {
    const groupName = groupsById.get(sw.group_id)?.name || '';
    return [sw.name, sw.ip, sw.site, sw.notes, groupName]
      .some(value => String(value || '').toLocaleLowerCase('de').includes(query));
  }) : switches;

  if (query && filteredSwitches.length === 0) {
    list.innerHTML = `<div style="color: var(--text-dim); font-size: 12px;">${escapeHtml(t('Keine passenden Switches gefunden.'))}</div>`;
    return;
  }

  const membersByGroup = new Map();
  filteredSwitches.forEach(sw => {
    const groupId = groupsById.has(sw.group_id) ? sw.group_id : null;
    if (!membersByGroup.has(groupId)) membersByGroup.set(groupId, []);
    membersByGroup.get(groupId).push(sw);
  });
  switchGroups.forEach(group => {
    const members = membersByGroup.get(group.id) || [];
    if (query && members.length === 0) return;
    const groupKey = `group:${group.id}`;
    const collapsed = !query && collapsedGroups.has(groupKey);
    const section = document.createElement('section');
    section.className = 'group-section';
    const header = document.createElement('div');
    header.className = 'group-header';
    const groupActions = currentSessionCanEdit() ? `
      <button class="group-action rollout" title="${escapeHtml(t('VLAN ausrollen'))}" aria-label="${escapeHtml(t('VLAN auf Gruppe {name} ausrollen', { name: group.name }))}">⇉</button>
      <button class="group-action edit" title="${escapeHtml(t('Gruppe umbenennen'))}" aria-label="${escapeHtml(t('Gruppe {name} umbenennen', { name: group.name }))}">✎</button>
      <button class="group-action delete" title="${escapeHtml(t('Gruppe löschen'))}" aria-label="${escapeHtml(t('Gruppe {name} löschen', { name: group.name }))}">×</button>
    ` : '';
    header.innerHTML = `
      <button class="group-action toggle" title="${escapeHtml(collapsed ? t('Gruppe aufklappen') : t('Gruppe einklappen'))}" aria-expanded="${!collapsed}" aria-label="${escapeHtml(collapsed ? t('Gruppe {name} aufklappen', { name: group.name }) : t('Gruppe {name} einklappen', { name: group.name }))}">${collapsed ? '▸' : '▾'}</button>
      <span class="group-name">${escapeHtml(group.name)}</span>
      <span class="group-count">${members.length}</span>
      ${groupActions}
    `;
    header.querySelector('.toggle').addEventListener('click', () => toggleSwitchGroup(groupKey));
    header.querySelector('.group-name').addEventListener('click', () => toggleSwitchGroup(groupKey));
    header.querySelector('.edit')?.addEventListener('click', () => openGroupModal(group));
    header.querySelector('.rollout')?.addEventListener('click', () => openVlanRolloutModal(group));
    header.querySelector('.delete')?.addEventListener('click', () => deleteSwitchGroup(group));
    section.appendChild(header);
    const memberList = document.createElement('div');
    memberList.className = 'group-members' + (collapsed ? ' hidden' : '');
    members.forEach(sw => memberList.appendChild(renderSwitchItem(sw)));
    if (members.length === 0) {
      const empty = document.createElement('div');
      empty.style.cssText = 'color: var(--text-dim); font-size: 11px; padding: 4px 10px;';
      empty.textContent = t('Keine Switches');
      memberList.appendChild(empty);
    }
    section.appendChild(memberList);
    list.appendChild(section);
  });

  const ungrouped = membersByGroup.get(null) || [];
  if (ungrouped.length > 0) {
    const groupKey = 'ungrouped';
    const collapsed = !query && collapsedGroups.has(groupKey);
    const section = document.createElement('section');
    section.className = 'group-section';
    section.innerHTML = `<div class="group-header"><button class="group-action toggle" title="${escapeHtml(collapsed ? t('Gruppe aufklappen') : t('Gruppe einklappen'))}" aria-expanded="${!collapsed}" aria-label="${escapeHtml(collapsed ? t('Ohne Gruppe aufklappen') : t('Ohne Gruppe einklappen'))}">${collapsed ? '▸' : '▾'}</button><span class="group-name">${escapeHtml(t('Ohne Gruppe'))}</span><span class="group-count">${ungrouped.length}</span></div>`;
    section.querySelector('.toggle').addEventListener('click', () => toggleSwitchGroup(groupKey));
    section.querySelector('.group-name').addEventListener('click', () => toggleSwitchGroup(groupKey));
    const memberList = document.createElement('div');
    memberList.className = 'group-members' + (collapsed ? ' hidden' : '');
    ungrouped.forEach(sw => memberList.appendChild(renderSwitchItem(sw)));
    section.appendChild(memberList);
    list.appendChild(section);
  }

  if (switches.length === 0 && switchGroups.length === 0) {
    list.innerHTML = `<div style="color: var(--text-dim); font-size: 12px;">${escapeHtml(t('Noch keine Switches oder Gruppen angelegt.'))}</div>`;
  }
}

document.getElementById('switch-search').addEventListener('input', renderSwitchList);

async function selectSwitch(id) {
  const normalizedId = Number(id);
  const selectionSequence = ++switchSelectionSequence;
  globalSearchSequence += 1;
  if (!Number.isInteger(normalizedId) || normalizedId <= 0) {
    currentSwitchId = null;
    document.getElementById('main-content').innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(t('Ungültige Switch-ID.'))}</div>`;
    renderSwitchList();
    return;
  }
  currentSwitchId = normalizedId;
  cancelInterfaceInventoryWork();
  document.getElementById('main-content').innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Switch …'))}</div>`;
  try {
    await loadSwitches({ reuseInFlight: true });
  } catch (error) {
    if (selectionSequence !== switchSelectionSequence || currentSwitchId !== normalizedId) return;
    currentSwitchId = null;
    renderSwitchList();
    document.getElementById('main-content').innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(error.message)}</div>`;
    return;
  }
  if (selectionSequence !== switchSelectionSequence || currentSwitchId !== normalizedId) return;
  const sw = switches.find(s => Number(s.id) === normalizedId);
  if (!sw) {
    currentSwitchId = null;
    renderSwitchList();
    document.getElementById('main-content').innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(t('Der ausgewählte Switch ist nicht mehr vorhanden.'))}</div>`;
    return;
  }
  renderSwitchDetail(sw);
}

// --- Capabilities (driver ∩ model profile ∩ runtime) ---------------------

function switchById(id) {
  return switches.find(sw => Number(sw.id) === Number(id)) || null;
}

// Effective state of one feature; port-level capability_overrides take precedence over the switch capabilities.
function featureState(sw, id, overrides = null) {
  if (overrides && typeof overrides === 'object' && Object.prototype.hasOwnProperty.call(overrides, id)) {
    return { supported: false, reason: hasValue(overrides[id]) ? String(overrides[id]) : '', options: null, requires: [] };
  }
  const capabilities = sw?.capabilities;
  // Responses without capability data impose no restrictions.
  if (!capabilities || typeof capabilities !== 'object') return { supported: true, reason: '', options: null, requires: [] };
  const entry = capabilities[id];
  if (!entry || typeof entry !== 'object') {
    return { supported: false, reason: t('Vom Treiber nicht unterstützt.'), options: null, requires: [] };
  }
  return {
    supported: entry.supported === true,
    reason: hasValue(entry.reason) ? String(entry.reason) : '',
    options: Array.isArray(entry.options) ? entry.options.map(String) : null,
    requires: Array.isArray(entry.requires) ? entry.requires.map(String) : [],
  };
}

function incompatibleTitle(state) {
  return state.reason ? `${t('Inkompatibel')}: ${state.reason}` : t('Inkompatibel');
}

function incompatibleAttributes(state) {
  if (!state || state.supported) return '';
  return ` disabled aria-disabled="true" class="is-incompatible" title="${escapeHtml(incompatibleTitle(state))}"`;
}

function incompatibleBadge() {
  return `<span class="incompatible-badge">${escapeHtml(t('inkompatibel'))}</span>`;
}

// Same marking as incompatibleAttributes for controls that already exist in the DOM.
function applyIncompatibleState(element, state) {
  element.classList.toggle('is-incompatible', !state.supported);
  if (state.supported) {
    element.removeAttribute('aria-disabled');
    element.removeAttribute('title');
  } else {
    element.setAttribute('aria-disabled', 'true');
    element.setAttribute('title', incompatibleTitle(state));
  }
}

function renderSwitchPlatform(sw) {
  const driver = sw.driver && typeof sw.driver === 'object' ? sw.driver : null;
  const platform = driver
    ? `${driver.label || sw.device_type}${driver.experimental ? ` ${t('(experimentell)')}` : ''}`
    : `${sw.device_type || '—'} · ${t('Unbekannter Gerätetyp')}`;
  const model = hasValue(sw.model?.effective_label) ? String(sw.model.effective_label) : t('Modell unbekannt');
  return `${platform} · ${model}`;
}

function renderSwitchModelMismatch(sw) {
  const model = sw.model && typeof sw.model === 'object' ? sw.model : null;
  if (!model || !hasValue(model.selected_id) || !hasValue(model.detected) || model.detected_id === model.selected_id) return '';
  return `<div class="search-warning">${escapeHtml(t('Erkanntes Modell {detected} weicht von der Auswahl ab.', { detected: model.detected }))}</div>`;
}

function renderSwitchDetail(sw) {
  const main = document.getElementById('main-content');
  const switchId = Number(sw && sw.id);
  if (!sw || !Number.isInteger(switchId) || switchId <= 0) {
    main.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(t('Switchdaten konnten nicht geladen werden.'))}</div>`;
    return;
  }
  const group = sw.group_id == null
    ? null
    : switchGroups.find(candidate => Number(candidate.id) === Number(sw.group_id));
  const groupName = group?.name || t('Ohne Gruppe');
  const saveConfigState = featureState(sw, 'save_config');
  const compareState = featureState(sw, 'config_compare');
  const writeActions = currentSessionCanEdit() ? `
    <button id="btn-test-conn">${escapeHtml(t('Verbindung testen'))}</button>
    <button id="btn-save-config"${incompatibleAttributes(saveConfigState)}>${escapeHtml(t('Config speichern'))}${saveConfigState.supported ? '' : incompatibleBadge()}</button>
    <button id="btn-edit-switch">${escapeHtml(t('Bearbeiten'))}</button>
    <button id="btn-switch-credentials">${escapeHtml(t('Zugangsdaten'))}</button>
    <button class="danger" id="btn-delete-switch">${escapeHtml(t('Löschen'))}</button>
  ` : '';
  const tabs = Object.entries(switchTabs).map(([tab, definition]) => {
    const state = switchTabState(sw, definition);
    return state.supported
      ? `<button class="tab-btn" data-tab="${tab}">${escapeHtml(definition.title())}</button>`
      : `<button class="tab-btn is-incompatible" data-tab="${tab}" disabled aria-disabled="true" title="${escapeHtml(incompatibleTitle(state))}">${escapeHtml(definition.title())}${incompatibleBadge()}</button>`;
  }).join('');
  const initialTab = Object.keys(switchTabs).find(tab => switchTabState(sw, switchTabs[tab]).supported);
  main.innerHTML = `
    <div class="panel-box">
      <div class="flex-row" style="justify-content: space-between;">
        <div>
          <strong style="font-family: var(--mono)">${escapeHtml(sw.name)}</strong>
          <span style="color: var(--text-dim); font-family: var(--mono); font-size: 12px;"> ${escapeHtml(sw.ip)}:${escapeHtml(sw.port)} · ${escapeHtml(renderSwitchPlatform(sw))}</span>
          ${renderSwitchModelMismatch(sw)}
          <div class="flex-row" style="margin-top: 4px; gap: 6px;"><span id="switch-config-status" class="config-status-badge" data-switch-id="${switchId}">${escapeHtml(t('Speicherstand wird geladen …'))}</span>
            <button id="btn-config-compare"${incompatibleAttributes(compareState)}>${escapeHtml(t('Mit Gerät vergleichen'))}${compareState.supported ? '' : incompatibleBadge()}</button></div>
        </div>
        <div class="flex-row">
          ${writeActions}
        </div>
      </div>
      <div id="switch-rollback-banner" class="rollback-banner hidden" role="status"></div>
      <div class="detail-grid" aria-label="${escapeHtml(t('Switch-Inventardetails'))}">
        <div class="detail-item"><span class="detail-label">${escapeHtml(t('Standort'))}</span><div class="detail-value">${escapeHtml(sw.site || '—')}</div></div>
        <div class="detail-item"><span class="detail-label">${escapeHtml(t('Gruppe'))}</span><div class="detail-value">${escapeHtml(groupName)}</div></div>
        <div class="detail-item"><span class="detail-label">${escapeHtml(t('Notizen'))}</span><div class="detail-value">${escapeHtml(sw.notes || '—')}</div></div>
        <div class="detail-item"><span class="detail-label">${escapeHtml(t('Zugangsdaten'))}</span><div class="detail-value">${escapeHtml(switchCredentialsLabel(sw))}</div></div>
      </div>
    </div>
    <div class="flex-row" style="margin-bottom: 12px; gap: 4px;">
      ${tabs}
    </div>
    <div id="tab-content"></div>
  `;
  document.getElementById('btn-test-conn')?.addEventListener('click', () => testConnection(switchId));
  document.getElementById('btn-save-config')?.addEventListener('click', () => saveConfig(switchId));
  document.getElementById('btn-edit-switch')?.addEventListener('click', () => openSwitchModal(sw));
  document.getElementById('btn-switch-credentials')?.addEventListener('click', () => openSwitchCredentialsModal(sw));
  document.getElementById('btn-delete-switch')?.addEventListener('click', () => deleteSwitch(switchId));
  document.getElementById('btn-config-compare')?.addEventListener('click', () => compareSwitchConfig(switchId));
  loadSwitchConfigStatus(switchId);
  main.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      main.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      showTab(switchId, btn.dataset.tab);
    });
  });
  if (initialTab) {
    main.querySelector(`.tab-btn[data-tab="${initialTab}"]`)?.classList.add('active');
    showTab(switchId, initialTab);
  } else {
    document.getElementById('tab-content').innerHTML = `<div class="empty-state">${escapeHtml(t('Für diesen Switch ist keine Ansicht verfügbar.'))}</div>`;
  }
}

function cancelInterfaceInventoryWork() {
  interfaceInventoryRequestSequence += 1;
  interfaceInventoryPollSequence += 1;
  clientInventoryRequestSequence += 1;
  neighborsRequestSequence += 1;
  summaryRequestSequence += 1;
  vlanRequestSequence += 1;
  backupRequestSequence += 1;
}

function renderTabPanel(title, containerId, loadingText = t('Lade {title} …', { title })) {
  const refreshId = `btn-refresh-${containerId.replace(/-container$/, '')}`;
  return `
      <div class="panel-box">
        <div class="flex-row" style="justify-content: space-between; margin-bottom: 10px;">
          <h3 style="margin:0; font-size: 13px; color: var(--text-dim); text-transform: uppercase;">${escapeHtml(title)}</h3>
          <button id="${refreshId}">${escapeHtml(t('Aktualisieren'))}</button>
        </div>
        <div id="${containerId}"><div class="empty-state">${escapeHtml(loadingText)}</div></div>
      </div>
    `;
}

// A tab is available when any of its features is supported (`features`) or its single `feature` is.
function switchTabState(sw, definition) {
  const states = (definition.features || [definition.feature]).map(feature => featureState(sw, feature));
  return states.find(state => state.supported) || states[0];
}

const switchTabs = {
  interfaces: { feature: 'interfaces', title: () => t('Interfaces'), load: switchId => loadInterfaces(switchId) },
  vlans: { feature: 'vlans', title: () => t('VLANs'), load: switchId => loadVlans(switchId) },
  vtp: { feature: 'vtp', title: () => t('VTP'), load: switchId => loadVtp(switchId) },
  security: {
    features: ['port_security', 'dot1x', 'stp_guard', 'storm_control', 'dhcp_snooping', 'arp_inspection', 'ip_source_guard'],
    title: () => t('Port-Sicherheit'),
    load: switchId => loadPortSecurity(switchId),
  },
  lags: { feature: 'lag', title: () => t('Link-Aggregation'), load: switchId => loadLags(switchId) },
  stp: { feature: 'stp', title: () => t('Spanning Tree'), load: switchId => loadStp(switchId) },
  summary: { feature: 'device_summary', title: () => t('Summary'), load: switchId => loadSummary(switchId) },
  backups: { feature: 'config_backup', title: () => t('Backups'), load: switchId => loadBackups(switchId) },
  device: {
    features: ['device_identity', 'device_services', 'device_snmp', 'device_aaa', 'device_users', 'device_ssh', 'device_l3', 'acl', 'qos'],
    title: () => t('Gerät'),
    load: switchId => loadDeviceConfig(switchId),
  },
  maintenance: { feature: 'reload', title: () => t('Wartung'), load: switchId => loadMaintenance(switchId) },
  diagnostics: { feature: 'diag_counters', title: () => t('Diagnose'), load: switchId => loadDiagnostics(switchId) },
  neighbors: { feature: 'neighbors', title: () => t('Nachbarn'), load: switchId => loadNeighbors(switchId) },
  clients: { feature: 'clients', title: () => t('Current Associated Clients'), loadingText: t('Lade Clients …'), load: switchId => loadClients(switchId) },
};

function showTab(switchId, tab) {
  const content = document.getElementById('tab-content');
  if (!content || (content.dataset.switchId === String(switchId) && content.dataset.tab === tab)) return;
  cancelInterfaceInventoryWork();
  content.dataset.switchId = String(switchId);
  content.dataset.tab = tab;
  const definition = switchTabs[tab];
  if (!definition) return;
  content.innerHTML = renderTabPanel(definition.title(), `${tab}-container`, definition.loadingText);
  document.getElementById(`btn-refresh-${tab}`).addEventListener('click', () => definition.load(switchId));
  definition.load(switchId);
}

async function loadNeighbors(switchId) {
  const container = document.getElementById('neighbors-container');
  if (!container) return;
  const sequence = ++neighborsRequestSequence;
  const isCurrent = () => sequence === neighborsRequestSequence
    && container === document.getElementById('neighbors-container');
  container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Nachbarn …'))}</div>`;
  try {
    const neighbors = await api(`/api/switches/${switchId}/neighbors`);
    if (!isCurrent()) return;
    if (neighbors.length === 0) {
      container.innerHTML = `<div class="empty-state">${escapeHtml(t('Keine Nachbarn gefunden.'))}</div>`;
      return;
    }
    const rows = neighbors.map(neighbor => {
      const version = neighbor.software_version
        ? `<div><strong>${escapeHtml(t('Software:'))}</strong><pre style="white-space: pre-wrap; margin: 4px 0 0; font-family: var(--mono);">${escapeHtml(neighbor.software_version)}</pre></div>`
        : '';
      const details = [
        neighbor.holdtime_seconds != null ? `<div><strong>${escapeHtml(t('Holdtime:'))}</strong> ${escapeHtml(neighbor.holdtime_seconds)} s</div>` : '',
        neighbor.native_vlan != null ? `<div><strong>${escapeHtml(t('Native VLAN:'))}</strong> ${escapeHtml(neighbor.native_vlan)}</div>` : '',
        neighbor.duplex ? `<div><strong>${escapeHtml(t('Duplex:'))}</strong> ${escapeHtml(neighbor.duplex)}</div>` : '',
        neighbor.vtp_domain ? `<div><strong>${escapeHtml(t('VTP-Domain:'))}</strong> ${escapeHtml(neighbor.vtp_domain)}</div>` : '',
        neighbor.advertisement_version ? `<div><strong>${escapeHtml(t('CDP-Version:'))}</strong> ${escapeHtml(neighbor.advertisement_version)}</div>` : '',
        version,
      ].filter(Boolean).join('');
      return `
        <tr class="neighbor-row">
          <td>${escapeHtml(hasValue(neighbor.protocol) ? String(neighbor.protocol).toUpperCase() : '—')}</td>
          <td>${escapeHtml(neighbor.device_id)}</td>
          <td>${escapeHtml(neighbor.platform || '—')}</td>
          <td>${escapeHtml((neighbor.ip_addresses || []).join(', ') || '—')}</td>
          <td>${escapeHtml(neighbor.local_interface || '—')}</td>
          <td>${escapeHtml(neighbor.remote_interface || '—')}</td>
          <td>${escapeHtml(neighbor.capabilities || '—')}</td>
          <td>${details ? `<details><summary class="link">${escapeHtml(t('Anzeigen'))}</summary>${details}</details>` : '—'}</td>
        </tr>
      `;
    }).join('');
    container.innerHTML = `
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr><th>${escapeHtml(t('Protokoll'))}</th><th>${escapeHtml(t('Name / Device ID'))}</th><th>${escapeHtml(t('Plattform / Typ'))}</th><th>${escapeHtml(t('IP-Adresse(n)'))}</th><th>${escapeHtml(t('Lokaler Port'))}</th><th>${escapeHtml(t('Nachbar-Port'))}</th><th>${escapeHtml(t('Fähigkeiten'))}</th><th>${escapeHtml(t('Weitere Parameter'))}</th></tr>
            <tr class="filter-row">
              <th><input class="table-filter" type="search" data-column="0" placeholder="${escapeHtml(t('Protokoll suchen'))}" aria-label="${escapeHtml(t('Protokoll suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="1" placeholder="${escapeHtml(t('Name suchen'))}" aria-label="${escapeHtml(t('Name oder Device ID suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="2" placeholder="${escapeHtml(t('Plattform suchen'))}" aria-label="${escapeHtml(t('Plattform oder Typ suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="3" placeholder="${escapeHtml(t('IP suchen'))}" aria-label="${escapeHtml(t('IP-Adresse suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="4" placeholder="${escapeHtml(t('Port suchen'))}" aria-label="${escapeHtml(t('Lokalen Port suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="5" placeholder="${escapeHtml(t('Port suchen'))}" aria-label="${escapeHtml(t('Nachbar-Port suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="6" placeholder="${escapeHtml(t('Fähigkeit suchen'))}" aria-label="${escapeHtml(t('Fähigkeit suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="7" placeholder="${escapeHtml(t('Parameter suchen'))}" aria-label="${escapeHtml(t('Weitere Parameter suchen'))}"></th>
            </tr>
          </thead>
          <tbody>
            ${rows}
            <tr id="no-neighbor-results" class="hidden"><td colspan="8" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden Nachbarn gefunden.'))}</td></tr>
          </tbody>
        </table>
      </div>
    `;
    attachTableFilters(container, '.neighbor-row', '#no-neighbor-results');
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  }
}

function renderSummaryPoe(poe, budgetState = { supported: true }) {
  if (!budgetState.supported) {
    return `<tr><th>${escapeHtml(t('PoE-Budget'))}</th><td><span title="${escapeHtml(incompatibleTitle(budgetState))}">${incompatibleBadge()}</span>`
      + `${budgetState.reason ? `<div class="interface-state-detail">${escapeHtml(budgetState.reason)}</div>` : ''}</td></tr>`;
  }
  const data = poe && typeof poe === 'object' ? poe : {};
  const unsupported = data.supported === false;
  const watts = value => unsupported ? escapeHtml(t('Nicht unterstützt'))
    : typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? formatPoeWatts(value) : escapeHtml(t('Nicht verfügbar'));
  const standards = Array.isArray(data.standards)
    ? data.standards.filter(value => typeof value === 'string' && value.trim()) : [];
  const standardsLabel = unsupported ? escapeHtml(t('Nicht unterstützt'))
    : standards.length ? standards.map(escapeHtml).join(', ') : escapeHtml(t('Nicht verfügbar'));
  const source = !unsupported && standards.length && typeof data.standards_source === 'string'
    ? `<div class="interface-state-detail">${escapeHtml(data.standards_source)}</div>` : '';
  const remaining = !unsupported && typeof data.remaining_watts === 'number'
    && Number.isFinite(data.remaining_watts) && data.remaining_watts >= 0
    ? `<tr><th>${escapeHtml(t('PoE-Budget verfügbar'))}</th><td>${watts(data.remaining_watts)}</td></tr>` : '';
  return `
    <tr><th>${escapeHtml(t('PoE-Budget genutzt / zugeteilt'))}</th><td>${watts(data.used_watts)}</td></tr>
    <tr><th>${escapeHtml(t('PoE-Budget maximal'))}</th><td>${watts(data.max_watts)}</td></tr>
    ${remaining}
    <tr><th>${escapeHtml(t('Unterstützte PoE-Versionen'))}</th><td>${standardsLabel}${source}</td></tr>
  `;
}

async function loadSummary(switchId) {
  const container = document.getElementById('summary-container');
  const button = document.getElementById('btn-refresh-summary');
  if (!container || button?.disabled) return;
  const session = currentSession;
  const sequence = ++summaryRequestSequence;
  const isCurrentView = () => sequence === summaryRequestSequence
    && container === document.getElementById('summary-container');
  const isCurrent = () => isCurrentView() && currentSession === session;
  if (button) button.disabled = true;
  try {
    const s = await api(`/api/switches/${switchId}/summary`);
    if (!isCurrent()) return;
    const sw = switchById(switchId);
    const deviceIp = sw?.ip;
    container.innerHTML = `
      <table>
        <tbody>
          <tr><th>${escapeHtml(t('Hostname'))}</th><td>${escapeHtml(s.hostname || '—')}</td></tr>
          <tr><th>${escapeHtml(t('IP-Adresse'))}</th><td>${escapeHtml(deviceIp || '—')}</td></tr>
          <tr><th>${escapeHtml(t('Modell'))}</th><td>${escapeHtml(s.model || '—')}</td></tr>
          <tr><th>${escapeHtml(t('Seriennummer'))}</th><td>${escapeHtml(s.serial_number || '—')}</td></tr>
          <tr><th>${escapeHtml(t('Software-Version'))}</th><td>${escapeHtml(s.software_version || '—')}</td></tr>
          <tr><th>${escapeHtml(t('Uptime'))}</th><td>${escapeHtml(s.uptime || '—')}</td></tr>
          <tr><th>${escapeHtml(t('Ports Up'))}</th><td class="status-connected">${escapeHtml(s.ports_up)}</td></tr>
          <tr><th>${escapeHtml(t('Ports Down'))}</th><td class="status-notconnect">${escapeHtml(s.ports_down)}</td></tr>
          <tr><th>${escapeHtml(t('Ports abgeschaltet'))}</th><td class="status-disabled">${escapeHtml(s.ports_disabled ?? 0)}</td></tr>
          <tr><th>${escapeHtml(t('Ports Gesamt'))}</th><td>${escapeHtml(s.ports_total)}</td></tr>
          ${renderSummaryPoe(s.poe, featureState(sw, 'poe_budget'))}
        </tbody>
      </table>
      ${renderInventoryWarnings(s.poe?.warnings)}
    `;
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (isCurrentView() && button === document.getElementById('btn-refresh-summary') && button) button.disabled = false;
  }
}

const CLIENT_UNKNOWN_LABEL = t('Nicht ermittelbar');

function hasValue(value) {
  return value !== null && value !== undefined && String(value).trim() !== '';
}

function nonnegativeClientCount(value, fallback) {
  if (!hasValue(value)) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.trunc(parsed) : fallback;
}

function clientSourceLabel(source) {
  const labels = {
    arp: 'ARP',
    device_tracking: 'Device Tracking',
    dhcp_snooping: 'DHCP Snooping',
    cdp: 'CDP',
    lldp: 'LLDP',
    dns: 'Reverse DNS',
    reverse_dns: 'Reverse DNS',
  };
  const label = labels[String(source || '').trim().toLowerCase()];
  return label ? t(label) : CLIENT_UNKNOWN_LABEL;
}

function clientPortModeLabel(mode) {
  const labels = {
    access: 'Access',
    'private-vlan-host': 'PVLAN Host',
    routed: 'Routed',
    dynamic: 'Dynamic',
    unknown: CLIENT_UNKNOWN_LABEL,
  };
  const normalized = String(mode || '').trim().toLowerCase();
  return labels[normalized] ? t(labels[normalized]) : (normalized ? String(mode) : CLIENT_UNKNOWN_LABEL);
}

function normalizeClientInventory(payload) {
  const envelope = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
  const rawDevices = Array.isArray(envelope.devices) ? envelope.devices : [];
  const validDevices = rawDevices.filter(device => device && typeof device === 'object');
  const portCounts = new Map();
  validDevices.forEach(device => {
    const key = String(device.interface || '').trim().toLowerCase();
    if (key) portCounts.set(key, (portCounts.get(key) || 0) + 1);
  });
  const devices = validDevices.map(device => {
    const portKey = String(device.interface || '').trim().toLowerCase();
    const derivedPortCount = portKey ? portCounts.get(portKey) : 1;
    return {
      ...device,
      classification: device.classification === 'infrastructure' ? 'infrastructure' : 'unknown',
      port_mac_count: Math.max(1, nonnegativeClientCount(device.port_mac_count, derivedPortCount)),
    };
  });

  const uniquePorts = new Set(
    devices.map(device => String(device.interface || '').trim().toLowerCase()).filter(Boolean)
  );
  const multiMacPorts = new Set(
    devices
      .filter(device => device.port_mac_count > 1 && hasValue(device.interface))
      .map(device => String(device.interface).trim().toLowerCase())
  );
  const derivedSummary = {
    raw_dynamic_entries: devices.length,
    local_devices: devices.length,
    local_ports: uniquePorts.size,
    with_ip: devices.filter(device => hasValue(device.ip)).length,
    with_name: devices.filter(device => hasValue(device.device_name)).length,
    infrastructure_devices: devices.filter(device => device.classification === 'infrastructure').length,
    unclassified_devices: devices.filter(device => device.classification !== 'infrastructure').length,
    without_ip: devices.filter(device => !hasValue(device.ip)).length,
    multi_mac_ports: multiMacPorts.size,
  };
  const rawSummary = envelope.summary && typeof envelope.summary === 'object' ? envelope.summary : {};
  const summary = Object.fromEntries(
    Object.entries(derivedSummary).map(([key, fallback]) => [key, nonnegativeClientCount(rawSummary[key], fallback)])
  );
  if (hasValue(rawSummary.raw_mac_entries)) {
    summary.raw_mac_entries = nonnegativeClientCount(rawSummary.raw_mac_entries, 0);
  }
  return {
    devices,
    summary,
    coverage: envelope.coverage && typeof envelope.coverage === 'object' ? envelope.coverage : {},
    warnings: Array.isArray(envelope.warnings) ? envelope.warnings : [],
    complete: envelope.complete !== false,
  };
}

function clientScalarValue(value) {
  if (!hasValue(value) || !['string', 'number', 'boolean'].includes(typeof value)) return '';
  return String(value).trim();
}

function clientCoverageArray(value) {
  const values = Array.isArray(value) ? value : (hasValue(value) ? [value] : []);
  return values.map(clientScalarValue).filter(Boolean);
}

function normalizeClientPortEntry(item) {
  if (['string', 'number'].includes(typeof item)) {
    const interfaceName = clientScalarValue(item);
    return interfaceName ? { interface: interfaceName, reason: '', state: '', mac: '', mac_type: '', vlan: '', mac_count: null, observed_vlans: [], allowed_vlans: [] } : null;
  }
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  const firstValue = values => values.map(clientScalarValue).find(Boolean) || '';
  const interfaceName = firstValue([item.interface, item.port, item.local_interface, item.name]);
  const reason = firstValue([item.reason, item.exclusion_reason, item.detail, item.message]);
  const state = firstValue([item.state, item.status, item.category]);
  const mac = firstValue([item.mac, item.mac_address]);
  const vlan = firstValue([item.vlan, item.observed_vlan]);
  if (!interfaceName && !reason && !state && !mac) return null;
  const rawMacCount = firstValue([item.mac_count, item.port_mac_count]);
  return {
    interface: interfaceName,
    reason,
    state,
    mac,
    mac_type: firstValue([item.mac_type, item.type]),
    vlan,
    mac_count: rawMacCount ? nonnegativeClientCount(rawMacCount, null) : null,
    observed_vlans: clientCoverageArray(item.observed_vlans ?? item.observed_vlan),
    allowed_vlans: clientCoverageArray(item.allowed_vlans ?? item.expected_vlans),
  };
}

function clientCoverageEntries(value) {
  if (Array.isArray(value)) return value.map(normalizeClientPortEntry).filter(Boolean);
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && !/^\s*\d+\s*$/.test(value)) {
      const entry = normalizeClientPortEntry(value);
      return entry ? [entry] : [];
    }
    return [];
  }
  const nestedEntries = [value.items, value.ports, value.entries, value.values]
    .find(candidate => Array.isArray(candidate));
  if (nestedEntries) return nestedEntries.map(normalizeClientPortEntry).filter(Boolean);
  const entry = normalizeClientPortEntry(value);
  return entry ? [entry] : [];
}

function clientCoverageValue(value, available = value !== undefined && value !== null) {
  const entries = clientCoverageEntries(value);
  const declaredCount = value && typeof value === 'object' && !Array.isArray(value)
    ? (value.count ?? value.total)
    : value;
  const count = Math.max(entries.length, nonnegativeClientCount(declaredCount, entries.length));
  return { available, count, entries };
}

function clientCoverageField(coverage, names) {
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(coverage, name)) {
      return { found: true, value: coverage[name] };
    }
  }
  return { found: false, value: undefined };
}

function normalizeClientPortMarker(value) {
  return clientScalarValue(value).toLowerCase().replace(/[\s-]+/g, '_');
}

function clientPortHasMarker(entry, markers) {
  return [entry.state, entry.reason]
    .map(normalizeClientPortMarker)
    .some(value => markers.includes(value));
}

function clientCoverageOrPortState(coverage, names, allPorts, markers) {
  const field = clientCoverageField(coverage, names);
  if (field.found) return clientCoverageValue(field.value);
  if (!allPorts.entries.length) return clientCoverageValue(undefined, false);
  const entries = allPorts.entries.filter(entry => clientPortHasMarker(entry, markers));
  return { available: true, count: entries.length, entries };
}

function clientPortReasonLabel(reason) {
  const rawReason = clientScalarValue(reason);
  const labels = {
    eligible: 'Lokaler Edge-Port',
    local_edge: 'Lokaler Edge-Port',
    with_mac: 'Aktuelle MAC erkannt',
    no_current_mac: 'Keine aktuell gelernte MAC',
    no_mac: 'Keine aktuell gelernte MAC',
    without_mac: 'Keine aktuell gelernte MAC',
    vlan_mismatch: 'MAC in unerwartetem VLAN',
    vlan_not_allowed: 'MAC in unerwartetem VLAN',
    switchport_details_unavailable: 'Switchport-Details nicht verfügbar',
    switchport_mode_unresolved: 'Switchport-Modus nicht eindeutig',
    unresolved: 'Portklassifikation nicht eindeutig',
    excluded: 'Von der Clienterkennung ausgeschlossen',
    trunk: 'Trunk oder Uplink',
    trunk_port: 'Trunk oder Uplink',
    trunk_or_uplink: 'Trunk oder Uplink',
    port_channel: 'Port-Channel',
    portchannel: 'Port-Channel',
    port_channel_member: 'Port-Channel',
    routed: 'Layer-3-Port',
    routed_port: 'Layer-3-Port',
    monitoring: 'Monitoring-Port',
    private_vlan_promiscuous: 'PVLAN-Promiscuous-Port',
    pvlan_promiscuous: 'PVLAN-Promiscuous-Port',
    unsupported_mode: 'Nicht unterstützter Portmodus',
    missing_switchport_data: 'Switchport-Daten fehlen',
    unverified: 'Keine aktuelle Zuordnung verifiziert',
    unverified_persistent_mac: 'Persistenter MAC-Eintrag nicht aktuell verifiziert',
    configured_static_mac: 'Konfigurierte statische MAC ohne aktuellen Nachweis',
    configured_secure_mac: 'Konfigurierte Port-Security-MAC ohne aktuellen Nachweis',
    system_mac: 'Switch- oder System-MAC, kein lokaler Client',
    unsupported_mac_type: 'MAC-Typ nicht als aktuelle Zuordnung nutzbar',
    non_unicast_mac: 'Keine Unicast-Client-MAC',
  };
  const label = labels[normalizeClientPortMarker(rawReason)];
  return label ? t(label) : (rawReason || CLIENT_UNKNOWN_LABEL);
}

function normalizeClientReasonCounts(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map(item => {
      if (!item || typeof item !== 'object') return null;
      const reason = clientScalarValue(item.reason ?? item.name ?? item.state);
      const count = nonnegativeClientCount(item.count ?? item.total, -1);
      return reason && count >= 0 ? { reason, count } : null;
    }).filter(Boolean);
  }
  if (typeof value !== 'object') return [];
  return Object.entries(value).map(([reason, rawCount]) => {
    const countValue = rawCount && typeof rawCount === 'object'
      ? (rawCount.count ?? rawCount.total)
      : rawCount;
    const count = nonnegativeClientCount(countValue, -1);
    return count >= 0 ? { reason, count } : null;
  }).filter(Boolean);
}

function renderClientPortEntry(entry) {
  const parts = [entry.interface || CLIENT_UNKNOWN_LABEL];
  if (entry.mac) parts.push(t('MAC {mac}', { mac: entry.mac }));
  if (entry.mac_type) parts.push(t('MAC-Typ {type}', { type: clientMacTypeLabel(entry.mac_type) }));
  if (entry.observed_vlans.length) {
    parts.push(t('beobachtet VLAN {vlans}', { vlans: entry.observed_vlans.join(', ') }));
  } else if (entry.vlan) {
    parts.push(t('VLAN {vlan}', { vlan: entry.vlan }));
  }
  if (entry.allowed_vlans.length) parts.push(t('erwartet {vlans}', { vlans: entry.allowed_vlans.join(', ') }));
  if (entry.mac_count !== null) parts.push(entry.mac_count === 1 ? t('{count} MAC', { count: entry.mac_count }) : t('{count} MACs', { count: entry.mac_count }));
  const reason = entry.reason || entry.state;
  if (reason) parts.push(clientPortReasonLabel(reason));
  return `<li>${parts.map(escapeHtml).join(' · ')}</li>`;
}

function renderClientPortDetails(title, coverageValue, description, tone = '') {
  if (!coverageValue.available || coverageValue.count === 0) return '';
  const className = tone ? `client-port-details ${tone}` : 'client-port-details';
  const explanation = `<p>${escapeHtml(description)}</p>`;
  if (!coverageValue.entries.length) {
    return `<div class="${className}"><strong>${escapeHtml(title)} (${escapeHtml(coverageValue.count)})</strong>
      ${explanation}<p>${escapeHtml(t('Die Portnamen wurden von dieser Firmware nicht geliefert.'))}</p></div>`;
  }
  return `<details class="${className}">
    <summary>${escapeHtml(title)} (${escapeHtml(coverageValue.count)})</summary>
    ${explanation}
    <ul class="client-port-list">${coverageValue.entries.map(renderClientPortEntry).join('')}</ul>
  </details>`;
}

function renderClientPortCoverage(inventory) {
  const coverage = inventory.coverage;
  const allPortsField = clientCoverageField(coverage, ['ports']);
  const allPorts = clientCoverageValue(allPortsField.value, allPortsField.found);
  const connectedField = clientCoverageField(coverage, ['connected_ports', 'link_up_ports']);
  const connected = connectedField.found
    ? clientCoverageValue(connectedField.value)
    : (allPorts.entries.length ? { available: true, count: allPorts.entries.length, entries: allPorts.entries } : clientCoverageValue(undefined, false));
  const candidateField = clientCoverageField(coverage, ['candidate_ports', 'connected_edge_ports', 'edge_ports']);
  const candidates = clientCoverageValue(candidateField.value, candidateField.found);
  const portsWithoutMac = clientCoverageOrPortState(
    coverage,
    ['ports_without_mac', 'connected_ports_without_mac', 'edge_ports_without_mac'],
    allPorts,
    ['no_current_mac', 'no_mac', 'without_mac']
  );
  const excluded = clientCoverageOrPortState(
    coverage,
    ['excluded_ports', 'excluded_connected_ports'],
    allPorts,
    ['excluded']
  );
  const unverifiedEntries = clientCoverageOrPortState(
    coverage,
    ['excluded_entries', 'unverified_entries'],
    allPorts,
    ['unverified', 'unverified_persistent_mac', 'unsupported_mac_type']
  );
  const unresolved = clientCoverageOrPortState(
    coverage,
    ['unresolved_ports', 'unclassified_ports'],
    allPorts,
    ['unresolved']
  );
  const vlanMismatches = clientCoverageOrPortState(
    coverage,
    ['vlan_mismatches', 'vlan_mismatch_ports'],
    allPorts,
    ['vlan_mismatch', 'vlan_not_allowed']
  );
  const reasonField = clientCoverageField(coverage, ['reason_counts', 'exclusion_reason_counts']);
  const reasonCounts = normalizeClientReasonCounts(reasonField.value);
  const coverageAvailable = [
    connected, candidates, portsWithoutMac, excluded, unverifiedEntries, unresolved, vlanMismatches, allPorts,
  ].some(value => value.available) || reasonField.found;
  if (!coverageAvailable) return '';

  const stats = [
    [connected, t('Physisch verbundene Ports')],
    [candidates, t('Lokale Edge-Kandidaten')],
    [{ available: true, count: inventory.summary.local_ports }, t('Ports mit verifizierter MAC-Zuordnung')],
    [portsWithoutMac, t('Edge-Ports ohne MAC')],
    [excluded, t('Ausgeschlossene Ports')],
    [unverifiedEntries, t('Nicht verifizierte MAC-Einträge')],
    [unresolved, t('Ungeklärte Ports')],
    [vlanMismatches, t('VLAN-Hinweise')],
  ].filter(([value]) => value.available)
    .map(([value, label]) => `<div class="client-coverage-stat"><strong>${escapeHtml(value.count)}</strong>${escapeHtml(label)}</div>`)
    .join('');
  const reasons = reasonCounts.length
    ? `<div class="client-reason-summary"><strong>${escapeHtml(t('Erkennungsgründe:'))}</strong>
        ${reasonCounts.map(item => `<span class="client-badge">${escapeHtml(clientPortReasonLabel(item.reason))}: ${escapeHtml(item.count)}</span>`).join('')}
      </div>`
    : '';

  return `<div class="client-port-coverage">
    <div class="client-port-coverage-title"><strong>${escapeHtml(t('Portbasierte Erkennungsabdeckung'))}</strong></div>
    <div class="client-coverage-grid">${stats}</div>
    ${renderClientPortDetails(
      t('Verbundene Edge-Ports ohne gelernte MAC'),
      portsWithoutMac,
      t('Der Link ist aktiv, aber der Switch hat aktuell keine passende MAC gelernt. Diese Ports werden nicht als Clients gezählt.'),
      'warning'
    )}
    ${renderClientPortDetails(
      t('Ausgeschlossene verbundene Ports'),
      excluded,
      t('Diese Ports sind keine lokalen Edge-Kandidaten, beispielsweise weil sie als Trunk, Port-Channel oder Layer-3-Port erkannt wurden.')
    )}
    ${renderClientPortDetails(
      t('Nicht als aktuell verifizierte MAC-Einträge'),
      unverifiedEntries,
      t('Diese MAC-Einträge sind zwar auf dem Switch vorhanden, belegen aber ohne dynamisches Lernen, eine autorisierte Zugriffssitzung oder einen weiteren aktuellen und portgenauen Nachweis keinen aktuell angeschlossenen Client.'),
      'warning'
    )}
    ${renderClientPortDetails(
      t('Nicht eindeutig klassifizierte Ports'),
      unresolved,
      t('Portmodus oder VLAN-Zuordnung konnten technisch nicht sicher interpretiert werden. Es werden daraus keine Clients abgeleitet.'),
      'warning'
    )}
    ${renderClientPortDetails(
      t('MACs mit abweichender VLAN-Zuordnung'),
      vlanMismatches,
      t('Die MAC wurde in einem VLAN gelernt, das nicht zur erkannten Portkonfiguration passt. Dieser Diagnosehinweis bedeutet für sich allein keinen ausgeschlossenen Client.'),
      'warning'
    )}
    ${reasons}
  </div>`;
}

function renderClientOverview(inventory) {
  const summary = inventory.summary;
  const overview = [
    [t('Lokale Geräte'), summary.local_devices],
    [t('Lokale Ports'), summary.local_ports],
    [t('Mit IP'), summary.with_ip],
    [t('Mit Namen'), summary.with_name],
    [t('Ohne IP'), summary.without_ip],
    [t('Mehrfach-MAC-Ports'), summary.multi_mac_ports],
  ].map(([label, value]) => `<span>${escapeHtml(label)}: <strong>${escapeHtml(value)}</strong></span>`).join('');
  let rawSummary = '';
  if (hasValue(summary.raw_mac_entries) && summary.raw_mac_entries !== summary.local_devices) {
    rawSummary = ` · ${t('{count} MAC-Einträge insgesamt', { count: summary.raw_mac_entries })}`;
  } else if (summary.raw_dynamic_entries !== summary.local_devices) {
    rawSummary = ` · ${t('{count} dynamische MAC-Einträge insgesamt', { count: summary.raw_dynamic_entries })}`;
  }
  const completeness = inventory.complete
    ? t('Technische Portauswertung vollständig')
    : t('Technische Portauswertung unvollständig');
  return `
    <div class="client-overview">${overview}</div>
    <div class="client-coverage">${escapeHtml(`${completeness}${rawSummary}`)}</div>
    ${renderClientPortCoverage(inventory)}
  `;
}

function renderClientSourceBadge(label, source) {
  return `<span class=client-badge>${escapeHtml(label)}: ${escapeHtml(clientSourceLabel(source))}</span>`;
}

function clientMacTypeLabel(macType) {
  const rawType = clientScalarValue(macType);
  const labels = {
    dynamic: 'Dynamisch',
    securedynamic: 'Secure Dynamic',
    dynamicsecure: 'Secure Dynamic',
    static: 'Statisch',
    sticky: 'Sticky',
    securesticky: 'Secure Sticky',
  };
  const normalized = rawType.toLowerCase().replace(/[^a-z0-9]/g, '');
  return labels[normalized] ? t(labels[normalized]) : rawType;
}

function clientAssociationLabel(value) {
  const rawValue = clientScalarValue(value);
  const labels = {
    mac_table_dynamic: 'Aktuelle MAC-Tabelle',
    verified_port_security: 'Verifizierte Port-Security',
    port_security_dynamic: 'Aktuelle Port-Security-Zuordnung',
    authenticated_session: 'Autorisierte Zugriffssitzung',
    authentication_session: 'Authentifizierungssitzung',
    mac_table: 'MAC-Tabelle',
    port_security: 'Port Security',
    arp: 'ARP',
    device_tracking: 'Device Tracking',
    dhcp_snooping: 'DHCP Snooping',
  };
  const label = labels[normalizeClientPortMarker(rawValue)];
  return label ? t(label) : rawValue;
}

function renderClientAssociationDetails(client) {
  const badges = [];
  const macType = clientMacTypeLabel(client.mac_type);
  if (macType) {
    badges.push(`<span class="client-badge">${escapeHtml(t('MAC-Typ: {type}', { type: macType }))}</span>`);
  }
  const associationSource = clientAssociationLabel(client.association_source);
  if (associationSource) {
    badges.push(`<span class="client-badge">${escapeHtml(t('Zuordnung: {source}', { source: associationSource }))}</span>`);
  }
  const evidence = clientCoverageArray(client.association_evidence)
    .map(clientAssociationLabel)
    .filter(Boolean);
  if (evidence.length) {
    badges.push(`<span class="client-badge">${escapeHtml(t('Nachweis: {evidence}', { evidence: evidence.join(' + ') }))}</span>`);
  }
  const vlanConsistency = normalizeClientPortMarker(client.vlan_consistency);
  const vlanConsistencyLabels = {
    verified: 'VLAN-Zuordnung geprüft',
    consistent: 'VLAN-Zuordnung geprüft',
    mismatch: 'VLAN-Zuordnung abweichend',
    unknown: 'VLAN-Zuordnung nicht prüfbar',
  };
  if (vlanConsistencyLabels[vlanConsistency]) {
    const badgeClass = vlanConsistency === 'mismatch' ? 'client-badge warning' : 'client-badge';
    badges.push(`<span class="${badgeClass}">${escapeHtml(t(vlanConsistencyLabels[vlanConsistency]))}</span>`);
  }
  const expectedVlans = clientCoverageArray(client.expected_vlans);
  if (vlanConsistency === 'mismatch' && expectedVlans.length) {
    badges.push(`<span class="client-badge warning">${escapeHtml(t('Erwartet: VLAN {vlans}', { vlans: expectedVlans.join(', ') }))}</span>`);
  }
  if (client.currently_learned === false || client.currently_learned === 'false') {
    badges.push(`<span class="client-badge warning">${escapeHtml(t('Nicht dynamisch gelernt · verifizierte persistente Zuordnung'))}</span>`);
  }
  return badges.length ? `<div class="client-cell-detail">${badges.join('')}</div>` : '';
}

function renderClientNeighbor(neighbor) {
  if (!neighbor || typeof neighbor !== 'object') return '';
  const protocol = hasValue(neighbor.protocol) ? String(neighbor.protocol).toUpperCase() : '';
  const identity = [neighbor.name, neighbor.platform].filter(hasValue).map(String);
  const description = [protocol, ...identity].filter(Boolean);
  const remotePort = hasValue(neighbor.remote_interface)
    ? ` · ${t('Remote-Port {port}', { port: String(neighbor.remote_interface) })}`
    : '';
  return description.length
    ? `<div class=client-cell-detail>${escapeHtml(description.join(' · '))}${escapeHtml(remotePort)}</div>`
    : '';
}

function fetchClientInventory(switchId) {
  return api(`/api/switches/${switchId}/client-inventory`);
}

function renderClientRow(client) {
  const infrastructure = client.classification === 'infrastructure';
  const name = hasValue(client.device_name) ? client.device_name : CLIENT_UNKNOWN_LABEL;
  const ip = hasValue(client.ip) ? client.ip : CLIENT_UNKNOWN_LABEL;
  const mac = hasValue(client.mac) ? client.mac : CLIENT_UNKNOWN_LABEL;
  const vlan = hasValue(client.vlan) ? client.vlan : CLIENT_UNKNOWN_LABEL;
  const port = hasValue(client.interface) ? client.interface : CLIENT_UNKNOWN_LABEL;
  const multiMac = client.port_mac_count > 1;
  const classificationLabel = infrastructure ? t('Infrastruktur erkannt') : t('Sonstige / unklassifiziert');
  const badgeClass = infrastructure ? 'client-badge infrastructure' : 'client-badge';
  const classificationBadge = `<span class="${badgeClass}">${escapeHtml(classificationLabel)}</span>`;
  const multiMacBadge = multiMac
    ? `<span class="client-badge warning">${escapeHtml(t('{count} MACs an diesem Port', { count: client.port_mac_count }))}</span>`
    : '';
  const nameSource = hasValue(client.device_name)
    ? renderClientSourceBadge(t('Namensquelle'), client.name_source)
    : `<span class="client-badge warning">${escapeHtml(hasValue(client.ip)
      ? t('Kein CDP-, LLDP- oder DNS-Name')
      : t('Ohne IP keine Namensauflösung'))}</span>`;
  const ipSource = hasValue(client.ip)
    ? renderClientSourceBadge(t('IP-Quelle'), client.ip_source)
    : `<span class="client-badge warning">${escapeHtml(t('Keine ARP-, Tracking- oder DHCP-Zuordnung'))}</span>`;
  const associationDetails = renderClientAssociationDetails(client);
  const neighbor = renderClientNeighbor(client.neighbor);
  const dataClassification = infrastructure ? 'infrastructure' : 'unknown';
  const dataHasIp = hasValue(client.ip) ? 'true' : 'false';
  return `<tr class="client-row" data-client-classification="${dataClassification}" data-client-has-ip="${dataHasIp}">
    <td>${escapeHtml(mac)}${associationDetails}</td>
    <td>${escapeHtml(name)}<div class="client-cell-detail">${nameSource}</div></td>
    <td>${escapeHtml(ip)}<div class="client-cell-detail">${ipSource}</div></td>
    <td>${escapeHtml(vlan)}</td>
    <td>${escapeHtml(port)}<div class="client-cell-detail">${escapeHtml(t('Modus: {mode}', { mode: clientPortModeLabel(client.port_mode) }))}</div>${multiMacBadge}</td>
    <td>${classificationBadge}${neighbor}</td>
  </tr>`;
}

async function loadClients(switchId) {
  const container = document.getElementById('clients-container');
  const requestSequence = ++clientInventoryRequestSequence;
  container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Clients …'))}</div>`;
  try {
    const payload = await fetchClientInventory(switchId);
    if (requestSequence !== clientInventoryRequestSequence
        || container !== document.getElementById('clients-container')) {
      return;
    }

    const inventory = normalizeClientInventory(payload);
    const warnings = inventory.warnings
      .map(warning => typeof warning === 'string' ? warning : inventoryWarningText(warning))
      .filter(hasValue);
    const warningBlock = warnings.length
      ? `<details class="search-warning"><summary>${escapeHtml(t('{count} Erkennungshinweis(e)', { count: warnings.length }))}</summary>
          <ul>${warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join('')}</ul>
        </details>`
      : '';
    const scopeHint = `
      <div class="client-coverage">
        ${escapeHtml(t('Angezeigt werden dynamisch gelernte oder durch eine autorisierte Zugriffssitzung beziehungsweise Port-Security verifizierte Zuordnungen auf sicher erkannten lokalen Access-, Voice- und PVLAN-Host-Ports. Uplinks, Trunks und Port-Channels sind ausgeschlossen.'))}
      </div>`;

    if (inventory.devices.length === 0) {
      container.innerHTML = `
        ${renderClientOverview(inventory)}
        ${warningBlock}
        ${scopeHint}
        <div class="empty-state">${escapeHtml(t('Keine aktiven, lokal angeschlossenen Clients gefunden.'))}</div>
      `;
      return;
    }

    const rows = inventory.devices.map(renderClientRow).join('');
    const filterDefinitions = [
      ['all', t('Alle'), inventory.summary.local_devices],
      ['infrastructure', t('Infrastruktur erkannt'), inventory.summary.infrastructure_devices],
      ['unknown', t('Sonstige / unklassifiziert'), inventory.summary.unclassified_devices],
      ['without-ip', t('Ohne IP'), inventory.summary.without_ip],
    ];
    const filterButtons = filterDefinitions.map(([value, label, count], index) => `
      <button type="button" class="client-filter-chip${index === 0 ? ' active' : ''}"
              data-client-filter="${escapeHtml(value)}" aria-pressed="${index === 0 ? 'true' : 'false'}">
        ${escapeHtml(label)} (${escapeHtml(count)})
      </button>
    `).join('');

    container.innerHTML = `
      ${renderClientOverview(inventory)}
      ${warningBlock}
      ${scopeHint}
      <div class="client-filter-bar" aria-label="${escapeHtml(t('Client-Ansicht filtern'))}">${filterButtons}</div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr><th>${escapeHtml(t('Mac Address'))}</th><th>${escapeHtml(t('Gerätename'))}</th><th>${escapeHtml(t('IP Address'))}</th><th>VLAN</th><th>${escapeHtml(t('Lokaler physischer Port'))}</th><th>${escapeHtml(t('Einordnung'))}</th></tr>
            <tr class="filter-row">
              <th><input class="table-filter" type="search" data-column="0" placeholder="${escapeHtml(t('MAC suchen'))}" aria-label="${escapeHtml(t('MAC-Adresse suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="1" placeholder="${escapeHtml(t('Gerätename suchen'))}" aria-label="${escapeHtml(t('Gerätename suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="2" placeholder="${escapeHtml(t('IP suchen'))}" aria-label="${escapeHtml(t('IP-Adresse suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="3" placeholder="${escapeHtml(t('VLAN suchen'))}" aria-label="${escapeHtml(t('VLAN suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="4" placeholder="${escapeHtml(t('Port suchen'))}" aria-label="${escapeHtml(t('Lokalen physischen Port suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="5" placeholder="${escapeHtml(t('Einordnung suchen'))}" aria-label="${escapeHtml(t('Einordnung suchen'))}"></th>
            </tr>
          </thead>
          <tbody>
            ${rows}
            <tr id="no-client-results" class="hidden"><td colspan="6" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden Clients gefunden.'))}</td></tr>
          </tbody>
        </table>
      </div>
    `;

    let activeClientFilter = 'all';
    const applyFilters = attachTableFilters(
      container,
      '.client-row',
      '#no-client-results',
      row => activeClientFilter === 'all'
        || (activeClientFilter === 'without-ip' && row.dataset.clientHasIp === 'false')
        || row.dataset.clientClassification === activeClientFilter
    );
    container.querySelectorAll('.client-filter-chip').forEach(button => {
      button.addEventListener('click', () => {
        activeClientFilter = button.dataset.clientFilter;
        container.querySelectorAll('.client-filter-chip').forEach(candidate => {
          const active = candidate === button;
          candidate.classList.toggle('active', active);
          candidate.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
        applyFilters();
      });
    });
  } catch (e) {
    if (requestSequence !== clientInventoryRequestSequence
        || container !== document.getElementById('clients-container')) {
      return;
    }
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  }
}

async function runSwitchAction(id, action, buttonId) {
  const key = `${id}:${action}`;
  if (pendingSwitchActions.has(key)) return;
  const sessionAtStart = currentSession;
  const operation = {};
  const button = document.getElementById(buttonId);
  pendingSwitchActions.set(key, operation);
  if (button) button.disabled = true;
  try {
    const result = await api(`/api/switches/${id}/${action}`, { method: 'POST' });
    if (currentSession === sessionAtStart) toast(result.message, !result.ok);
  } catch (e) {
    if (currentSession === sessionAtStart) toast(e.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) {
      pendingSwitchActions.delete(key);
      if (button?.isConnected) button.disabled = false;
    }
  }
}

async function testConnection(id) {
  if (!requireEditPermission()) return;
  return runSwitchAction(id, 'test-connection', 'btn-test-conn');
}

async function saveConfig(id) {
  if (!requireEditPermission()) return null;
  const key = `${id}:save-config`;
  if (pendingSwitchActions.has(key)) return null;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  const button = document.getElementById('btn-save-config');
  if (button) button.disabled = true;
  try {
    return await runSwitchChange(id, 'save-config', {}, { title: t('Konfiguration speichern') });
  } catch (e) {
    toast(e.message, true);
    return null;
  } finally {
    if (pendingSwitchActions.get(key) === operation) {
      pendingSwitchActions.delete(key);
      if (button?.isConnected) button.disabled = false;
    }
  }
}

// --- Änderungsvorschau (Vorschau → Anwenden) ------------------------------

// Jede Schreibänderung an einem Switch läuft über eine serverseitige Vorschau.
// Das Promise liefert das Apply-Ergebnis oder null (abgebrochen); Fehler der
// ersten Vorschau und unerwartete Apply-Fehler werden an den Aufrufer gereicht.
let changePreviewState = null;

function changePreviewIsCurrent(state) {
  return changePreviewState === state && currentSession === state.session;
}

// Ein Sitzungswechsel beendet die laufende Änderung ohne Ergebnis.
function changePreviewStillValid(state) {
  if (changePreviewState === state && currentSession !== state.session) closeChangePreview(state, null);
  return changePreviewIsCurrent(state);
}

function runSwitchChange(switchId, kind, params, { title, onApplied } = {}) {
  if (changePreviewState) closeChangePreview(changePreviewState, null);
  return new Promise((resolve, reject) => {
    const state = {
      switchId: Number(switchId), kind, params: params || {}, title: title || t('Änderung prüfen'), onApplied,
      resolve, reject, session: currentSession, preview: null, shown: false, busy: false,
      requestSequence: 0, rollbackMinutes: null, notice: '', error: '',
    };
    changePreviewState = state;
    requestChangePreview(state);
  });
}

async function requestChangePreview(state) {
  const sequence = ++state.requestSequence;
  state.busy = true;
  state.preview = null;
  state.error = '';
  if (state.shown) renderChangePreview(state);
  const body = { kind: state.kind, params: state.params };
  if (state.rollbackMinutes != null) body.rollback_minutes = state.rollbackMinutes;
  try {
    const preview = await api(`/api/switches/${state.switchId}/changes/preview`, {
      method: 'POST', body: JSON.stringify(body),
    });
    if (!changePreviewStillValid(state) || sequence !== state.requestSequence) return;
    state.preview = preview && typeof preview === 'object' ? preview : null;
    state.busy = false;
    if (!state.shown) {
      state.shown = true;
      document.getElementById('change-preview-risk-confirm').checked = false;
      document.getElementById('change-preview-rollback').checked = false;
      const defaultMinutes = Number(preview?.rollback?.default_minutes) || 5;
      document.getElementById('change-preview-rollback-minutes').value = String(defaultMinutes);
      setElementHidden('change-preview-modal', false);
    }
    renderChangePreview(state);
  } catch (error) {
    if (!changePreviewStillValid(state) || sequence !== state.requestSequence) return;
    state.busy = false;
    if (!state.shown) {
      changePreviewState = null;
      state.reject(error);
      return;
    }
    state.error = error.message;
    renderChangePreview(state);
  }
}

function changePreviewExpiryText(expiresAt) {
  const date = expiresAt ? new Date(expiresAt) : null;
  if (!date || Number.isNaN(date.getTime())) return '';
  return t('Vorschau gültig bis {time}.', { time: date.toLocaleTimeString(uiLocale()) });
}

function renderChangePreview(state) {
  const preview = state.preview;
  document.getElementById('change-preview-title').textContent = state.title;
  const lines = Array.isArray(preview?.lines) ? preview.lines : [];
  document.getElementById('change-preview-lines').textContent = state.busy
    ? t('Vorschau wird erstellt …')
    : (lines.length ? lines.join('\n') : t('Keine Befehle.'));
  const warnings = Array.isArray(preview?.warnings) ? preview.warnings : [];
  const warningList = document.getElementById('change-preview-warnings');
  warningList.innerHTML = warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join('');
  warningList.classList.toggle('hidden', warnings.length === 0);
  const risk = hasValue(preview?.risk) ? String(preview.risk) : '';
  document.getElementById('change-preview-risk-text').textContent = risk;
  setElementHidden('change-preview-risk', !risk);
  const rollback = preview?.rollback;
  const rollbackAvailable = rollback?.available === true;
  setElementHidden('change-preview-rollback-row', !rollbackAvailable && state.rollbackMinutes == null);
  const minutesInput = document.getElementById('change-preview-rollback-minutes');
  if (rollbackAvailable) {
    minutesInput.min = String(rollback.min ?? 1);
    minutesInput.max = String(rollback.max ?? 60);
  }
  const hints = [];
  if (preview?.persistent) hints.push(t('Diese Änderung wird sofort dauerhaft gespeichert.'));
  if (preview?.reloads) hints.push(t('Der Switch startet bei dieser Änderung neu.'));
  document.getElementById('change-preview-hint').textContent = hints.join(' ');
  setElementHidden('change-preview-hint', hints.length === 0);
  document.getElementById('change-preview-expiry').textContent = changePreviewExpiryText(preview?.expires_at);
  document.getElementById('change-preview-error').textContent = [state.notice, state.error].filter(Boolean).join(' ');
  updateChangePreviewControls(state);
}

function updateChangePreviewControls(state = changePreviewState) {
  const busy = !state || state.busy;
  const preview = state?.preview;
  const riskConfirmed = document.getElementById('change-preview-risk-confirm').checked;
  document.getElementById('change-preview-apply').disabled = busy || !preview
    || (hasValue(preview.risk) && !riskConfirmed);
  document.getElementById('change-preview-risk-confirm').disabled = busy || !preview;
  const rollbackAvailable = preview?.rollback?.available === true;
  document.getElementById('change-preview-rollback').disabled = busy || !rollbackAvailable;
  document.getElementById('change-preview-rollback-minutes').disabled = busy || !rollbackAvailable;
  document.getElementById('change-preview-cancel').disabled = Boolean(state?.applying);
}

function closeChangePreview(state, result) {
  if (changePreviewState !== state) return;
  changePreviewState = null;
  setElementHidden('change-preview-modal', true);
  state.resolve(result);
}

function cancelSwitchChange() {
  if (changePreviewState) closeChangePreview(changePreviewState, null);
}

function selectedRollbackMinutes() {
  if (!document.getElementById('change-preview-rollback').checked) return null;
  const value = Number(document.getElementById('change-preview-rollback-minutes').value);
  return Number.isInteger(value) ? Math.min(60, Math.max(1, value)) : 5;
}

function changeRollbackSelection() {
  const state = changePreviewState;
  if (!state || state.applying) return;
  const minutes = selectedRollbackMinutes();
  if (minutes === state.rollbackMinutes) return;
  state.rollbackMinutes = minutes;
  state.notice = '';
  document.getElementById('change-preview-risk-confirm').checked = false;
  requestChangePreview(state);
}

async function applySwitchChange() {
  const state = changePreviewState;
  if (!state || state.busy || !state.preview || !changePreviewIsCurrent(state)) return;
  const preview = state.preview;
  const confirmRisk = document.getElementById('change-preview-risk-confirm').checked;
  if (hasValue(preview.risk) && !confirmRisk) return;
  state.busy = true;
  state.applying = true;
  state.error = '';
  state.notice = '';
  updateChangePreviewControls(state);
  let result;
  try {
    result = await api(`/api/switches/${state.switchId}/changes/apply`, {
      method: 'POST', body: JSON.stringify({ preview_token: preview.preview_token, confirm_risk: confirmRisk }),
    });
  } catch (error) {
    if (!changePreviewStillValid(state)) return;
    state.busy = false;
    state.applying = false;
    if (error.status === 409 && ['preview_stale', 'preview_invalid'].includes(error.code)) {
      state.notice = error.message;
      document.getElementById('change-preview-risk-confirm').checked = false;
      requestChangePreview(state);
      return;
    }
    if (error.status === 409 && ['risk_confirmation_required', 'rollback_pending'].includes(error.code)) {
      state.error = error.message;
      renderChangePreview(state);
      if (error.code === 'rollback_pending') loadSwitchConfigStatus(state.switchId);
      return;
    }
    changePreviewState = null;
    setElementHidden('change-preview-modal', true);
    state.reject(error);
    return;
  }
  if (!changePreviewStillValid(state)) return;
  const warnings = Array.isArray(result?.warnings) ? result.warnings.filter(hasValue) : [];
  const message = [result?.message, ...warnings].filter(hasValue).join(' ');
  toast(message || (result?.ok ? t('Änderung angewendet.') : t('Die Änderung ist fehlgeschlagen.')), !result?.ok);
  closeChangePreview(state, result);
  loadSwitchConfigStatus(state.switchId);
  try {
    state.onApplied?.(result);
  } catch (error) {
    toast(error.message, true);
  }
}

document.getElementById('change-preview-cancel').addEventListener('click', cancelSwitchChange);
document.getElementById('change-preview-apply').addEventListener('click', applySwitchChange);
document.getElementById('change-preview-risk-confirm').addEventListener('change', () => updateChangePreviewControls());
document.getElementById('change-preview-rollback').addEventListener('change', changeRollbackSelection);
document.getElementById('change-preview-rollback-minutes').addEventListener('change', changeRollbackSelection);

registerSessionHooks({
  closePrivilegedModals: () => {
    if (changePreviewState && changePreviewState.session !== currentSession) cancelSwitchChange();
    if (configTextDialog && configTextDialog.session !== currentSession) closeConfigTextDialog();
  },
});

// Unified-Diff-Zeilen vom Server: {type: context|add|del|hunk, text}.
function renderConfigDiff(lines) {
  if (!Array.isArray(lines) || lines.length === 0) {
    return `<div class="empty-state">${escapeHtml(t('Keine Unterschiede.'))}</div>`;
  }
  const classes = { add: 'diff-add', del: 'diff-del', hunk: 'diff-hunk' };
  const body = lines.map(line => {
    const className = classes[line?.type];
    const text = escapeHtml(line?.text ?? '');
    return className ? `<span class="${className}">${text}</span>` : text;
  }).join('\n');
  return `<pre class="command-preview config-diff">${body}</pre>`;
}

// Lesedialog für Konfigurationstexte und Diffs (Backups, Gerätevergleich). Der Inhalt
// gehört zur Sitzung, die ihn geöffnet hat, und wird beim Sitzungswechsel verworfen.
let configTextDialog = null;

function showConfigTextDialog(title, html) {
  configTextDialog = { session: currentSession };
  document.getElementById('config-text-title').textContent = title;
  document.getElementById('config-text-body').innerHTML = html;
  setElementHidden('config-text-modal', false);
  return configTextDialog;
}

// Füllt den Dialog nur, solange er noch zu derselben Anfrage und Sitzung gehört.
function updateConfigTextDialog(dialog, html) {
  if (configTextDialog !== dialog || currentSession !== dialog.session) return false;
  document.getElementById('config-text-body').innerHTML = html;
  return true;
}

function closeConfigTextDialog() {
  configTextDialog = null;
  document.getElementById('config-text-body').innerHTML = '';
  setElementHidden('config-text-modal', true);
}

document.getElementById('config-text-close').addEventListener('click', closeConfigTextDialog);

function configTextLoading(text) {
  return `<div class="empty-state">${escapeHtml(text)}</div>`;
}

function configTextError(message) {
  return `<div class="empty-state" style="color: var(--danger)">${escapeHtml(message)}</div>`;
}

function renderDeviceCompare(device) {
  if (!device || typeof device !== 'object') return configTextError(t('Der Switch lieferte kein Vergleichsergebnis.'));
  if (device.differs !== true) {
    return `<p>${escapeHtml(t('Running- und Startup-Konfiguration sind gleich.'))}</p>`;
  }
  const summary = `<p>${escapeHtml(t('Die Running-Konfiguration enthält ungespeicherte Änderungen.'))}</p>`;
  if (!Array.isArray(device.diff)) {
    return `${summary}<p class="wlan-modal-help">${escapeHtml(t('Die Unterschiede sehen nur Administratoren.'))}</p>`;
  }
  return `${summary}<p class="wlan-modal-help">${escapeHtml(t('- nur in der Startup-Konfiguration, + nur in der Running-Konfiguration.'))}</p>`
    + renderConfigDiff(device.diff);
}

// Liest Running und Startup vom Gerät; der Server aktualisiert dabei den Speicherstand.
async function compareSwitchConfig(switchId) {
  const key = `${switchId}:config-compare`;
  if (pendingSwitchActions.has(key)) return;
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  const button = document.getElementById('btn-config-compare');
  if (button) button.disabled = true;
  const dialog = showConfigTextDialog(t('Running- und Startup-Konfiguration vergleichen'),
    configTextLoading(t('Konfigurationen werden vom Switch gelesen …')));
  try {
    const status = await api(`/api/switches/${switchId}/config-status?compare=1`);
    if (currentSession !== session) return;
    configStatusRequestSequence += 1;
    renderSwitchConfigStatus(switchId, status);
    updateConfigTextDialog(dialog, renderDeviceCompare(status?.device));
  } catch (error) {
    if (currentSession !== session) return;
    if (!updateConfigTextDialog(dialog, configTextError(error.message))) toast(error.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
    if (button?.isConnected) button.disabled = false;
  }
}

// --- Speicherstand und Rollback im Switch-Kopf ---------------------------

const configStatusLabels = {
  saved: () => t('Gespeichert'),
  dirty: () => t('Ungespeicherte Änderungen'),
  unknown: () => t('Unbekannt'),
  untracked: () => t('Nicht erfasst'),
};

function configStatusContainerFor(switchId) {
  const element = document.getElementById('switch-config-status');
  return element && element.dataset.switchId === String(switchId) ? element : null;
}

async function loadSwitchConfigStatus(switchId) {
  if (!configStatusContainerFor(switchId)) return;
  const session = currentSession;
  const sequence = ++configStatusRequestSequence;
  const isCurrent = () => sequence === configStatusRequestSequence && currentSession === session
    && Boolean(configStatusContainerFor(switchId));
  try {
    const status = await api(`/api/switches/${switchId}/config-status`);
    if (!isCurrent()) return;
    renderSwitchConfigStatus(switchId, status);
  } catch (error) {
    if (!isCurrent()) return;
    const badge = configStatusContainerFor(switchId);
    badge.className = 'config-status-badge status-unknown';
    badge.textContent = t('Speicherstand nicht verfügbar');
    badge.setAttribute('title', error.message);
  }
}

function rollbackRemainingText(expiresAt) {
  const remaining = new Date(expiresAt).getTime() - Date.now();
  if (!Number.isFinite(remaining)) return '';
  const minutes = Math.max(0, Math.ceil(remaining / 60000));
  return t('Automatisches Zurücksetzen in {minutes} min, falls nicht bestätigt.', { minutes });
}

function renderSwitchConfigStatus(switchId, status) {
  const badge = configStatusContainerFor(switchId);
  if (!badge) return;
  const appState = status?.app?.status;
  const label = configStatusLabels[appState] || configStatusLabels.unknown;
  badge.className = `config-status-badge config-status-${configStatusLabels[appState] ? appState : 'unknown'}`;
  badge.textContent = label();
  const details = [];
  if (status?.app?.last_change_at) {
    details.push(t('Letzte Änderung: {time} ({user})', { time: status.app.last_change_at, user: status.app.last_change_by || '—' }));
  }
  if (status?.app?.last_saved_at) details.push(t('Zuletzt gespeichert: {time}', { time: status.app.last_saved_at }));
  if (details.length) badge.setAttribute('title', details.join(' · '));
  else badge.removeAttribute('title');

  const banner = document.getElementById('switch-rollback-banner');
  if (!banner) return;
  const rollback = status?.rollback;
  if (!rollback || typeof rollback !== 'object') {
    banner.innerHTML = '';
    banner.classList.add('hidden');
    return;
  }
  const text = rollback.expired
    ? t('Ein automatisches Rollback ist abgelaufen; der Speicherstand ist unbekannt.')
    : rollbackRemainingText(rollback.expires_at);
  const actions = currentSessionCanEdit() && !rollback.expired ? `
      <button id="btn-rollback-confirm" class="primary">${escapeHtml(t('Änderung bestätigen'))}</button>
      <button id="btn-rollback-revert" class="danger">${escapeHtml(t('Jetzt zurücksetzen'))}</button>` : '';
  banner.innerHTML = `<div class="flex-row" style="justify-content: space-between;"><span>${escapeHtml(text)}</span><div class="flex-row">${actions}</div></div>`;
  banner.classList.remove('hidden');
  document.getElementById('btn-rollback-confirm')?.addEventListener('click', () => resolveSwitchRollback(switchId, 'confirm'));
  document.getElementById('btn-rollback-revert')?.addEventListener('click', () => resolveSwitchRollback(switchId, 'revert'));
}

async function resolveSwitchRollback(switchId, action) {
  if (!requireEditPermission()) return;
  const key = `${switchId}:rollback`;
  if (pendingSwitchActions.has(key)) return;
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  ['btn-rollback-confirm', 'btn-rollback-revert'].forEach(id => {
    const button = document.getElementById(id);
    if (button) button.disabled = true;
  });
  try {
    const result = await api(`/api/switches/${switchId}/rollback/${action}`, { method: 'POST' });
    if (currentSession === session) toast(result?.message || '', result?.ok === false);
  } catch (error) {
    if (currentSession === session) toast(error.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
    if (currentSession === session) await loadSwitchConfigStatus(switchId);
  }
}

function normalizeAdminState(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[_-]+/g, ' ');
  if (['enabled', 'no shutdown', 'administratively up'].includes(normalized)) return 'enabled';
  if (['disabled', 'shutdown', 'administratively down', 'admin down'].includes(normalized)) return 'disabled';
  return 'unknown';
}

function normalizeLinkState(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[_-]+/g, ' ');
  if (['up', 'connected', 'link up'].includes(normalized)) return 'up';
  if (['down', 'notconnect', 'not connected', 'link down'].includes(normalized)) return 'down';
  return 'unknown';
}

function interfaceValueText(value) {
  if (Array.isArray(value)) return value.join(', ');
  return String(value);
}

function renderInterfaceVlans(intf) {
  const fields = [
    ['Access', intf.access_vlan],
    ['Voice', intf.voice_vlan],
    ['Native', intf.native_vlan],
    ['Allowed', intf.trunk_allowed_vlan],
  ].filter(([, value]) => hasValue(value));

  if (fields.length === 0) {
    return hasValue(intf.vlan) ? escapeHtml(interfaceValueText(intf.vlan)) : '—';
  }
  return fields.map(([label, value], index) => {
    const className = index === 0 ? '' : ' class="interface-vlan-detail"';
    return `<div${className}><strong>${escapeHtml(t(label))}:</strong> ${escapeHtml(interfaceValueText(value))}</div>`;
  }).join('');
}

function formatPoeWatts(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? `${value.toLocaleString(uiLocale(), { maximumFractionDigits: 3 })} W` : escapeHtml(t('unbekannt'));
}

function renderInterfacePoe(intf, poeState = { supported: true }) {
  if (!poeState.supported) return `<span title="${escapeHtml(incompatibleTitle(poeState))}">${incompatibleBadge()}</span>`;
  if (intf.poe_supported === false) return `<span style="color: var(--text-dim);">${escapeHtml(t('Nicht unterstützt'))}</span>`;
  if (intf.poe_supported !== true) return `<span style="color: var(--text-dim);">${escapeHtml(t('Nicht verfügbar'))}</span>`;
  const details = [intf.poe_mode, intf.poe_status].filter(hasValue).map(escapeHtml).join(' · ');
  return `<div title="${escapeHtml(t('Verwendetes / maximales PoE-Budget laut Switch'))}">${formatPoeWatts(intf.poe_used_watts)} / ${formatPoeWatts(intf.poe_max_watts)}</div>`
    + (details ? `<div class="interface-state-detail">${details}</div>` : '');
}

function inventoryWarningText(warning) {
  if (typeof warning === 'string') return warning;
  if (!warning || typeof warning !== 'object') return String(warning || t('Unbekannter Hinweis'));
  return warning.message || warning.detail || warning.warning || JSON.stringify(warning);
}

function renderInventoryWarnings(warnings) {
  if (!Array.isArray(warnings) || warnings.length === 0) return '';
  const items = warnings.map(warning => `<li>${escapeHtml(inventoryWarningText(warning))}</li>`).join('');
  return `
    <details class="search-warning" open>
      <summary>${escapeHtml(warnings.length === 1 ? t('{count} Hinweis zur Erkennung', { count: warnings.length }) : t('{count} Hinweise zur Erkennung', { count: warnings.length }))}</summary>
      <ul>${items}</ul>
    </details>
  `;
}

function setInterfaceRefreshBusy(isBusy) {
  const button = document.getElementById('btn-refresh-interfaces');
  if (!button) return;
  button.disabled = isBusy;
  button.setAttribute('aria-busy', isBusy ? 'true' : 'false');
}

function setInterfaceActionControlsBusy(isBusy) {
  document.querySelectorAll('#interfaces-container .toggle-port-btn, #interfaces-container .port-action-btn').forEach(button => {
    button.disabled = isBusy || button.dataset.actionAvailable !== 'true';
  });
  document.querySelectorAll('#interfaces-container .edit-port-btn').forEach(button => {
    button.disabled = isBusy;
  });
  setInterfaceRefreshBusy(isBusy || interfaceInventoryActiveRequestSequence !== 0);
}

// Operator-Aktionen der Interface-Tabelle (Port-/PoE-Neustart, err-disabled-Recovery).
const PORT_ACTIONS = Object.freeze({
  'port-bounce': {
    feature: 'port_bounce', className: 'bounce-port-btn',
    label: () => t('Port neu starten'), title: port => t('Port {port} neu starten', { port }),
  },
  'poe-cycle': {
    feature: 'poe_cycle', className: 'poe-cycle-btn',
    label: () => t('PoE neu starten'), title: port => t('PoE an Port {port} neu starten', { port }),
  },
  'errdisable-recover': {
    feature: 'errdisable_recovery', className: 'errdisable-recover-btn',
    label: () => t('Reaktivieren'), title: port => t('Port {port} reaktivieren', { port }),
  },
});

function portActionKinds(intf) {
  const kinds = ['port-bounce'];
  if (intf.poe_supported === true) kinds.push('poe-cycle');
  if (hasValue(intf.errdisabled_reason)) kinds.push('errdisable-recover');
  return kinds;
}

function renderPortActionButtons(sw, intf) {
  return portActionKinds(intf).map(kind => {
    const action = PORT_ACTIONS[kind];
    const state = featureState(sw, action.feature);
    const classes = ['port-action-btn', action.className, state.supported ? '' : 'is-incompatible'].filter(Boolean).join(' ');
    const marking = state.supported ? '' : ` title="${escapeHtml(incompatibleTitle(state))}" aria-disabled="true"`;
    const disabled = !state.supported || interfaceMutationInProgress ? ' disabled' : '';
    return `<button class="${classes}" data-port="${escapeHtml(intf.port)}" data-kind="${kind}" data-action-available="${state.supported}"${marking}${disabled}>`
      + `${escapeHtml(action.label())}${state.supported ? '' : incompatibleBadge()}</button>`;
  }).join('');
}

function interfaceStatusText(intf) {
  if (hasValue(intf.errdisabled_reason)) {
    return t('err-disabled ({reason})', { reason: interfaceValueText(intf.errdisabled_reason) });
  }
  return hasValue(intf.status) ? interfaceValueText(intf.status) : 'unknown';
}

async function runPortAction(switchId, port, kind) {
  const action = PORT_ACTIONS[kind];
  if (!action || !requireOperatePermission() || interfaceMutationInProgress) return null;
  const sessionAtStart = currentSession;
  const mutationSequence = ++interfaceMutationSequence;
  interfaceMutationInProgress = true;
  setInterfaceActionControlsBusy(true);
  try {
    let result;
    try {
      result = await runSwitchChange(switchId, kind, { interface: port }, { title: action.title(port) });
    } catch (error) {
      if (currentSession === sessionAtStart) toast(error.message, true);
      return null;
    }
    if (currentSession !== sessionAtStart || !result) return result;
    await refreshInterfaceInventoryAfterMutation(switchId);
    return result;
  } finally {
    if (mutationSequence === interfaceMutationSequence) {
      interfaceMutationInProgress = false;
      setInterfaceActionControlsBusy(false);
    }
  }
}

async function loadInterfaces(id, options = {}) {
  const container = document.getElementById('interfaces-container');
  if (!container) return null;

  const requestSequence = ++interfaceInventoryRequestSequence;
  interfaceInventoryActiveRequestSequence = requestSequence;
  const showLoading = options.showLoading !== false;
  const keepRefreshDisabled = options.keepRefreshDisabled === true;
  const preserveOnError = options.preserveOnError === true;
  const rethrowOnError = options.rethrowOnError === true;
  if (showLoading) {
    interfaceRenderState.delete(container);
    container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Interfaces …'))}</div>`;
  }
  setInterfaceRefreshBusy(true);

  try {
    const inventory = await api(`/api/switches/${id}/interface-inventory`);
    const isCurrentRequest = requestSequence === interfaceInventoryRequestSequence
      && currentSwitchId === id
      && document.getElementById('interfaces-container') === container;
    if (!isCurrentRequest) return null;
    if (!inventory || !Array.isArray(inventory.interfaces) || !Array.isArray(inventory.vlans)) {
      throw new Error(t('Der Switch lieferte kein gültiges Interface-Inventar.'));
    }

    const canEdit = canOperateSwitches();
    const sw = switchById(id);
    const portState = featureState(sw, 'port_state');
    const poeState = featureState(sw, 'poe');
    const renderSignature = JSON.stringify([inventory, canEdit, sw?.capabilities ?? null]);
    const previousRender = interfaceRenderState.get(container);
    if (previousRender?.session === currentSession && previousRender.signature === renderSignature) {
      // Jede Pollingprobe bleibt eine frische Abfrage. Unveränderte Daten
      // benötigen jedoch kein neues Tabellen-DOM und behalten aktive Filter.
      setInterfaceActionControlsBusy(interfaceMutationInProgress);
      return inventory;
    }
    const filterValues = new Map([...container.querySelectorAll('.table-filter')]
      .map(input => [input.dataset.column, input.value]));
    const interfaces = inventory.interfaces;
    const vlans = inventory.vlans;
    const warnings = renderInventoryWarnings(inventory.warnings);
    if (interfaces.length === 0) {
      container.innerHTML = `${warnings}<div class="empty-state">${escapeHtml(t('Keine Interfaces gefunden.'))}</div>`;
      interfaceRenderState.set(container, { session: currentSession, signature: renderSignature });
      return inventory;
    }

    const rows = interfaces.map(intf => {
      const adminState = normalizeAdminState(intf.admin_state);
      const linkState = normalizeLinkState(intf.link_state);
      const adminLabel = escapeHtml(adminState === 'enabled' ? t('Aktiv') : adminState === 'disabled' ? t('Shutdown') : t('Unbekannt'));
      const linkLabel = linkState === 'up' ? 'up' : linkState === 'down' ? 'down' : t('unbekannt');
      const rawStatus = interfaceStatusText(intf);
      const statusTone = hasValue(intf.errdisabled_reason) ? 'err-disabled' : statusClass(rawStatus);
      const adminMode = intf.switchport_enabled === false
        ? (intf.mode || intf.administrative_mode)
        : (intf.administrative_mode || intf.mode);
      const adminDetails = [
        hasValue(adminMode) ? escapeHtml(t('Modus: {mode}', { mode: interfaceValueText(adminMode) })) : '',
        intf.switchport_enabled === false ? escapeHtml(t('Switchport: aus')) : '',
      ].filter(Boolean).join(' · ');
      const operationDetails = [
        escapeHtml(t('Link: {state}', { state: linkLabel })),
        hasValue(intf.operational_mode) ? escapeHtml(t('Modus: {mode}', { mode: interfaceValueText(intf.operational_mode) })) : '',
      ].filter(Boolean).join(' · ');
      const stateKnown = adminState !== 'unknown';
      const canToggle = stateKnown && portState.supported;
      const enable = adminState === 'disabled';
      const toggleLabel = escapeHtml(stateKnown ? (enable ? t('Einschalten') : t('Ausschalten')) : t('Status unbekannt'));
      const toggleTitle = !portState.supported ? incompatibleTitle(portState)
        : stateKnown ? '' : t('Administrativer Zustand konnte nicht sicher erkannt werden');
      const toggleDisabled = !canToggle || interfaceMutationInProgress;
      const toggleClasses = ['toggle-port-btn', adminState === 'enabled' && portState.supported ? 'danger' : '',
        portState.supported ? '' : 'is-incompatible'].filter(Boolean).join(' ');
      const actionCell = canEdit ? `
          <td class="table-actions"><div class="table-actions-inner">
            <button class="${toggleClasses}" data-port="${escapeHtml(intf.port)}" data-enable="${enable}" data-action-available="${canToggle}" title="${escapeHtml(toggleTitle)}" ${toggleDisabled ? 'disabled' : ''}${portState.supported ? '' : ' aria-disabled="true"'}>
              ${toggleLabel}${portState.supported ? '' : incompatibleBadge()}
            </button>
            <button class="edit-port-btn" data-port="${escapeHtml(intf.port)}" ${interfaceMutationInProgress ? 'disabled' : ''}>${escapeHtml(t('Bearbeiten'))}</button>
            ${renderPortActionButtons(sw, intf)}
          </div></td>
      ` : `
          <td style="text-align: right;">
            <button class="view-port-btn" data-port="${escapeHtml(intf.port)}">${escapeHtml(t('Details'))}</button>
          </td>
      `;
      return `
        <tr class="interface-row">
          <td>${escapeHtml(intf.port)}</td>
          <td>${escapeHtml(intf.description || '—')}</td>
          <td class="status-${adminState === 'enabled' ? 'connected' : adminState === 'disabled' ? 'disabled' : 'unknown'}">
            ${adminLabel}
            ${adminDetails ? `<div class="interface-state-detail">${adminDetails}</div>` : ''}
          </td>
          <td class="status-${statusTone}">
            ${escapeHtml(rawStatus)}
            <div class="interface-state-detail">${operationDetails}</div>
          </td>
          <td>${renderInterfaceVlans(intf)}</td>
          <td>${renderInterfacePoe(intf, poeState)}</td>
          ${actionCell}
        </tr>
      `;
    }).join('');

    container.innerHTML = `
      ${warnings}
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr><th>${escapeHtml(t('Port'))}</th><th>${escapeHtml(t('Beschreibung'))}</th><th>${escapeHtml(t('Admin'))}</th><th>${escapeHtml(t('Status / Link'))}</th><th>VLANs</th><th>${escapeHtml(t('PoE genutzt / max.'))}</th><th></th></tr>
            <tr class="filter-row">
              <th><input class="table-filter" type="search" data-column="0" placeholder="${escapeHtml(t('Port suchen'))}" aria-label="${escapeHtml(t('Port suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="1" placeholder="${escapeHtml(t('Beschreibung suchen'))}" aria-label="${escapeHtml(t('Beschreibung suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="2" placeholder="${escapeHtml(t('Adminstatus suchen'))}" aria-label="${escapeHtml(t('Administrativen Status suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="3" placeholder="${escapeHtml(t('Status suchen'))}" aria-label="${escapeHtml(t('Verbindungsstatus suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="4" placeholder="${escapeHtml(t('VLAN suchen'))}" aria-label="${escapeHtml(t('VLAN suchen'))}"></th>
              <th><input class="table-filter" type="search" data-column="5" placeholder="${escapeHtml(t('PoE suchen'))}" aria-label="${escapeHtml(t('PoE-Budget und Modus suchen'))}"></th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${rows}
            <tr id="no-interface-results" class="hidden"><td colspan="7" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden Interfaces gefunden.'))}</td></tr>
          </tbody>
        </table>
      </div>
    `;
    container.querySelectorAll('.table-filter').forEach(input => {
      input.value = filterValues.get(input.dataset.column) || '';
    });
    const applyFilters = attachTableFilters(container, '.interface-row', '#no-interface-results');
    if ([...filterValues.values()].some(value => value.trim())) applyFilters();
    container.querySelectorAll('.toggle-port-btn').forEach(btn => {
      btn.addEventListener('click', () => togglePort(id, btn.dataset.port, btn.dataset.enable === 'true'));
    });
    container.querySelectorAll('.edit-port-btn').forEach(btn => {
      btn.addEventListener('click', () => openInterfaceModal(id, btn.dataset.port, vlans));
    });
    container.querySelectorAll('.port-action-btn').forEach(btn => {
      btn.addEventListener('click', () => runPortAction(id, btn.dataset.port, btn.dataset.kind));
    });
    container.querySelectorAll('.view-port-btn').forEach(btn => {
      btn.addEventListener('click', () => openInterfaceModal(id, btn.dataset.port, vlans));
    });
    interfaceRenderState.set(container, { session: currentSession, signature: renderSignature });
    return inventory;
  } catch (e) {
    const isCurrentRequest = requestSequence === interfaceInventoryRequestSequence
      && currentSwitchId === id
      && document.getElementById('interfaces-container') === container;
    if (isCurrentRequest) {
      if (!preserveOnError || !container.querySelector('table')) {
        interfaceRenderState.delete(container);
        container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
      }
      if (rethrowOnError) throw e;
    }
    return null;
  } finally {
    if (interfaceInventoryActiveRequestSequence === requestSequence) {
      interfaceInventoryActiveRequestSequence = 0;
    }
    if (requestSequence === interfaceInventoryRequestSequence) {
      setInterfaceRefreshBusy(keepRefreshDisabled || interfaceMutationInProgress);
    }
  }
}

function interfacePollSignature(intf) {
  return JSON.stringify([
    normalizeAdminState(intf.admin_state),
    normalizeLinkState(intf.link_state),
    intf.admin_state,
    intf.link_state,
    intf.status,
    intf.vlan,
    intf.mode,
    intf.administrative_mode,
    intf.operational_mode,
    intf.switchport_enabled,
    intf.access_vlan,
    intf.voice_vlan,
    intf.native_vlan,
    intf.trunk_allowed_vlan,
    intf.poe_mode,
    intf.poe_max_watts,
    intf.poe_configured_max_watts,
  ].map(value => interfaceValueText(value ?? '')));
}

function normalizedPollTargetValue(value) {
  return interfaceValueText(value ?? '').trim().toLowerCase().replace(/\s+/g, '');
}

function interfaceMatchesConfigTarget(intf, target) {
  if (!target) return true;
  if (target.admin_state && normalizeAdminState(intf.admin_state) !== target.admin_state) return false;
  if (target.mode) {
    const structuredMode = ['switchport_enabled', 'administrative_mode', 'operational_mode']
      .some(key => Object.prototype.hasOwnProperty.call(intf, key));
    const actualMode = structuredMode
      ? (intf.switchport_enabled === true ? configurableInterfaceMode(intf.administrative_mode) : null)
      : configurableInterfaceMode(intf.mode);
    if (actualMode !== target.mode) return false;
  }
  for (const field of ['access_vlan', 'native_vlan']) {
    if (target[field] !== null && target[field] !== undefined
        && normalizedPollTargetValue(intf[field]) !== normalizedPollTargetValue(target[field])) {
      return false;
    }
  }
  if (Number.isInteger(target.voice_vlan)) {
    const actual = hasValue(intf.voice_vlan) ? normalizedPollTargetValue(intf.voice_vlan) : '';
    if (target.voice_vlan === 0 ? !['', 'none'].includes(actual) : actual !== String(target.voice_vlan)) return false;
  }
  if (target.trunk_allowed_vlan != null) {
    const actual = allowedVlanSignature(intf.trunk_allowed_vlan);
    if (actual === null || actual !== allowedVlanSignature(target.trunk_allowed_vlan)) return false;
  }
  if (target.poe_mode !== undefined && intf.poe_mode !== target.poe_mode) return false;
  // Ein aktives Budget beweist nicht, dass das konfigurierte Limit entfernt wurde.
  if (target.poe_standard === 'default'
      && (!Object.prototype.hasOwnProperty.call(intf, 'poe_configured_max_watts')
          || intf.poe_configured_max_watts !== null)) return false;
  if (target.poe_max_watts > 0 && (typeof intf.poe_max_watts !== 'number'
      || !Number.isFinite(intf.poe_max_watts)
      || Math.abs(intf.poe_max_watts - target.poe_max_watts) > 0.051)) return false;
  return true;
}

async function refreshInterfaceInventoryAfterMutation(switchId) {
  if (currentSwitchId !== switchId || !document.getElementById('interfaces-container')) return;
  try {
    await loadInterfaces(switchId, {
      showLoading: false,
      keepRefreshDisabled: true,
      preserveOnError: true,
      rethrowOnError: true,
    });
  } catch (refreshError) {
    toast(t('Status konnte nach dem Fehler nicht aktualisiert werden: {message}', { message: refreshError.message }), true);
  }
}

async function pollInterfaceInventory(switchId, port, options = {}) {
  const expectedAdminState = options.expectedAdminState || null;
  const configTarget = options.configTarget || null;
  const pollSequence = ++interfaceInventoryPollSequence;
  let previousSignature = null;
  let stableReadCount = 0;
  let targetConfirmed = false;
  let pollError = null;
  let poeConfiguration = null;
  setInterfaceRefreshBusy(true);

  try {
    if (configTarget?.poe_standard === 'default') {
      try {
        // Die Inventarliste enthält nur das aktuelle Budget, nicht das konfigurierte Limit.
        const detail = await api(`/api/switches/${switchId}/interface-detail?interface=${encodeURIComponent(port)}`);
        if (detail.poe_supported === true && Object.prototype.hasOwnProperty.call(detail, 'poe_configured_max_watts')) {
          poeConfiguration = { poe_configured_max_watts: detail.poe_configured_max_watts };
        }
      } catch {
        // Fehlendes Rücklesen darf das entfernte Limit nicht als bestätigt darstellen.
      }
    }
    await waitFor(async () => {
      if (pollSequence !== interfaceInventoryPollSequence || currentSwitchId !== switchId) return true;
      let inventory;
      try {
        inventory = await loadInterfaces(switchId, {
          showLoading: false,
          keepRefreshDisabled: true,
          preserveOnError: true,
          rethrowOnError: true,
        });
      } catch (error) {
        pollError = error;
        return true;
      }
      if (!inventory || pollSequence !== interfaceInventoryPollSequence) return true;

      const intf = inventory.interfaces.find(item => String(item.port) === String(port));
      if (!intf) return true;
      const verificationInterface = poeConfiguration ? { ...intf, ...poeConfiguration } : intf;
      const signature = interfacePollSignature(verificationInterface);
      stableReadCount = signature === previousSignature ? stableReadCount + 1 : 1;
      previousSignature = signature;

      const adminState = normalizeAdminState(intf.admin_state);
      const linkState = normalizeLinkState(intf.link_state);
      const expectedReached = !expectedAdminState || adminState === expectedAdminState;
      if (configTarget) {
        // Konfiguration erst nach zwei identischen, vollständigen Ziel-Reads bestätigen.
        targetConfirmed = interfaceMatchesConfigTarget(verificationInterface, configTarget) && stableReadCount >= 2;
        return targetConfirmed;
      }
      const disabledReached = expectedAdminState === 'disabled' && expectedReached;
      const enabledAndLinked = expectedAdminState === 'enabled' && expectedReached && linkState === 'up';
      const stableReached = expectedReached && stableReadCount >= (expectedAdminState === 'enabled' ? 3 : 2);
      if (!disabledReached && !enabledAndLinked && !stableReached) return false;
      targetConfirmed = expectedReached;
      return true;
    }, { attempts: 5, intervalMs: 1200 });
  } finally {
    if (pollSequence === interfaceInventoryPollSequence) {
      setInterfaceRefreshBusy(interfaceMutationInProgress);
    }
  }

  const stillCurrent = pollSequence === interfaceInventoryPollSequence && currentSwitchId === switchId;
  if (stillCurrent && pollError) {
    toast(t('Die Statusaktualisierung wurde unterbrochen: {message}', { message: pollError.message }), true);
  } else if (stillCurrent && configTarget && !targetConfirmed) {
    toast(t('Die neue Konfiguration von {port} konnte noch nicht vollständig bestätigt werden.', { port }), true);
  } else if (stillCurrent && expectedAdminState && !targetConfirmed) {
    toast(t('Der administrative Zustand von {port} konnte noch nicht bestätigt werden.', { port }), true);
  }
  return { targetConfirmed, error: pollError };
}

function canOperateSwitches() {
  return currentSessionCanEdit() || currentSessionCanOperate();
}

function requireOperatePermission() {
  if (canOperateSwitches()) return true;
  toast(t('Nur Operatoren und Administratoren dürfen diese Aktion ausführen.'), true);
  return false;
}

async function togglePort(switchId, port, enable) {
  if (!requireOperatePermission()) return;
  if (interfaceMutationInProgress) return;

  const sessionAtStart = currentSession;
  const mutationSequence = ++interfaceMutationSequence;
  interfaceMutationInProgress = true;
  setInterfaceActionControlsBusy(true);
  try {
    let result;
    try {
      result = await runSwitchChange(switchId, 'port-state', { interface: port, enabled: enable }, {
        title: enable ? t('Port {port} einschalten', { port }) : t('Port {port} ausschalten', { port }),
      });
    } catch (mutationError) {
      if (currentSession !== sessionAtStart) return;
      toast(mutationError.message, true);
      await refreshInterfaceInventoryAfterMutation(switchId);
      return;
    }
    if (currentSession !== sessionAtStart || !result) return;
    if (!result.ok) {
      await refreshInterfaceInventoryAfterMutation(switchId);
      return;
    }
    await pollInterfaceInventory(switchId, port, {
      expectedAdminState: enable ? 'enabled' : 'disabled',
    });
  } finally {
    if (mutationSequence === interfaceMutationSequence) {
      interfaceMutationInProgress = false;
      setInterfaceActionControlsBusy(false);
    }
  }
}

async function deleteSwitch(id) {
  if (!requireEditPermission()) return;
  if (!confirm(t('Diesen Switch wirklich aus dem Inventar entfernen?'))) return;
  const sessionAtStart = currentSession;
  try {
    await api(`/api/switches/${id}`, { method: 'DELETE' });
    if (currentSession !== sessionAtStart) return;
    if (currentSwitchId === Number(id)) {
      currentSwitchId = null;
      switchSelectionSequence += 1;
      cancelInterfaceInventoryWork();
      if (isWorkspaceActive('switches')) {
        document.getElementById('main-content').innerHTML = `<div class="empty-state">${escapeHtml(t('Wähle links einen Switch aus, oder füge einen neuen hinzu.'))}</div>`;
      }
    }
    await loadSwitches();
  } catch (error) {
    if (currentSession !== sessionAtStart) return;
    toast(error.message, true);
  }
}

// --- Interface-Modal (Administrative Mode, VLANs, PortFast, Speed/Duplex) ---

let intfModalState = {
  session: null,
  switchId: null,
  port: null,
  detailLoaded: false,
  saving: false,
  unsupportedMode: null,
  modeExplicitlySelected: false,
  preserveUnknownSpeed: false,
  preserveUnknownDuplex: false,
  sw: null,
  overrides: {},
  portOptions: {},
};
let interfaceModalSequence = 0;
let copiedInterfaceSettings = null;

// port-configure params field -> capability feature id.
const interfaceConfigFeatures = Object.freeze({
  description: 'port_description',
  mode: 'port_mode',
  access_vlan: 'access_vlan',
  native_vlan: 'native_vlan',
  trunk_allowed_vlan: 'trunk_allowed_vlans',
  edge_port: 'edge_port',
  speed: 'speed',
  duplex: 'duplex',
  shutdown: 'port_state',
  poe_mode: 'poe_mode',
  poe_standard: 'poe_limit',
  voice_vlan: 'voice_vlan',
});

// Port-Dialog-Felder, die Operatoren an Access-Ports ändern dürfen (Server prüft dasselbe).
const OPERATOR_PORT_FIELDS = new Set(['description', 'access_vlan', 'voice_vlan', 'shutdown', 'poe_mode', 'poe_standard', 'speed', 'duplex']);
const OPERATOR_PORT_CONTROLS = new Set(['intf-description', 'intf-access-vlan', 'intf-voice-vlan', 'intf-shutdown']);

// Modal control -> capability feature id.
const interfaceControlFeatures = Object.freeze({
  'intf-description': 'port_description',
  'intf-mode': 'port_mode',
  'intf-access-vlan': 'access_vlan',
  'intf-native-vlan': 'native_vlan',
  'intf-trunk-allowed': 'trunk_allowed_vlans',
  'intf-portfast': 'edge_port',
  'intf-shutdown': 'port_state',
  'intf-voice-vlan': 'voice_vlan',
});

function interfaceConfigLabel(field) {
  const labels = {
    description: t('Beschreibung'),
    mode: t('Modus'),
    access_vlan: t('Access VLAN'),
    native_vlan: t('Native VLAN'),
    trunk_allowed_vlan: t('Allowed VLANs'),
    edge_port: t('PortFast / Edge-Port'),
    speed: t('Speed'),
    duplex: t('Duplex'),
    shutdown: t('Administrativer Portstatus'),
    poe_mode: t('PoE-Modus'),
    poe_standard: t('PoE-Standard'),
    voice_vlan: t('Voice-VLAN'),
  };
  return labels[field] || field;
}

function interfaceFeature(id) {
  return featureState(intfModalState.sw, id, intfModalState.overrides);
}

function interfaceConfigSupported(field) {
  return interfaceFeature(interfaceConfigFeatures[field]).supported;
}

// Speed and duplex are sent together when either capability declares the other in `requires`.
function interfaceTunablesCoupled() {
  return interfaceFeature('speed').requires.includes('duplex') || interfaceFeature('duplex').requires.includes('speed');
}

// Marks select options outside `allowed` as incompatible; null allows every option.
function markIncompatibleOptions(select, allowed) {
  Array.from(select.options).forEach(option => {
    if (!option.value || option.dataset.preservedValue !== undefined) return;
    if (option.dataset.label === undefined) option.dataset.label = option.textContent;
    const incompatible = Array.isArray(allowed) && !allowed.includes(option.value);
    option.disabled = incompatible;
    option.textContent = incompatible ? `${option.dataset.label} ${t('(inkompatibel)')}` : option.dataset.label;
  });
}

function normalizeAllowedVlans(value) {
  const raw = String(value ?? '');
  const invalid = () => new Error(t('Allowed VLANs: Bitte IDs von 1 bis 4094, Bereiche (z. B. 10,20,30-40), all oder none eingeben.'));
  if (raw.length > 24576 || /[\x00-\x1f\x7f]/.test(raw)) throw invalid();
  const normalized = raw.trim().toLowerCase().replace(/ *, */g, ',').replace(/ *- */g, '-');
  if (!normalized) return null;
  if (['all', 'none'].includes(normalized)) return normalized;
  if (!/^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$/.test(normalized)) throw invalid();
  return normalized.split(',').map(item => {
    const bounds = item.split('-').map(Number);
    if (bounds.some(bound => !Number.isInteger(bound) || bound < 1 || bound > 4094)
        || (bounds.length === 2 && bounds[0] > bounds[1])) throw invalid();
    return bounds.join('-');
  }).join(',');
}

function allowedVlanSignature(value) {
  try {
    const normalized = normalizeAllowedVlans(value);
    if (normalized === null) return null;
    if (normalized === 'none') return '';
    const members = new Set();
    for (const item of (normalized === 'all' ? '1-4094' : normalized).split(',')) {
      const [first, last = first] = item.split('-').map(Number);
      for (let vlan = first; vlan <= last; vlan += 1) members.add(vlan);
    }
    return [...members].sort((a, b) => a - b).join(',');
  } catch {
    return null;
  }
}

// Gemeinsamer Formularvertrag für Kopieren und Übernehmen. Port und Switch
// gehören ausschließlich zum Ziel und werden nie aus der Vorlage übernommen.
function readInterfaceSettings({ includeUnchangedPoE = false } = {}) {
  if (!intfModalState.detailLoaded || intfModalState.session !== currentSession) {
    throw new Error(t('Die aktuellen Portwerte müssen zuerst erfolgreich geladen werden.'));
  }
  const mode = document.getElementById('intf-mode').value;
  const modeSupported = interfaceConfigSupported('mode');
  if (modeSupported && (!['access', 'trunk'].includes(mode)
      || (intfModalState.unsupportedMode && !intfModalState.modeExplicitlySelected))) {
    throw new Error(t('Bitte Static Access oder Trunk ausdrücklich auswählen.'));
  }
  const shutdown = document.getElementById('intf-shutdown').value;
  const shutdownSupported = interfaceConfigSupported('shutdown');
  if (shutdownSupported && !['true', 'false'].includes(shutdown)) {
    throw new Error(t('Bitte den administrativen Portstatus ausdrücklich auswählen.'));
  }
  const config = {};
  if (modeSupported) config.mode = mode;
  if (interfaceConfigSupported('description')) config.description = document.getElementById('intf-description').value;
  if (interfaceConfigSupported('edge_port')) config.edge_port = document.getElementById('intf-portfast').value === 'true';
  if (shutdownSupported) config.shutdown = shutdown === 'true';
  if (interfaceConfigSupported('trunk_allowed_vlan')) {
    config.trunk_allowed_vlan = normalizeAllowedVlans(document.getElementById('intf-trunk-allowed').value);
  }
  for (const field of ['speed', 'duplex']) {
    if (!interfaceConfigSupported(field)) continue;
    const value = interfaceTunableRequestValue(field);
    if (value !== undefined) config[field] = value;
  }
  if (interfaceTunablesCoupled() && (config.speed === undefined) !== (config.duplex === undefined)) {
    // A coupled pair is only sent complete; an unknown partner value leaves both unchanged.
    delete config.speed;
    delete config.duplex;
  }
  if (['access', 'trunk'].includes(mode)) {
    const vlanField = mode === 'access' ? 'access_vlan' : 'native_vlan';
    const vlanInput = mode === 'access' ? 'intf-access-vlan' : 'intf-native-vlan';
    if (interfaceConfigSupported(vlanField)) {
      config[vlanField] = parseInt(document.getElementById(vlanInput).value, 10) || null;
    }
  }
  const voiceVlan = readVoiceVlanSetting(mode, includeUnchangedPoE);
  if (voiceVlan !== undefined) config.voice_vlan = voiceVlan;
  Object.assign(config, readPoeSettings(includeUnchangedPoE));
  return config;
}

// Voice-VLAN am Access-Port: leer = unverändert, 0 = entfernen. Eine Vorlage (Kopieren)
// übernimmt bei leerem Feld den vom Switch gelesenen Wert.
function readVoiceVlanSetting(mode, includeCurrent) {
  if (mode !== 'access' || !interfaceConfigSupported('voice_vlan')) return undefined;
  const raw = String(document.getElementById('intf-voice-vlan').value ?? '').trim();
  if (!raw) return includeCurrent && Number.isInteger(intfModalState.currentVoiceVlan) ? intfModalState.currentVoiceVlan : undefined;
  const value = /^\d+$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(value) || value > 4094) {
    throw new Error(t('Voice-VLAN: Bitte eine VLAN-ID von 1 bis 4094 oder 0 zum Entfernen eingeben.'));
  }
  return value;
}

const poeStandardWatts = Object.freeze({
  '802.3af': 15.4,
  '802.3at': 30,
  '802.3bt-type3': 60,
  '802.3bt-type4': 90,
  'cisco-upoe': 60,
});

function supportedPoeStandards(detail) {
  if (detail.poe_supported !== true || !Array.isArray(detail.poe_standard_options)) return [];
  const seen = new Set();
  return detail.poe_standard_options.filter(option => {
    if (!option || !Object.prototype.hasOwnProperty.call(poeStandardWatts, option.id)
        || option.max_watts !== poeStandardWatts[option.id] || seen.has(option.id)) return false;
    seen.add(option.id);
    return true;
  }).map(option => ({ id: option.id, label: String(option.label || option.id), max_watts: option.max_watts }));
}

function readPoeSettings(includeUnchanged) {
  if (intfModalState.poeSupported !== true || !interfaceConfigSupported('poe_mode')
      || (!intfModalState.poeChanged && !includeUnchanged)) return {};
  const mode = document.getElementById('intf-poe-mode').value;
  if (!['auto', 'static', 'never'].includes(mode)) {
    if (includeUnchanged && !intfModalState.poeChanged) return {};
    throw new Error(t('Bitte einen unterstützten PoE-Modus auswählen.'));
  }
  const config = { poe_mode: mode };
  if (mode !== 'never' && interfaceConfigSupported('poe_standard')) {
    const standard = document.getElementById('intf-poe-standard').value;
    if (standard === 'preserve') {
      // Sonderwerte bleiben lokal erhalten und werden niemals als Vorlage übertragen.
      return includeUnchanged ? {} : config;
    }
    if (standard !== 'default' && !intfModalState.poeStandardOptions.some(option => option.id === standard)) {
      throw new Error(t('PoE-Standard: Bitte ein für diesen Port bestätigtes Leistungsprofil auswählen.'));
    }
    if (includeUnchanged || intfModalState.poeStandardChanged) {
      config.poe_standard = standard;
    }
  }
  return config;
}

function initializePoeSettings(detail) {
  intfModalState.poeSupported = detail.poe_supported;
  intfModalState.poeChanged = false;
  intfModalState.poeStandardChanged = false;
  intfModalState.poeStandardOptions = supportedPoeStandards(detail);
  document.getElementById('intf-poe-mode').value = ['auto', 'static', 'never'].includes(detail.poe_mode) ? detail.poe_mode : '';
  const configuredLimit = detail.poe_configured_max_watts;
  const knownLimit = typeof configuredLimit === 'number' && Number.isFinite(configuredLimit);
  const select = document.getElementById('intf-poe-standard');
  const preserveLabel = knownLimit
    ? t('Bestehendes Limit beibehalten ({limit})', { limit: formatPoeWatts(configuredLimit) })
    : t('Bestehendes Limit beibehalten');
  select.innerHTML = `<option value="preserve">${escapeHtml(preserveLabel)}</option>`
    + (detail.poe_supported === true ? `<option value="default">${escapeHtml(t('Gerätestandard (kein manuelles Limit)'))}</option>` : '')
    + intfModalState.poeStandardOptions.map(option => `<option value="${escapeHtml(option.id)}">${escapeHtml(option.label)}</option>`).join('');
  const matching = knownLimit
    ? intfModalState.poeStandardOptions.filter(option => Math.abs(option.max_watts - configuredLimit) < 0.000001) : [];
  select.value = matching.length === 1 ? matching[0].id
    : configuredLimit === null && detail.poe_supported === true ? 'default' : 'preserve';
  const capabilityMessage = detail.poe_supported === true
    ? (intfModalState.poeStandardOptions.length
      ? (detail.poe_hardware_model
        ? t('Für diesen Port bestätigte Standards ({model}).', { model: detail.poe_hardware_model })
        : t('Für diesen Port bestätigte Standards.'))
      : t('Die unterstützten Standards konnten nicht bestätigt werden. Es sind keine Standardprofile freigegeben.'))
      + (detail.poe_standards_reason ? ` ${detail.poe_standards_reason}` : '')
    : '';
  document.getElementById('intf-poe-capability').textContent = capabilityMessage;
  document.getElementById('intf-poe-status').textContent = detail.poe_supported === false
    ? t('Dieses Interface unterstützt kein PoE.')
    : detail.poe_supported !== true
      ? t('PoE-Daten sind für dieses Interface nicht verfügbar. Die PoE-Konfiguration bleibt unverändert.')
      : t('Genutzt: {used} · Maximum: {max}', { used: formatPoeWatts(detail.poe_used_watts), max: formatPoeWatts(detail.poe_max_watts) })
        + (detail.poe_status ? ` · ${t('Status: {status}', { status: detail.poe_status })}` : '');
}

function updateInterfaceCopyControls() {
  const canEdit = currentSessionCanEdit();
  if (!canEdit || copiedInterfaceSettings?.session !== currentSession) copiedInterfaceSettings = null;
  const busy = !intfModalState.detailLoaded || intfModalState.session !== currentSession
    || intfModalState.saving || interfaceMutationInProgress;
  setElementHidden('intf-copy-controls', !canEdit);
  setElementHidden('intf-copy-status', !canEdit);
  document.getElementById('intf-copy').disabled = !canEdit || busy;
  document.getElementById('intf-paste').disabled = !canEdit || busy || !copiedInterfaceSettings;
  const source = copiedInterfaceSettings;
  document.getElementById('intf-copy-status').textContent = source
    ? t('Vorlage: {switch} / {port}. Einfügen füllt diesen Dialog; „Übernehmen“ konfiguriert den Zielport.', { switch: source.sourceSwitchName, port: source.sourcePort })
      + interfaceCopyOmissions(source.config)
    : t('Kopiert die Einstellungen dieses Dialogs. Anschließend einen anderen Port öffnen und „Einfügen“ wählen.');
}

function interfaceCopyOmissions(config) {
  const omitted = ['speed', 'duplex'].filter(field => config[field] === undefined);
  const labels = omitted.map(field => interfaceTunableFields[field].label);
  const fields = labels.length === 2 ? t('{first} und {second}', { first: labels[0], second: labels[1] }) : labels[0];
  return (omitted.length
    ? ` ${t('{fields} nicht kopiert: Quellwert unbekannt oder nicht unterstützt; bleibt am Ziel unverändert.', { fields })}`
    : '') + (config.poe_mode === undefined ? ` ${t('PoE nicht kopiert: Quelldaten unbekannt, nicht unterstützt oder bestehendes Sonderlimit ohne bestätigtes Standardprofil.')}` : '');
}

function copyInterfaceSettings() {
  if (!requireEditPermission() || intfModalState.saving || interfaceMutationInProgress) return;
  try {
    const config = readInterfaceSettings({ includeUnchangedPoE: true });
    copiedInterfaceSettings = {
      session: currentSession,
      sourceSwitchId: intfModalState.switchId,
      sourceSwitchName: switches.find(sw => Number(sw.id) === Number(intfModalState.switchId))?.name
        || t('Switch {id}', { id: intfModalState.switchId }),
      sourcePort: intfModalState.port,
      config,
    };
    document.getElementById('intf-modal-error').textContent = '';
    updateInterfaceCopyControls();
    toast(t('Einstellungen von {port} kopiert.', { port: intfModalState.port }));
  } catch (e) {
    document.getElementById('intf-modal-error').textContent = e.message;
  }
}

function pasteInterfaceSettings() {
  if (!requireEditPermission() || !intfModalState.detailLoaded
      || intfModalState.session !== currentSession
      || intfModalState.saving || interfaceMutationInProgress) return;
  if (!copiedInterfaceSettings || copiedInterfaceSettings.session !== currentSession) {
    updateInterfaceCopyControls();
    return;
  }
  const { config, sourcePort, sourceSwitchName } = copiedInterfaceSettings;
  // Fields the target does not support (other vendor/model/port) are left out and listed.
  const skipped = [];
  const paste = (field, apply) => {
    if (config[field] === undefined) return;
    if (!interfaceConfigSupported(field)) {
      skipped.push(field);
      return;
    }
    apply(config[field]);
  };
  paste('description', value => { document.getElementById('intf-description').value = value; });
  paste('mode', value => {
    document.getElementById('intf-mode').value = value;
    intfModalState.modeExplicitlySelected = true;
  });
  if (config.mode !== undefined) {
    const vlanField = config.mode === 'access' ? 'access_vlan' : 'native_vlan';
    const vlanInput = config.mode === 'access' ? 'intf-access-vlan' : 'intf-native-vlan';
    paste(vlanField, value => selectCurrentInterfaceVlan(document.getElementById(vlanInput), value, t('kopiert')));
  }
  // Fehlende Quellwerte bedeuten unverändert, auch wenn das Ziel Werte besitzt.
  paste('trunk_allowed_vlan', value => { document.getElementById('intf-trunk-allowed').value = value ?? ''; });
  paste('edge_port', value => { document.getElementById('intf-portfast').value = value ? 'true' : 'false'; });
  paste('voice_vlan', value => { document.getElementById('intf-voice-vlan').value = String(value); });
  paste('shutdown', value => { document.getElementById('intf-shutdown').value = value ? 'true' : 'false'; });
  for (const field of ['speed', 'duplex']) {
    paste(field, value => {
      if (value !== 'auto' && !interfaceTunableValues(field).includes(value)) {
        skipped.push(field);
        return;
      }
      initializeInterfaceTunableField(field, value);
    });
  }
  let pastePoe = false;
  let poeIncompatible = false;
  if (config.poe_mode !== undefined) {
    const modeState = interfaceFeature('poe_mode');
    if (!modeState.supported || (modeState.options && !modeState.options.includes(config.poe_mode))) {
      poeIncompatible = true;
      skipped.push('poe_mode');
      if (config.poe_standard !== undefined) skipped.push('poe_standard');
    } else {
      let standard = config.poe_standard;
      if (standard !== undefined && !interfaceConfigSupported('poe_standard')) {
        skipped.push('poe_standard');
        standard = undefined;
      }
      pastePoe = intfModalState.poeSupported === true
        && (config.poe_mode === 'never' || standard === undefined || standard === 'default'
          || intfModalState.poeStandardOptions.some(option => option.id === standard));
      if (pastePoe) {
        document.getElementById('intf-poe-mode').value = config.poe_mode;
        if (standard !== undefined) document.getElementById('intf-poe-standard').value = standard;
        intfModalState.poeChanged = true;
        intfModalState.poeStandardChanged = standard !== undefined;
      }
    }
  }
  document.getElementById('intf-modal-error').textContent = '';
  updateInterfaceModalControls();
  document.getElementById('intf-copy-status').textContent = t('Einstellungen von {switch} / {port} eingefügt. Bitte prüfen und mit „Übernehmen“ auf {target} anwenden.', { switch: sourceSwitchName, port: sourcePort, target: intfModalState.port })
    + interfaceCopyOmissions(config)
    + (config.poe_mode !== undefined && !pastePoe && !poeIncompatible ? ` ${t('PoE am Ziel nicht eingefügt: Der Port unterstützt das gewählte Standardprofil nicht oder die Unterstützung ist unbekannt. Die PoE-Einstellungen am Ziel bleiben unverändert.')}` : '')
    + (skipped.length
      ? ` ${t('Nicht übernommen (inkompatibel): {fields}.', { fields: skipped.map(interfaceConfigLabel).join(', ') })}`
      : '');
}

document.getElementById('intf-copy').addEventListener('click', copyInterfaceSettings);
document.getElementById('intf-paste').addEventListener('click', pasteInterfaceSettings);

function configurableInterfaceMode(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[_-]+/g, ' ');
  if (['access', 'static access'].includes(normalized)) return 'access';
  if (['trunk', 'static trunk'].includes(normalized)) return 'trunk';
  return null;
}

const preservedTunableValue = '__preserve_unknown__';
const interfaceTunableFields = {
  speed: {
    checkboxId: 'intf-speed-enable',
    selectId: 'intf-speed',
    defaultValues: ['10', '100', '1000'],
    optionLabel: value => value,
    preserveKey: 'preserveUnknownSpeed',
    label: t('Speed'),
  },
  duplex: {
    checkboxId: 'intf-duplex-enable',
    selectId: 'intf-duplex',
    defaultValues: ['half', 'full'],
    optionLabel: value => value.charAt(0).toUpperCase() + value.slice(1),
    preserveKey: 'preserveUnknownDuplex',
    label: t('Duplex'),
  },
};

// Allowed values: port_options of the interface detail narrow the capability options.
function interfaceTunableAllowed(fieldName) {
  const capabilityOptions = interfaceFeature(fieldName).options;
  const portOptions = intfModalState.portOptions?.[fieldName];
  let allowed = capabilityOptions ? capabilityOptions.map(value => value.toLowerCase()) : null;
  if (Array.isArray(portOptions)) {
    const port = portOptions.map(value => String(value).toLowerCase());
    allowed = allowed ? allowed.filter(value => port.includes(value)) : port;
  }
  return allowed;
}

function renderInterfaceTunableOptions(fieldName) {
  const field = interfaceTunableFields[fieldName];
  const allowed = interfaceTunableAllowed(fieldName);
  const values = [...new Set([...field.defaultValues, ...(allowed || [])])].filter(value => value !== 'auto');
  document.getElementById(field.selectId).innerHTML = values.map(value => {
    const incompatible = allowed !== null && !allowed.includes(value);
    const label = field.optionLabel(value) + (incompatible ? ` ${t('(inkompatibel)')}` : '');
    return `<option value="${escapeHtml(value)}"${incompatible ? ' disabled' : ''}>${escapeHtml(label)}</option>`;
  }).join('');
}

// Selectable (compatible) values currently offered for a speed/duplex field.
function interfaceTunableValues(fieldName) {
  const select = document.getElementById(interfaceTunableFields[fieldName].selectId);
  return Array.from(select.options)
    .filter(option => !option.disabled && option.dataset.preservedValue === undefined)
    .map(option => option.value);
}

function resetInterfaceTunableField(fieldName) {
  const field = interfaceTunableFields[fieldName];
  const checkbox = document.getElementById(field.checkboxId);
  const select = document.getElementById(field.selectId);
  renderInterfaceTunableOptions(fieldName);
  checkbox.checked = false;
  select.disabled = true;
  select.selectedIndex = 0;
  intfModalState[field.preserveKey] = false;
}

function initializeInterfaceTunableField(fieldName, rawValue) {
  const field = interfaceTunableFields[fieldName];
  const checkbox = document.getElementById(field.checkboxId);
  const select = document.getElementById(field.selectId);
  resetInterfaceTunableField(fieldName);
  const normalized = String(rawValue ?? '').trim().toLowerCase();

  if (normalized === 'auto') return;
  if (interfaceTunableValues(fieldName).includes(normalized)) {
    checkbox.checked = true;
    select.disabled = false;
    select.value = normalized;
    return;
  }

  const option = document.createElement('option');
  option.value = preservedTunableValue;
  option.textContent = t('{field}: {value} (unverändert)', { field: field.label, value: hasValue(rawValue) ? rawValue : t('unbekannt') });
  option.disabled = true;
  option.dataset.preservedValue = 'true';
  select.appendChild(option);
  option.selected = true;
  checkbox.checked = true;
  select.disabled = false;
  intfModalState[field.preserveKey] = true;
}

function setInterfaceTunableEnabled(fieldName, enabled) {
  const field = interfaceTunableFields[fieldName];
  const select = document.getElementById(field.selectId);
  document.getElementById(field.checkboxId).checked = enabled;
  select.disabled = !enabled;
  intfModalState[field.preserveKey] = false;
  const values = interfaceTunableValues(fieldName);
  if (enabled && !values.includes(select.value) && values.length) select.value = values[0];
}

function interfaceTunableRequestValue(fieldName) {
  const field = interfaceTunableFields[fieldName];
  const checkbox = document.getElementById(field.checkboxId);
  const select = document.getElementById(field.selectId);
  if (intfModalState[field.preserveKey]) return undefined;
  if (!checkbox.checked) return 'auto';
  return interfaceTunableValues(fieldName).includes(select.value) ? select.value : undefined;
}

function renderInterfaceVlanOptions(vlans) {
  const options = (Array.isArray(vlans) ? vlans : []).map(vlan => {
    const id = vlan.id ?? vlan.vlan_id;
    if (!hasValue(id)) return '';
    const status = hasValue(vlan.status) ? String(vlan.status).trim() : '';
    const selectable = !status || status.toLowerCase() === 'active';
    const name = hasValue(vlan.name) ? ` - ${vlan.name}` : '';
    const statusLabel = status ? ` [${status}]` : '';
    return `<option value="${escapeHtml(id)}" ${selectable ? '' : 'disabled'}>${escapeHtml(id)}${escapeHtml(name)}${escapeHtml(statusLabel)}</option>`;
  }).join('');
  return `<option value="">${escapeHtml(t('Kein VLAN ausgewählt'))}</option>${options}`;
}

function selectCurrentInterfaceVlan(select, value, label = t('aktuell')) {
  if (!hasValue(value)) {
    select.value = '';
    return;
  }
  const normalizedValue = String(value);
  let option = [...select.options].find(item => item.value === normalizedValue);
  if (!option) {
    option = document.createElement('option');
    option.value = normalizedValue;
    option.textContent = t('{value} - {label} (nicht in VLAN-Liste)', { value: normalizedValue, label });
    option.disabled = true;
    select.appendChild(option);
  }
  option.selected = true;
}

function showInterfaceModeWarning(message) {
  const warning = document.getElementById('intf-mode-warning');
  warning.textContent = message || '';
  warning.classList.toggle('hidden', !message);
}

function toggleIntfModeFields() {
  const mode = document.getElementById('intf-mode').value;
  document.getElementById('intf-access-fields').classList.toggle('hidden', mode !== 'access');
  document.getElementById('intf-trunk-fields').classList.toggle('hidden', mode !== 'trunk');
}

function updateInterfaceModalControls() {
  const canEdit = currentSessionCanEdit();
  // Operatoren dürfen nur die Operator-Felder an erkannten Access-Ports ändern.
  const operatorOnly = !canEdit && canOperateSwitches();
  const canWrite = canEdit || (operatorOnly && intfModalState.operatorAccessPort === true);
  const fieldsDisabled = !canWrite || !intfModalState.detailLoaded
    || intfModalState.session !== currentSession || intfModalState.saving;
  const mode = document.getElementById('intf-mode').value;
  const shutdown = document.getElementById('intf-shutdown').value;
  const validMode = mode === 'access' || mode === 'trunk';
  const modeSupported = interfaceConfigSupported('mode');
  const shutdownSupported = interfaceConfigSupported('shutdown');
  toggleIntfModeFields();

  if (!modeSupported) {
    showInterfaceModeWarning('');
  } else if (intfModalState.unsupportedMode && !canEdit) {
    showInterfaceModeWarning(t('Erkannter administrativer Modus: {mode}', { mode: intfModalState.unsupportedMode }));
  } else if (intfModalState.unsupportedMode) {
    if (!validMode || !intfModalState.modeExplicitlySelected) {
      showInterfaceModeWarning(t(
        'Der erkannte Modus „{mode}“ wird nicht automatisch geändert. Wählen Sie ausdrücklich Static Access oder Trunk, um fortzufahren.',
        { mode: intfModalState.unsupportedMode }
      ));
    } else {
      const targetMode = mode === 'access' ? 'Static Access' : 'Trunk';
      showInterfaceModeWarning(t(
        'Der bisherige Modus „{mode}“ wird beim Speichern ausdrücklich in {target} geändert.',
        { mode: intfModalState.unsupportedMode, target: targetMode }
      ));
    }
  } else if (intfModalState.detailLoaded && !validMode) {
    showInterfaceModeWarning(canEdit
      ? t('Der administrative Portmodus konnte nicht sicher erkannt werden. Bitte Modus explizit wählen.')
      : t('Der administrative Portmodus konnte nicht sicher erkannt werden.'));
  } else {
    showInterfaceModeWarning('');
  }

  for (const [id, feature] of Object.entries(interfaceControlFeatures)) {
    const state = interfaceFeature(feature);
    const element = document.getElementById(id);
    element.disabled = fieldsDisabled || !state.supported || (operatorOnly && !OPERATOR_PORT_CONTROLS.has(id));
    applyIncompatibleState(element, state);
  }
  for (const [fieldName, field] of Object.entries(interfaceTunableFields)) {
    const state = interfaceFeature(fieldName);
    const checkbox = document.getElementById(field.checkboxId);
    const select = document.getElementById(field.selectId);
    checkbox.disabled = fieldsDisabled || !state.supported;
    select.disabled = fieldsDisabled || !state.supported || !checkbox.checked;
    applyIncompatibleState(checkbox, state);
    applyIncompatibleState(select, state);
  }
  const poeModeState = interfaceFeature('poe_mode');
  const poeLimitState = interfaceFeature('poe_limit');
  const poeModeSelect = document.getElementById('intf-poe-mode');
  const poeStandardSelect = document.getElementById('intf-poe-standard');
  const poeDisabled = fieldsDisabled || intfModalState.poeSupported !== true;
  markIncompatibleOptions(poeModeSelect, poeModeState.options);
  poeModeSelect.disabled = poeDisabled || !poeModeState.supported;
  applyIncompatibleState(poeModeSelect, poeModeState);
  poeStandardSelect.disabled = poeDisabled || !poeModeState.supported || !poeLimitState.supported
    || !['auto', 'static'].includes(poeModeSelect.value);
  applyIncompatibleState(poeStandardSelect, poeLimitState);
  setElementHidden('intf-save', !canWrite);
  document.getElementById('intf-cancel').textContent = canWrite ? t('Abbrechen') : t('Schließen');
  document.getElementById('intf-save').disabled = fieldsDisabled
    || (modeSupported && !validMode)
    || (shutdownSupported && !['true', 'false'].includes(shutdown))
    || Boolean(modeSupported && intfModalState.unsupportedMode && !intfModalState.modeExplicitlySelected);
  updateInterfaceCopyControls();
  updateInterfaceProfileControls(fieldsDisabled);
}

document.getElementById('intf-mode').addEventListener('change', () => {
  const mode = document.getElementById('intf-mode').value;
  if (intfModalState.unsupportedMode && ['access', 'trunk'].includes(mode)) {
    intfModalState.modeExplicitlySelected = true;
  }
  updateInterfaceModalControls();
});
document.getElementById('intf-shutdown').addEventListener('change', updateInterfaceModalControls);
document.getElementById('intf-poe-mode').addEventListener('change', () => {
  intfModalState.poeChanged = true;
  updateInterfaceModalControls();
});
document.getElementById('intf-poe-standard').addEventListener('change', () => {
  intfModalState.poeChanged = true;
  intfModalState.poeStandardChanged = true;
});

for (const [fieldName, field] of Object.entries(interfaceTunableFields)) {
  document.getElementById(field.checkboxId).addEventListener('change', event => {
    const enabled = event.target.checked;
    setInterfaceTunableEnabled(fieldName, enabled);
    // Coupled speed/duplex (capability `requires`) are switched together.
    const partner = fieldName === 'speed' ? 'duplex' : 'speed';
    if (interfaceTunablesCoupled() && interfaceFeature(partner).supported) setInterfaceTunableEnabled(partner, enabled);
    updateInterfaceModalControls();
  });
  document.getElementById(field.selectId).addEventListener('change', () => {
    intfModalState[field.preserveKey] = false;
  });
}

async function openInterfaceModal(switchId, port, vlans) {
  const canEdit = canOperateSwitches();
  const sessionAtStart = currentSession;
  const modalSequence = ++interfaceModalSequence;
  intfModalState = {
    session: sessionAtStart,
    switchId,
    port,
    detailLoaded: false,
    saving: false,
    unsupportedMode: null,
    modeExplicitlySelected: false,
    preserveUnknownSpeed: false,
    preserveUnknownDuplex: false,
    sw: switchById(switchId),
    overrides: {},
    portOptions: {},
  };
  document.getElementById('intf-modal-title').textContent = canEdit
    ? t('Port {port} konfigurieren', { port })
    : t('Port {port} – Details', { port });
  document.getElementById('intf-modal-error').textContent = '';
  document.getElementById('intf-name').value = port;
  document.getElementById('intf-description').value = '';
  document.getElementById('intf-mode').value = '';
  document.getElementById('intf-shutdown').value = '';
  document.getElementById('intf-trunk-allowed').value = '';
  document.getElementById('intf-portfast').value = 'false';
  const vlanOptions = renderInterfaceVlanOptions(vlans);
  document.getElementById('intf-access-vlan').innerHTML = vlanOptions;
  document.getElementById('intf-native-vlan').innerHTML = vlanOptions;
  document.getElementById('intf-access-vlan').value = '';
  document.getElementById('intf-native-vlan').value = '';
  document.getElementById('intf-voice-vlan').value = '';
  document.getElementById('intf-voice-vlan').placeholder = '';
  resetInterfaceTunableField('speed');
  resetInterfaceTunableField('duplex');
  initializePoeSettings({});
  initInterfaceProfileSelector(switchId, port, sessionAtStart);
  showInterfaceModeWarning('');
  updateInterfaceModalControls();

  document.getElementById('interface-modal').classList.remove('hidden');

  try {
    const detail = await api(`/api/switches/${switchId}/interface-detail?interface=${encodeURIComponent(port)}`);
    if (modalSequence !== interfaceModalSequence || currentSession !== sessionAtStart) return;
    document.getElementById('intf-description').value = detail.description || '';
    const rawMode = detail.switchport_enabled === false
      ? 'routed / switchport disabled'
      : (detail.administrative_mode || detail.mode || t('unbekannt'));
    const configurableMode = detail.switchport_enabled === true
      ? configurableInterfaceMode(detail.administrative_mode)
      : null;
    intfModalState.unsupportedMode = configurableMode ? null : (String(rawMode).trim() || t('unbekannt'));
    intfModalState.operatorAccessPort = configurableMode === 'access';
    document.getElementById('intf-mode').value = configurableMode || '';
    selectCurrentInterfaceVlan(document.getElementById('intf-access-vlan'), detail.access_vlan);
    selectCurrentInterfaceVlan(document.getElementById('intf-native-vlan'), detail.native_vlan);
    const voiceVlan = Number(detail.voice_vlan);
    intfModalState.currentVoiceVlan = hasValue(detail.voice_vlan) && Number.isInteger(voiceVlan) ? voiceVlan : null;
    document.getElementById('intf-voice-vlan').placeholder = intfModalState.currentVoiceVlan === null
      ? '' : t('Aktuell: {vlan}', { vlan: intfModalState.currentVoiceVlan });
    document.getElementById('intf-trunk-allowed').value = detail.trunk_allowed_vlan || '';
    document.getElementById('intf-portfast').value = detail.portfast ? 'true' : 'false';
    if (typeof detail.shutdown === 'boolean') {
      document.getElementById('intf-shutdown').value = detail.shutdown ? 'true' : 'false';
    } else {
      const adminState = normalizeAdminState(detail.admin_state);
      document.getElementById('intf-shutdown').value = adminState === 'disabled'
        ? 'true'
        : adminState === 'enabled' ? 'false' : '';
    }
    const isObject = value => value && typeof value === 'object' && !Array.isArray(value);
    intfModalState.overrides = isObject(detail.capability_overrides) ? detail.capability_overrides : {};
    intfModalState.portOptions = isObject(detail.port_options) ? detail.port_options : {};

    initializeInterfaceTunableField('speed', detail.speed);
    initializeInterfaceTunableField('duplex', detail.duplex);
    initializePoeSettings(detail);

    intfModalState.detailLoaded = true;
    updateInterfaceModalControls();
  } catch (e) {
    if (modalSequence !== interfaceModalSequence || currentSession !== sessionAtStart) return;
    document.getElementById('intf-modal-error').textContent = t('Aktuelle Werte konnten nicht geladen werden: {message}', { message: e.message });
    updateInterfaceModalControls();
  }
}

document.getElementById('intf-cancel').addEventListener('click', () => {
  interfaceModalSequence += 1;
  document.getElementById('interface-modal').classList.add('hidden');
});

document.getElementById('intf-save').addEventListener('click', async () => {
  if (!requireOperatePermission()) return;
  if (interfaceMutationInProgress) return;
  let settings;
  try {
    settings = readInterfaceSettings();
    if (!currentSessionCanEdit()) {
      settings = Object.fromEntries(Object.entries(settings).filter(([field]) => OPERATOR_PORT_FIELDS.has(field)));
    }
  } catch (e) {
    document.getElementById('intf-modal-error').textContent = e.message;
    updateInterfaceModalControls();
    return;
  }

  const switchId = intfModalState.switchId;
  const port = intfModalState.port;
  const modalSequence = interfaceModalSequence;
  const sessionAtStart = currentSession;
  const body = { interface: port, ...settings };
  const configTarget = {
    admin_state: body.shutdown === undefined ? null : (body.shutdown ? 'disabled' : 'enabled'),
    mode: body.mode,
    access_vlan: body.access_vlan ?? null,
    native_vlan: body.native_vlan ?? null,
    voice_vlan: body.voice_vlan,
    trunk_allowed_vlan: body.trunk_allowed_vlan,
    poe_mode: body.poe_mode,
    poe_standard: body.poe_standard,
    poe_max_watts: intfModalState.poeStandardOptions.find(option => option.id === body.poe_standard)?.max_watts,
  };
  const mutationSequence = ++interfaceMutationSequence;
  intfModalState.saving = true;
  interfaceMutationInProgress = true;
  document.getElementById('intf-modal-error').textContent = '';
  updateInterfaceModalControls();
  setInterfaceActionControlsBusy(true);
  try {
    let result;
    try {
      result = await runSwitchChange(switchId, 'port-configure', body, {
        title: t('Port {port} konfigurieren', { port }),
      });
    } catch (mutationError) {
      if (currentSession !== sessionAtStart) return;
      if (modalSequence === interfaceModalSequence) {
        document.getElementById('intf-modal-error').textContent = mutationError.message;
      } else {
        toast(mutationError.message, true);
      }
      await refreshInterfaceInventoryAfterMutation(switchId);
      return;
    }
    if (currentSession !== sessionAtStart || !result) return;
    if (!result.ok) {
      // Der Switch hat Teile abgelehnt - Dialog offen lassen, damit die
      // Eingaben nicht verloren gehen und die Meldung sichtbar bleibt.
      if (modalSequence === interfaceModalSequence) {
        document.getElementById('intf-modal-error').textContent = result.message || t('Der Switch hat die Konfiguration abgelehnt.');
      }
      await refreshInterfaceInventoryAfterMutation(switchId);
      return;
    }
    if (modalSequence === interfaceModalSequence) {
      interfaceModalSequence += 1;
      document.getElementById('interface-modal').classList.add('hidden');
    }
    await pollInterfaceInventory(switchId, port, {
      expectedAdminState: configTarget.admin_state,
      configTarget,
    });
  } catch (e) {
    if (currentSession !== sessionAtStart) return;
    if (modalSequence === interfaceModalSequence) {
      document.getElementById('intf-modal-error').textContent = e.message;
    } else {
      toast(e.message, true);
    }
  } finally {
    if (mutationSequence === interfaceMutationSequence) {
      interfaceMutationInProgress = false;
      setInterfaceActionControlsBusy(false);
    }
    if (modalSequence === interfaceModalSequence) {
      intfModalState.saving = false;
      updateInterfaceModalControls();
    }
  }
});

// --- Gruppen-Modal -------------------------------------------------------

let editingGroupId = null;

function openGroupModal(group = null) {
  if (!requireEditPermission()) return;
  if (modalOperations.has('group-modal')) return;
  editingGroupId = group ? group.id : null;
  document.getElementById('group-modal-title').textContent = group ? t('Gruppe umbenennen') : t('Gruppe erstellen');
  document.getElementById('group-name').value = group ? group.name : '';
  document.getElementById('group-modal').classList.remove('hidden');
  document.getElementById('group-name').focus();
}

document.getElementById('btn-add-group').addEventListener('click', () => openGroupModal());
document.getElementById('group-cancel').addEventListener('click', () => {
  document.getElementById('group-modal').classList.add('hidden');
});
document.getElementById('group-save').addEventListener('click', async () => {
  if (!requireEditPermission()) return;
  const name = document.getElementById('group-name').value.trim();
  if (!name) {
    toast(t('Bitte einen Gruppennamen eingeben.'), true);
    return;
  }
  const operation = beginModalOperation('group-modal');
  if (!operation) return;
  try {
    if (editingGroupId) {
      await api(`/api/switch-groups/${editingGroupId}`, { method: 'PUT', body: JSON.stringify({ name }) });
    } else {
      await api('/api/switch-groups', { method: 'POST', body: JSON.stringify({ name }) });
    }
    if (!modalOperationIsCurrent(operation)) return;
    document.getElementById('group-modal').classList.add('hidden');
    await loadSwitches();
  } catch (e) {
    if (modalOperationIsCurrent(operation)) toast(e.message, true);
  } finally {
    finishModalOperation(operation);
  }
});
document.getElementById('group-name').addEventListener('keydown', event => {
  if (event.key === 'Enter') document.getElementById('group-save').click();
});

async function deleteSwitchGroup(group) {
  if (!requireEditPermission()) return;
  const question = group.switch_count
    ? t('Gruppe „{name}“ wirklich löschen? Die {count} enthaltenen Switches bleiben ohne Gruppe erhalten.', { name: group.name, count: group.switch_count })
    : t('Gruppe „{name}“ wirklich löschen?', { name: group.name });
  if (!confirm(question)) return;
  const sessionAtStart = currentSession;
  try {
    await api(`/api/switch-groups/${group.id}`, { method: 'DELETE' });
    if (currentSession !== sessionAtStart) return;
    collapsedGroups.delete(`group:${group.id}`);
    persistCollapsedGroups();
    await loadSwitches();
  } catch (e) {
    if (currentSession === sessionAtStart) toast(e.message, true);
  }
}

// --- VLAN-Tab ------------------------------------------------------------

let vlanModalState = null;
// switchId -> VLAN list of the last rendered VLAN tab; the row buttons look their VLAN up here.
const vlanTabData = new Map();
const VLAN_USAGE_KINDS = [['access', 'Access'], ['native', 'Native'], ['voice', 'Voice'], ['trunk', 'Trunk']];
const VLAN_USAGE_PORT_LIMIT = 6;
const VLAN_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;

function renderVlanUsage(vlan) {
  const usage = vlan.usage && typeof vlan.usage === 'object' ? vlan.usage : {};
  const lines = VLAN_USAGE_KINDS.map(([kind, label]) => {
    const ports = Array.isArray(usage[kind]) ? usage[kind].filter(hasValue).map(String) : [];
    if (ports.length === 0) return '';
    const hidden = ports.length - VLAN_USAGE_PORT_LIMIT;
    const more = hidden > 0 ? ` ${t('+{count} weitere', { count: hidden })}` : '';
    return `${escapeHtml(t(label))}: ${escapeHtml(ports.slice(0, VLAN_USAGE_PORT_LIMIT).join(', ') + more)}`;
  }).filter(Boolean);
  if (vlan.l3_interface === true) lines.push(escapeHtml(t('Layer-3-Interface')));
  if (lines.length === 0) return '—';
  return lines.map((line, index) => `<div${index === 0 ? '' : ' class="interface-vlan-detail"'}>${line}</div>`).join('');
}

// Class, disabled and title attributes of a VLAN write button; blockedReason disables a supported action.
function vlanActionAttributes(classes, state, blockedReason = '') {
  const classList = [...classes, state.supported ? '' : 'is-incompatible'].filter(Boolean).join(' ');
  const title = state.supported ? blockedReason : incompatibleTitle(state);
  return ` class="${classList}"${!state.supported || blockedReason ? ' disabled' : ''}`
    + `${state.supported ? '' : ' aria-disabled="true"'}${title ? ` title="${escapeHtml(title)}"` : ''}`;
}

// vtpLock: {reason, takeover} when VTP refuses VLAN writes on this switch (client or VTPv3 secondary server).
function renderVlanTable(switchId, list, warnings, vtpLock = null) {
  const sw = switchById(switchId);
  const canEdit = currentSessionCanEdit();
  const createState = featureState(sw, 'vlan_create');
  const renameState = featureState(sw, 'vlan_rename');
  const deleteState = featureState(sw, 'vlan_delete');
  // Voice als VLAN-Eigenschaft gibt es nur auf AOS-CX/AOS-S (Feature vlan_voice).
  const voiceState = featureState(sw, 'vlan_voice');
  const badge = state => (state.supported ? '' : incompatibleBadge());
  const lockReason = vtpLock && hasValue(vtpLock.reason) ? String(vtpLock.reason) : '';
  const toolbar = `${renderVtpLock(switchId, vtpLock, 'vlan-vtp-lock', 'btn-vlan-vtp-primary')}${canEdit ? `
    <div class="flex-row" style="justify-content: flex-end; margin-bottom: 8px;">
      <button id="btn-create-vlan"${vlanActionAttributes(['primary'], createState, lockReason)}>${escapeHtml(t('VLAN anlegen'))}${badge(createState)}</button>
    </div>
  ` : ''}`;
  if (list.length === 0) {
    return `${toolbar}${renderInventoryWarnings(warnings)}<div class="empty-state">${escapeHtml(t('Keine VLANs gefunden.'))}</div>`;
  }
  const rows = list.map(vlan => {
    const id = escapeHtml(vlan.id);
    const blocked = lockReason || (hasValue(vlan.delete_blocked) ? String(vlan.delete_blocked) : '');
    const actions = canEdit ? `
          <td class="table-actions"><div class="table-actions-inner">
            <button data-vlan-id="${id}"${vlanActionAttributes(['rename-vlan-btn'], renameState, lockReason)}>${escapeHtml(t('Umbenennen'))}${badge(renameState)}</button>
            <button data-vlan-id="${id}"${vlanActionAttributes(['delete-vlan-btn', deleteState.supported ? 'danger' : ''], deleteState, blocked)}>${escapeHtml(t('Löschen'))}${badge(deleteState)}</button>
            ${voiceState.supported && typeof vlan.voice === 'boolean' ? `<button data-vlan-id="${id}" data-voice="${!vlan.voice}" class="voice-vlan-btn">${escapeHtml(vlan.voice ? t('Voice entfernen') : t('Als Voice markieren'))}</button>` : ''}
          </div></td>
    ` : '';
    return `
        <tr class="vlan-row" data-vlan-id="${id}">
          <td>${id}</td>
          <td>${escapeHtml(vlan.name || '—')}</td>
          <td>${escapeHtml(vlan.status || '—')}</td>
          <td>${renderVlanUsage(vlan)}</td>
          ${voiceState.supported ? `<td>${escapeHtml(vlan.voice === true ? t('Ja') : vlan.voice === false ? t('Nein') : '—')}</td>` : ''}
          ${actions}
        </tr>
    `;
  }).join('');
  const filter = (column, placeholder) => `<th><input class="table-filter" type="search" data-column="${column}" placeholder="${escapeHtml(placeholder)}" aria-label="${escapeHtml(placeholder)}"></th>`;
  return `
    ${toolbar}
    ${renderInventoryWarnings(warnings)}
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr><th>${escapeHtml(t('VLAN-ID'))}</th><th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Verwendung'))}</th>${voiceState.supported ? `<th>${escapeHtml(t('Voice'))}</th>` : ''}${canEdit ? '<th></th>' : ''}</tr>
          <tr class="filter-row">
            ${filter(0, t('VLAN suchen'))}
            ${filter(1, t('Name suchen'))}
            ${filter(2, t('Status suchen'))}
            ${filter(3, t('Port suchen'))}
            ${voiceState.supported ? '<th></th>' : ''}
            ${canEdit ? '<th></th>' : ''}
          </tr>
        </thead>
        <tbody>
          ${rows}
          <tr id="no-vlan-results" class="hidden"><td colspan="${4 + (canEdit ? 1 : 0) + (voiceState.supported ? 1 : 0)}" style="text-align:center; color:var(--text-dim);">${escapeHtml(t('Keine passenden VLANs gefunden.'))}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}

function vlanFromTab(switchId, vlanId) {
  return (vlanTabData.get(Number(switchId)) || []).find(vlan => String(vlan.id) === String(vlanId)) || null;
}

// force: a reload after a write replaces a read that is still running (and disables the refresh button).
async function loadVlans(switchId, { force = false } = {}) {
  const container = document.getElementById('vlans-container');
  const button = document.getElementById('btn-refresh-vlans');
  if (!container || (button?.disabled && !force)) return;
  const session = currentSession;
  const sequence = ++vlanRequestSequence;
  const isCurrentView = () => sequence === vlanRequestSequence
    && container === document.getElementById('vlans-container');
  const isCurrent = () => isCurrentView() && currentSession === session;
  if (button) button.disabled = true;
  try {
    const result = await api(`/api/switches/${switchId}/vlans`);
    if (!isCurrent()) return;
    if (!Array.isArray(result?.vlans)) throw new Error(t('Der Switch lieferte keine gültige VLAN-Liste.'));
    const list = result.vlans.filter(vlan => vlan && typeof vlan === 'object');
    vlanTabData.set(Number(switchId), list);
    container.innerHTML = renderVlanTable(switchId, list, result.warnings, result.vtp || null);
    document.getElementById('btn-vlan-vtp-primary')?.addEventListener('click', () => openVtpPrimaryModal(switchId, reloadVlansAfterWrite));
    if (list.length) attachTableFilters(container, '.vlan-row', '#no-vlan-results');
    document.getElementById('btn-create-vlan')?.addEventListener('click', () => openVlanModal(switchId, null));
    container.querySelectorAll('.rename-vlan-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const vlan = vlanFromTab(switchId, btn.dataset.vlanId);
        if (vlan) openVlanModal(switchId, vlan);
      });
    });
    container.querySelectorAll('.voice-vlan-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const vlan = vlanFromTab(switchId, btn.dataset.vlanId);
        if (vlan) setVlanVoice(switchId, vlan, btn.dataset.voice === 'true');
      });
    });
    container.querySelectorAll('.delete-vlan-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const vlan = vlanFromTab(switchId, btn.dataset.vlanId);
        if (vlan) deleteVlan(switchId, vlan);
      });
    });
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (isCurrentView() && button === document.getElementById('btn-refresh-vlans') && button) button.disabled = false;
  }
}

// Reloads the VLAN tab after a write while the same session still shows that switch's VLAN tab.
function reloadVlansAfterWrite(switchId, session) {
  if (currentSession !== session || Number(currentSwitchId) !== Number(switchId)) return undefined;
  if (!document.getElementById('vlans-container')) return undefined;
  return loadVlans(switchId, { force: true });
}

function openVlanModal(switchId, vlan = null) {
  if (!requireEditPermission()) return;
  if (modalOperations.has('vlan-modal')) return;
  const sw = switchById(switchId);
  vlanModalState = { switchId: Number(switchId), vlanId: vlan ? Number(vlan.id) : null, session: currentSession };
  document.getElementById('vlan-modal-title').textContent = vlan
    ? t('VLAN {vlan} umbenennen', { vlan: vlan.id }) : t('VLAN anlegen');
  const idInput = document.getElementById('vlan-id');
  idInput.value = vlan ? String(vlan.id) : '';
  idInput.disabled = Boolean(vlan);
  document.getElementById('vlan-name').value = vlan && hasValue(vlan.name) ? String(vlan.name) : '';
  setElementHidden('vlan-name-field', !vlan && !featureState(sw, 'vlan_rename').supported);
  document.getElementById('vlan-modal-error').textContent = '';
  setElementHidden('vlan-modal', false);
  document.getElementById(vlan ? 'vlan-name' : 'vlan-id').focus();
}

function closeVlanModal() {
  setElementHidden('vlan-modal', true);
  vlanModalState = null;
}

document.getElementById('vlan-cancel').addEventListener('click', closeVlanModal);
document.getElementById('vlan-save').addEventListener('click', async () => {
  if (!requireEditPermission()) return;
  const state = vlanModalState;
  if (!state || state.session !== currentSession) return;
  const errorElement = document.getElementById('vlan-modal-error');
  const creating = state.vlanId === null;
  const nameHidden = document.getElementById('vlan-name-field').classList.contains('hidden');
  const name = nameHidden ? '' : document.getElementById('vlan-name').value.trim();
  let vlanId = state.vlanId;
  if (creating) {
    const raw = String(document.getElementById('vlan-id').value).trim();
    vlanId = /^\d+$/.test(raw) ? Number(raw) : NaN;
    if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) {
      errorElement.textContent = t('Bitte eine VLAN-ID von 1 bis 4094 eingeben.');
      return;
    }
  }
  if ((name || !creating) && (!VLAN_NAME_PATTERN.test(name) || /^\d+$/.test(name))) {
    errorElement.textContent = t('Ungültiger VLAN-Name: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich (nicht nur Ziffern).');
    return;
  }
  const operation = beginModalOperation('vlan-modal');
  if (!operation) return;
  errorElement.textContent = '';
  const { switchId } = state;
  let applied = false;
  try {
    const result = creating
      ? await runSwitchChange(switchId, 'vlan-create', { vlan_id: vlanId, name: name || null }, { title: t('VLAN anlegen') })
      : await runSwitchChange(switchId, 'vlan-rename', { vlan_id: vlanId, name }, { title: t('VLAN {vlan} umbenennen', { vlan: vlanId }) });
    applied = Boolean(result);
    if (!modalOperationIsCurrent(operation) || !result) return;
    if (result.ok) {
      if (vlanModalState === state) closeVlanModal();
    } else {
      errorElement.textContent = result.message || '';
    }
  } catch (e) {
    applied = true;
    if (modalOperationIsCurrent(operation)) errorElement.textContent = e.message;
  } finally {
    finishModalOperation(operation);
    if (applied) await reloadVlansAfterWrite(switchId, state.session);
  }
});
['vlan-id', 'vlan-name'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', event => {
    if (event.key === 'Enter') document.getElementById('vlan-save').click();
  });
});

async function setVlanVoice(switchId, vlan, voice) {
  if (!requireEditPermission()) return;
  const vlanId = Number(vlan.id);
  if (!Number.isInteger(vlanId)) return;
  const key = `${switchId}:vlan-voice:${vlanId}`;
  if (pendingSwitchActions.has(key)) return;
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  let applied = false;
  try {
    const result = await runSwitchChange(switchId, 'vlan-voice', { vlan_id: vlanId, voice }, {
      title: voice ? t('VLAN {vlan} als Voice-VLAN markieren', { vlan: vlanId }) : t('Voice-Markierung von VLAN {vlan} entfernen', { vlan: vlanId }),
    });
    applied = Boolean(result);
  } catch (e) {
    applied = true;
    if (currentSession === session) toast(e.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
    if (applied) await reloadVlansAfterWrite(switchId, session);
  }
}

async function deleteVlan(switchId, vlan) {
  if (!requireEditPermission()) return;
  if (hasValue(vlan.delete_blocked)) {
    toast(String(vlan.delete_blocked), true);
    return;
  }
  const vlanId = Number(vlan.id);
  if (!Number.isInteger(vlanId)) return;
  const key = `${switchId}:vlan-delete:${vlanId}`;
  if (pendingSwitchActions.has(key)) return;
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  let applied = false;
  try {
    const result = await runSwitchChange(switchId, 'vlan-delete', { vlan_id: vlanId }, {
      title: t('VLAN {vlan} löschen', { vlan: vlan.name ? `${vlanId} (${vlan.name})` : vlanId }),
    });
    applied = Boolean(result);
  } catch (e) {
    applied = true;
    if (currentSession === session) toast(e.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
    if (applied) await reloadVlansAfterWrite(switchId, session);
  }
}

// --- Switch-Modal (Anlegen / Bearbeiten) --------------------------------

let editingSwitchId = null;
let editingSwitchEndpoint = null;

function updateSwitchCredentialsHelp() {
  const original = editingSwitchEndpoint;
  const endpointChanged = original && (
    document.getElementById('sw-ip').value.trim() !== original.ip
    || Number(document.getElementById('sw-port').value) !== original.port
    || document.getElementById('sw-device-type').value !== original.device_type
  );
  const button = document.getElementById('sw-edit-credentials');
  button.disabled = Boolean(endpointChanged);
  setElementHidden('sw-edit-credentials', !original);
  document.getElementById('sw-credentials-help').textContent = !original
    ? t('Nach dem Anlegen können Sie globale oder eigene Zugangsdaten für diesen Switch auswählen.')
    : endpointChanged && original.source === 'device'
      ? t('IP-Adresse, Port oder Gerätetyp geändert: Die eigenen Zugangsdaten werden beim Speichern entfernt und müssen für das neue Ziel erneut gesetzt werden. Es erfolgt kein automatischer Wechsel auf globale Zugangsdaten.')
      : endpointChanged
        ? t('Speichern Sie die geänderte Verbindung, bevor Sie Zugangsdaten konfigurieren.')
        : original.source === 'device'
          ? t('Dieser Switch verwendet eigene Zugangsdaten. Bei Änderung von IP-Adresse, Port oder Gerätetyp müssen diese erneut gesetzt werden.')
          : t('Dieser Switch verwendet globale Zugangsdaten. Eigene Zugangsdaten können separat konfiguriert werden.');
}

['sw-ip', 'sw-port', 'sw-device-type'].forEach(id => {
  document.getElementById(id).addEventListener('input', updateSwitchCredentialsHelp);
  document.getElementById(id).addEventListener('change', updateSwitchCredentialsHelp);
});
document.getElementById('sw-edit-credentials').addEventListener('click', () => {
  if (document.getElementById('sw-edit-credentials').disabled) return;
  const sw = switches.find(candidate => Number(candidate.id) === Number(editingSwitchId));
  if (sw) void openSwitchCredentialsModal(sw);
});

// Driver catalog from /api/switch-drivers, loaded once per session.
let switchDriversCache = null;
let switchModalPortTouched = false;

async function loadSwitchDrivers() {
  if (switchDriversCache && switchDriversCache.session === currentSession) return switchDriversCache.drivers;
  const session = currentSession;
  const payload = await api('/api/switch-drivers');
  const drivers = (Array.isArray(payload) ? payload : [])
    .filter(driver => driver && typeof driver === 'object' && hasValue(driver.id));
  if (currentSession === session) switchDriversCache = { session, drivers };
  return drivers;
}

function switchModalDrivers() {
  return switchDriversCache?.drivers || [];
}

function switchModalDriver() {
  const id = document.getElementById('sw-device-type').value;
  return switchModalDrivers().find(driver => driver.id === id) || null;
}

function renderSwitchVendorOptions(selectedVendor) {
  const vendors = [...new Set(switchModalDrivers().map(driver => String(driver.vendor || '')))];
  const select = document.getElementById('sw-vendor');
  select.innerHTML = vendors.map(vendor => `<option value="${escapeHtml(vendor)}">${escapeHtml(vendor)}</option>`).join('');
  select.value = vendors.includes(selectedVendor) ? selectedVendor : (vendors[0] ?? '');
}

function renderSwitchPlatformOptions(selectedId) {
  const vendor = document.getElementById('sw-vendor').value;
  const drivers = switchModalDrivers().filter(driver => String(driver.vendor || '') === vendor);
  const select = document.getElementById('sw-device-type');
  select.innerHTML = drivers.map(driver => {
    const label = driver.experimental ? `${driver.label} ${t('(experimentell)')}` : String(driver.label || driver.id);
    return `<option value="${escapeHtml(driver.id)}">${escapeHtml(label)}</option>`;
  }).join('');
  select.value = drivers.some(driver => driver.id === selectedId) ? selectedId : (drivers[0]?.id ?? '');
}

function renderSwitchModelOptions(selectedModelId) {
  const models = Array.isArray(switchModalDriver()?.models) ? switchModalDriver().models : [];
  const select = document.getElementById('sw-model');
  select.innerHTML = `<option value="">${escapeHtml(t('Automatisch erkennen'))}</option>`
    + models.map(model => `<option value="${escapeHtml(model.id)}">${escapeHtml(model.label || model.id)}</option>`).join('');
  select.value = models.some(model => model.id === selectedModelId) ? selectedModelId : '';
}

function handleSwitchDriverChange() {
  renderSwitchModelOptions(null);
  const driver = switchModalDriver();
  if (driver && !switchModalPortTouched && Number.isInteger(Number(driver.default_port))) {
    document.getElementById('sw-port').value = Number(driver.default_port);
  }
  updateSwitchCredentialsHelp();
}

document.getElementById('sw-vendor').addEventListener('change', () => {
  renderSwitchPlatformOptions(null);
  handleSwitchDriverChange();
});
document.getElementById('sw-device-type').addEventListener('change', handleSwitchDriverChange);
document.getElementById('sw-port').addEventListener('input', () => { switchModalPortTouched = true; });

async function openSwitchModal(sw = null) {
  if (!requireEditPermission()) return;
  if (modalOperations.has('switch-modal')) return;
  const sessionAtStart = currentSession;
  try {
    await loadSwitchDrivers();
  } catch (e) {
    if (currentSession === sessionAtStart) toast(t('Switch-Treiber konnten nicht geladen werden: {message}', { message: e.message }), true);
    return;
  }
  if (currentSession !== sessionAtStart || modalOperations.has('switch-modal')) return;
  editingSwitchId = sw ? sw.id : null;
  switchModalPortTouched = false;
  document.getElementById('switch-modal-title').textContent = sw ? t('Switch bearbeiten') : t('Switch hinzufügen');
  document.getElementById('sw-name').value = sw ? sw.name : '';
  document.getElementById('sw-ip').value = sw ? sw.ip : '';
  const currentDriver = sw ? switchModalDrivers().find(driver => driver.id === sw.device_type) : null;
  renderSwitchVendorOptions(currentDriver?.vendor);
  renderSwitchPlatformOptions(currentDriver?.id);
  renderSwitchModelOptions(sw?.model?.selected_id ?? null);
  document.getElementById('sw-site').value = sw ? (sw.site || '') : '';
  document.getElementById('sw-group').innerHTML = [
    `<option value="">${escapeHtml(t('Ohne Gruppe'))}</option>`,
    ...switchGroups.map(group => `<option value="${group.id}">${escapeHtml(group.name)}</option>`),
  ].join('');
  document.getElementById('sw-group').value = sw && sw.group_id ? String(sw.group_id) : '';
  document.getElementById('sw-port').value = sw ? sw.port : (switchModalDriver()?.default_port ?? 22);
  document.getElementById('sw-notes').value = sw ? (sw.notes || '') : '';
  editingSwitchEndpoint = sw ? {ip: sw.ip, port: Number(sw.port), device_type: sw.device_type, source: sw.credentials_source} : null;
  updateSwitchCredentialsHelp();
  document.getElementById('switch-modal').classList.remove('hidden');
}

document.getElementById('btn-add-switch').addEventListener('click', () => openSwitchModal());
document.getElementById('sw-cancel').addEventListener('click', () => document.getElementById('switch-modal').classList.add('hidden'));
document.getElementById('sw-save').addEventListener('click', async () => {
  if (!requireEditPermission()) return;
  const port = Number(document.getElementById('sw-port').value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    toast(t('Bitte einen Port zwischen 1 und 65535 eingeben.'), true);
    document.getElementById('sw-port').focus();
    return;
  }
  const body = {
    name: document.getElementById('sw-name').value.trim(),
    ip: document.getElementById('sw-ip').value.trim(),
    device_type: document.getElementById('sw-device-type').value,
    model_id: document.getElementById('sw-model').value || null,
    site: document.getElementById('sw-site').value.trim(),
    group_id: parseInt(document.getElementById('sw-group').value, 10) || null,
    port,
    notes: document.getElementById('sw-notes').value.trim(),
  };
  if (!body.name || !body.ip) {
    toast(t('Bitte Name und IP-Adresse eingeben.'), true);
    return;
  }
  const switchId = editingSwitchId;
  const operation = beginModalOperation('switch-modal');
  if (!operation) return;
  try {
    let savedSwitch;
    if (switchId) {
      savedSwitch = await api(`/api/switches/${switchId}`, { method: 'PUT', body: JSON.stringify(body) });
    } else {
      savedSwitch = await api('/api/switches', { method: 'POST', body: JSON.stringify(body) });
    }
    if (!modalOperationIsCurrent(operation)) return;
    document.getElementById('switch-modal').classList.add('hidden');
    await loadSwitches();
    if (modalOperationIsCurrent(operation) && Number(currentSwitchId) === Number(switchId)
        && switchId !== null && isWorkspaceActive('switches')) {
      const selected = switches.find(sw => Number(sw.id) === Number(switchId));
      if (selected) renderSwitchDetail(selected);
    }
    if (modalOperationIsCurrent(operation) && !switchId && savedSwitch?.id) {
      await openSwitchCredentialsModal(switches.find(sw => Number(sw.id) === Number(savedSwitch.id)) || savedSwitch);
    }
  } catch (e) {
    if (modalOperationIsCurrent(operation)) toast(e.message, true);
  } finally {
    finishModalOperation(operation);
  }
});

// --- Zugangsdaten je Switch ----------------------------------------------

let switchCredentialsSequence = 0;
let switchCredentialsState = null;

function switchCredentialsLabel(sw) {
  const source = sw?.credentials_source === 'device' ? t('Eigene Zugangsdaten') : t('Globale Zugangsdaten');
  return sw?.credentials_configured === false ? t('{source} · nicht eingerichtet', { source }) : source;
}

function clearSwitchCredentialInputs() {
  ['switch-credentials-username', 'switch-credentials-password', 'switch-credentials-enable'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('switch-credentials-clear-enable').checked = false;
}

function closeSwitchCredentialsModal() {
  switchCredentialsSequence += 1;
  switchCredentialsState = null;
  clearSwitchCredentialInputs();
  document.getElementById('switch-credentials-status').textContent = '';
  document.getElementById('switch-credentials-error').textContent = '';
  setElementHidden('switch-credentials-modal', true);
}

function updateSwitchCredentialsControls() {
  const state = switchCredentialsState;
  const mode = document.getElementById('switch-credentials-mode').value;
  const own = mode === 'device';
  const busy = modalOperations.has('switch-credentials-modal');
  const ready = Boolean(state?.info && state.session === currentSession && currentSessionCanEdit() && !state.stale);
  const info = state?.info;
  setElementHidden('switch-credentials-device-fields', !own);
  document.getElementById('switch-credentials-mode').disabled = !ready || busy;
  document.getElementById('switch-credentials-save').disabled = !ready || busy;
  ['switch-credentials-username', 'switch-credentials-password', 'switch-credentials-clear-enable'].forEach(id => {
    document.getElementById(id).disabled = !ready || busy || !own;
  });
  const clearEnable = document.getElementById('switch-credentials-clear-enable').checked;
  document.getElementById('switch-credentials-enable').disabled = !ready || busy || !own || clearEnable;
  setElementHidden('switch-credentials-clear-enable-field', !info?.enable_secret_configured);
  document.getElementById('switch-credentials-mode-help').textContent = own
    ? t('Eigene Zugangsdaten gelten ausschließlich für diesen Switch und werden verschlüsselt gespeichert.')
    : (info?.global_configured ? t('Dieser Switch verwendet den global gespeicherten Benutzernamen und das Passwort.') : t('Globale Zugangsdaten sind noch nicht eingerichtet. Legen Sie diese unter „Administration → Globale Zugangsdaten“ an oder wählen Sie eigene Zugangsdaten.'))
      + (info?.override_configured ? ` ${t('Beim Speichern werden die eigenen Zugangsdaten dieses Switches entfernt.')}` : '');
  document.getElementById('switch-credentials-password-help').textContent = info?.override_configured
    ? t('Passwort leer lassen, um das für diesen Switch gespeicherte Passwort beizubehalten.')
    : t('Für eigene Zugangsdaten sind Benutzername und Passwort erforderlich.');
  document.getElementById('switch-credentials-enable-help').textContent = info?.enable_secret_configured
    ? t('Leer behält das eigene Enable-Secret bei. Zum Entfernen das Kontrollkästchen auswählen.')
    : t('Optional für privilegierten Zugriff. Leer bedeutet kein Enable-Secret; das globale Enable-Secret wird bei eigenen Zugangsdaten nicht übernommen.');
}

async function openSwitchCredentialsModal(sw) {
  if (!requireEditPermission() || modalOperations.has('switch-credentials-modal')) return;
  const switchId = Number(sw?.id);
  if (!Number.isInteger(switchId) || switchId <= 0) return;
  closeSwitchCredentialsModal();
  const state = {switchId, session: currentSession, sequence: switchCredentialsSequence, info: null, stale: false};
  switchCredentialsState = state;
  document.getElementById('switch-credentials-title').textContent = t('Zugangsdaten · {name}', { name: sw.name || 'Switch' });
  document.getElementById('switch-credentials-mode').value = 'global';
  document.getElementById('switch-credentials-status').textContent = t('Zugangsdatenstatus wird geladen …');
  setElementHidden('switch-credentials-modal', false);
  updateSwitchCredentialsControls();
  try {
    const info = await api(`/api/switches/${switchId}/credentials`);
    if (switchCredentialsState !== state || currentSession !== state.session || !currentSessionCanEdit()) return;
    state.info = info;
    document.getElementById('switch-credentials-mode').value = info.mode === 'device' ? 'device' : 'global';
    document.getElementById('switch-credentials-username').value = info.username || '';
    document.getElementById('switch-credentials-status').textContent = info.configured
      ? t('Zugangsdaten sind eingerichtet. Gespeicherte Passwörter werden nicht angezeigt.')
      : t('Für diesen Switch sind noch keine nutzbaren Zugangsdaten eingerichtet.');
    updateSwitchCredentialsControls();
  } catch (error) {
    if (switchCredentialsState !== state || currentSession !== state.session) return;
    document.getElementById('switch-credentials-status').textContent = '';
    document.getElementById('switch-credentials-error').textContent = error.message;
  }
}

document.getElementById('switch-credentials-mode').addEventListener('change', () => {
  document.getElementById('switch-credentials-password').value = '';
  document.getElementById('switch-credentials-enable').value = '';
  document.getElementById('switch-credentials-clear-enable').checked = false;
  updateSwitchCredentialsControls();
});
document.getElementById('switch-credentials-clear-enable').addEventListener('change', () => {
  if (document.getElementById('switch-credentials-clear-enable').checked) document.getElementById('switch-credentials-enable').value = '';
  updateSwitchCredentialsControls();
});
document.getElementById('switch-credentials-cancel').addEventListener('click', () => {
  if (!modalOperations.has('switch-credentials-modal')) closeSwitchCredentialsModal();
});
document.getElementById('switch-credentials-save').addEventListener('click', async () => {
  const state = switchCredentialsState;
  if (!requireEditPermission() || !state?.info || state.session !== currentSession || state.stale) return;
  const errorField = document.getElementById('switch-credentials-error');
  errorField.textContent = '';
  const body = {mode: document.getElementById('switch-credentials-mode').value, revision_token: state.info.revision_token};
  if (body.mode === 'device') {
    body.username = document.getElementById('switch-credentials-username').value.trim();
    const password = document.getElementById('switch-credentials-password').value;
    const enable = document.getElementById('switch-credentials-enable').value;
    if (!body.username || (!state.info.override_configured && !password)) {
      errorField.textContent = t('Bitte Benutzername und Passwort für diesen Switch eingeben.');
      return;
    }
    if (password) body.password = password;
    if (document.getElementById('switch-credentials-clear-enable').checked) body.clear_enable_secret = true;
    else if (enable) body.enable_secret = enable;
  } else if (body.mode !== 'global') {
    errorField.textContent = t('Bitte globale oder eigene Zugangsdaten auswählen.');
    return;
  }
  const operation = beginModalOperation('switch-credentials-modal');
  if (!operation) return;
  try {
    await api(`/api/switches/${state.switchId}/credentials`, {method: 'PUT', body: JSON.stringify(body)});
    if (!modalOperationIsCurrent(operation) || switchCredentialsState !== state) return;
    closeSwitchCredentialsModal();
    toast(t('Zugangsdaten für den Switch gespeichert.'));
    await loadSwitches();
    if (!modalOperationIsCurrent(operation)) return;
    const updated = switches.find(sw => Number(sw.id) === state.switchId);
    if (updated && Number(editingSwitchId) === state.switchId && editingSwitchEndpoint) {
      editingSwitchEndpoint.source = updated.credentials_source;
      updateSwitchCredentialsHelp();
    }
    if (updated && Number(currentSwitchId) === state.switchId && isWorkspaceActive('switches')) renderSwitchDetail(updated);
  } catch (error) {
    if (!modalOperationIsCurrent(operation)) return;
    if (switchCredentialsState === state) {
      state.stale = error.status === 409;
      errorField.textContent = error.message + (state.stale ? ` ${t('Dialog schließen und erneut öffnen, um den aktuellen Stand zu laden.')}` : '');
    } else toast(error.message, true);
  } finally {
    body.password = null;
    body.enable_secret = null;
    finishModalOperation(operation);
    if (switchCredentialsState === state) updateSwitchCredentialsControls();
  }
});

// --- Globale Zugangsdaten ------------------------------------------------

let globalCredentialsSequence = 0;
let globalCredentialsSession = null;

async function openGlobalCredentials() {
  if (!currentSessionCanEdit() || modalOperations.has('admin-page-credentials')) return;
  const sessionAtStart = currentSession;
  const sequence = ++globalCredentialsSequence;
  globalCredentialsSession = sessionAtStart;
  const status = document.getElementById('cred-status');
  status.textContent = t('Lade Daten …');
  document.getElementById('cred-password').value = '';
  document.getElementById('cred-enable').value = '';
  const isStale = () => currentSession !== sessionAtStart
    || sequence !== globalCredentialsSequence
    || modalOperations.has('admin-page-credentials');
  try {
    const info = await api('/api/credentials');
    if (isStale()) return;
    status.textContent = info.configured
      ? t('Zugangsdaten sind konfiguriert.')
      : t('Es sind keine Zugangsdaten konfiguriert.');
    document.getElementById('cred-username').value = info.configured ? (info.username || '') : '';
  } catch (error) {
    if (isStale()) return;
    status.textContent = '';
    toast(error.message, true);
  }
}

function resetGlobalCredentialsPage() {
  globalCredentialsSequence += 1;
  globalCredentialsSession = null;
  document.getElementById('cred-username').value = '';
  document.getElementById('cred-password').value = '';
  document.getElementById('cred-enable').value = '';
  document.getElementById('cred-status').textContent = '';
}

document.getElementById('cred-save').addEventListener('click', async () => {
  if (!requireEditPermission()) return;
  const body = {
    username: document.getElementById('cred-username').value.trim(),
    password: document.getElementById('cred-password').value,
    enable_secret: document.getElementById('cred-enable').value || null,
  };
  const operation = beginModalOperation('admin-page-credentials');
  if (!operation) return;
  try {
    await api('/api/credentials', { method: 'POST', body: JSON.stringify(body) });
    if (!modalOperationIsCurrent(operation)) return;
    toast(t('Zugangsdaten gespeichert.'));
    document.getElementById('cred-password').value = '';
    document.getElementById('cred-enable').value = '';
    document.getElementById('cred-status').textContent = t('Zugangsdaten sind konfiguriert.');
    runSessionHooks('credentialsChanged');
    await loadSwitches();
    if (modalOperationIsCurrent(operation) && currentSwitchId != null && isWorkspaceActive('switches')) {
      const selected = switches.find(sw => Number(sw.id) === Number(currentSwitchId));
      if (selected) renderSwitchDetail(selected);
    }
  } catch (e) {
    if (modalOperationIsCurrent(operation)) toast(e.message, true);
  } finally {
    body.password = null;
    body.enable_secret = null;
    finishModalOperation(operation);
  }
});

// --- Arbeitsbereich -------------------------------------------------------

function renderSwitchWorkspace() {
  renderSwitchList();
  const selected = switches.find(sw => Number(sw.id) === Number(currentSwitchId));
  if (selected) {
    renderSwitchDetail(selected);
  } else {
    document.getElementById('main-content').innerHTML = currentSessionCanEdit()
      ? `<div class="empty-state">${escapeHtml(t('Wähle links einen Switch aus, oder füge einen neuen hinzu.'))}</div>`
      : `<div class="empty-state">${escapeHtml(t('Wähle links einen Switch aus.'))}</div>`;
  }
}

registerWorkspace('switches', {
  navButtonId: 'nav-switches',
  sidebarId: 'switch-sidebar',
  onEnter() {
    switchSelectionSequence += 1;
    globalSearchSequence += 1;
    renderSwitchWorkspace();
  },
  onLeave() {
    switchSelectionSequence += 1;
    globalSearchSequence += 1;
    cancelInterfaceInventoryWork();
  },
});
document.getElementById('nav-switches').addEventListener('click', () => setWorkspaceMode('switches'));
