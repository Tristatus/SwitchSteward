(() => {
  'use strict';

  const PAGE_SIZE = 100;
  const WLAN_API = '/api/wlan/controllers';
  const DEFAULT_WLAN_TRANSPORTS = [
    { id: 'restconf', label: 'RESTCONF (HTTPS)', default_port: 443 },
    { id: 'netconf', label: 'NETCONF (SSH/YANG)', default_port: 830 },
  ];
  const FALLBACK_WLAN_PLATFORMS = [
    { id: 'catalyst_9800', label: 'Cisco Catalyst 9800', transports: DEFAULT_WLAN_TRANSPORTS },
  ];
  let wlanControllers = [];
  let currentWlanControllerId = null;
  let activeWlanTab = 'overview';
  let controllerListSequence = 0;
  let wlanDataSequence = 0;
  let wlanTestConnectionSequence = 0;
  let editingWlanControllerId = null;
  let editingWlanControllerSnapshot = null;
  let wlanPlatformCatalog = FALLBACK_WLAN_PLATFORMS;
  let wlanControllerSelectedPlatform = 'catalyst_9800';
  let wlanControllerSelectedTransport = 'restconf';
  let wlanControllerModalGeneration = 0;
  let wlanControllerSaveSequence = 0;
  let wlanControllerRevisionConflict = false;
  let credentialsWlanControllerId = null;
  let wlanCredentialsConfigured = false;
  let wlanGlobalCredentialsConfigured = false;
  let wlanCredentialsRevisionToken = null;
  let wlanCredentialsControllerRevisionToken = null;
  let wlanCredentialsReloadControllersOnClose = false;
  let wlanCredentialsModalGeneration = 0;
  let wlanCredentialsSaveSequence = 0;
  let wlanCredentialsSaving = false;
  let wlanCredentialsSession = null;
  let wlanConfigurationSequence = 0;
  let wlanConfiguration = null;
  let wlanDeviceGeneration = 0;
  let wlanDeviceContext = null;
  let wlanDeviceFocusReturn = null;
  const wlanTableState = {
    accessPoints: { q: '', status: '', offset: 0 },
    clients: { q: '', ap: '', ssid: '', offset: 0 },
  };

  const element = id => document.getElementById(id);
  const controllerKey = id => String(id ?? '');
  const isWlanWorkspace = () => isWorkspaceActive('wlan');
  const selectedWlanController = () => wlanControllers.find(
    controller => controllerKey(controller.id) === controllerKey(currentWlanControllerId),
  ) || null;

  function firstValue(source, keys, fallback = null) {
    if (!source || typeof source !== 'object') return fallback;
    for (const key of keys) {
      const value = source[key];
      if (value !== null && value !== undefined && value !== '') return value;
    }
    return fallback;
  }

  function finiteInteger(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? Math.trunc(parsed) : fallback;
  }

  function controllerName(controller) {
    return String(firstValue(controller, ['name', 'display_name'], t('Unbenannter Controller')));
  }

  function controllerCredentialsMode(controller) {
    const mode = controller?.mode || controller?.credentials_source;
    if (mode === 'global' || mode === 'device') return mode;
    return controller?.credentials_override_configured === true
      || controller?.credentials_configured === true ? 'device' : 'global';
  }

  function controllerHasCredentialOverride(controller) {
    return controller?.credentials_override_configured
      ?? (controllerCredentialsMode(controller) === 'device' && controller?.credentials_configured === true);
  }

  function controllerHost(controller) {
    return String(firstValue(controller, ['host', 'ip', 'address'], '—'));
  }

  function normalizedControllerHost(value) {
    return String(value || '').trim().replace(/\.$/, '').toLocaleLowerCase('en-US');
  }

  function controllerConnectionChanged(original, next) {
    if (!original) return false;
    return normalizedControllerHost(controllerHost(original)) !== normalizedControllerHost(next.host)
      || String(original.platform || 'catalyst_9800') !== String(next.platform)
      || controllerTransport(original) !== normalizeTransportId(next.transport)
      || controllerPort(original) !== Number(next.port);
  }

  function platformLabel(platform) {
    const catalogEntry = wlanPlatformCatalog.find(entry => entry.id === String(platform || ''));
    return catalogEntry?.label || String(platform || t('Unbekannte Plattform'));
  }

  function normalizeTransportId(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return normalized || 'restconf';
  }

  function controllerTransport(controller) {
    return normalizeTransportId(controller?.transport);
  }

  function transportsForPlatform(platform) {
    const platformId = String(platform || 'catalyst_9800');
    const metadata = wlanPlatformCatalog.find(entry => entry.id === platformId);
    return Array.isArray(metadata?.transports) && metadata.transports.length
      ? metadata.transports
      : DEFAULT_WLAN_TRANSPORTS;
  }

  function transportMetadata(platform, transport) {
    const transportId = normalizeTransportId(transport);
    return transportsForPlatform(platform).find(entry => entry.id === transportId)
      || DEFAULT_WLAN_TRANSPORTS.find(entry => entry.id === transportId)
      || { id: transportId, label: transportId.toUpperCase(), default_port: 443 };
  }

  function transportLabel(transport, platform = 'catalyst_9800') {
    return transportMetadata(platform, transport).label;
  }

  function transportProtocolName(transport) {
    const transportId = normalizeTransportId(transport);
    if (transportId === 'restconf') return 'RESTCONF';
    if (transportId === 'netconf') return 'NETCONF';
    return transportId.toUpperCase();
  }

  function transportDefaultPort(platform, transport) {
    const value = Number(transportMetadata(platform, transport).default_port);
    return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : 443;
  }

  function controllerPort(controller) {
    const value = Number(controller?.port);
    return Number.isInteger(value) && value >= 1 && value <= 65535
      ? value
      : transportDefaultPort(controller?.platform, controllerTransport(controller));
  }

  function encodeControllerId(id) {
    return encodeURIComponent(controllerKey(id));
  }

  function resetWlanTableState() {
    wlanTableState.accessPoints.q = '';
    wlanTableState.accessPoints.status = '';
    wlanTableState.accessPoints.offset = 0;
    wlanTableState.clients.q = '';
    wlanTableState.clients.ap = '';
    wlanTableState.clients.ssid = '';
    wlanTableState.clients.offset = 0;
  }

  registerWorkspace('wlan', {
    navButtonId: 'nav-wlan',
    sidebarId: 'wlan-sidebar',
    onEnter() {
      wlanDataSequence += 1;
      wlanTestConnectionSequence += 1;
      invalidateWlanConfiguration();
      element('main-content').innerHTML = `<div class="empty-state" role="status">${escapeHtml(t('Lade WLAN-Controller …'))}</div>`;
      loadWlanControllers();
    },
    onLeave() {
      wlanDataSequence += 1;
      wlanTestConnectionSequence += 1;
      invalidateWlanConfiguration();
    },
  });

  function normalizeControllerCollection(payload) {
    const raw = Array.isArray(payload) ? payload : payload?.items;
    return (Array.isArray(raw) ? raw : []).filter(
      controller => controller && typeof controller === 'object' && !Array.isArray(controller),
    );
  }

  async function loadWlanControllers(options = {}) {
    const sessionAtStart = currentSession;
    const sequence = ++controllerListSequence;
    const list = element('wlan-controller-list');
    list.innerHTML = `<div class="wlan-sidebar-message">${escapeHtml(t('Lade Controller …'))}</div>`;
    try {
      const payload = await api(WLAN_API);
      if (sequence !== controllerListSequence || currentSession !== sessionAtStart || !currentSession) return;
      wlanControllers = normalizeControllerCollection(payload);
      const selectedControllerBeforeLoad = currentWlanControllerId;
      const selectedStillExists = wlanControllers.some(
        controller => controllerKey(controller.id) === controllerKey(currentWlanControllerId),
      );
      if (!selectedStillExists) currentWlanControllerId = wlanControllers[0]?.id ?? null;
      if (controllerKey(selectedControllerBeforeLoad) !== controllerKey(currentWlanControllerId)) {
        activeWlanTab = 'overview';
        resetWlanTableState();
        wlanTestConnectionSequence += 1;
      }
      renderWlanControllerList();
      if (!isWlanWorkspace()) return;
      if (currentWlanControllerId === null) {
        renderEmptyWlanWorkspace();
        return;
      }
      renderWlanControllerDetail(selectedWlanController());
      if (options.keepTab !== true) activeWlanTab = 'overview';
      showWlanTab(activeWlanTab);
    } catch (error) {
      if (sequence !== controllerListSequence || currentSession !== sessionAtStart) return;
      list.innerHTML = `<div class="wlan-sidebar-message error">${escapeHtml(error.message)}</div>`;
      if (isWlanWorkspace()) {
        element('main-content').innerHTML = `
          <div class="panel-box">
            <div class="wlan-error-box">${escapeHtml(t('WLAN-Controller konnten nicht geladen werden: {error}', { error: error.message }))}</div>
            <button id="wlan-retry-controller-list" type="button">${escapeHtml(t('Erneut versuchen'))}</button>
          </div>`;
        element('wlan-retry-controller-list')?.addEventListener('click', () => loadWlanControllers());
      }
    }
  }

  function renderWlanControllerList() {
    const list = element('wlan-controller-list');
    const query = element('wlan-controller-search').value.trim().toLocaleLowerCase('de');
    const filtered = wlanControllers.filter(controller => [
      controllerName(controller),
      controllerHost(controller),
      controller.site,
      controller.notes,
      platformLabel(controller.platform),
    ].some(value => String(value || '').toLocaleLowerCase('de').includes(query)));

    if (filtered.length === 0) {
      if (wlanControllers.length === 0) {
        list.innerHTML = `<div class="wlan-sidebar-message">${escapeHtml(t('Noch kein WLAN-Controller angelegt.'))}</div>`;
      } else {
        list.innerHTML = `<div class="wlan-sidebar-message">${escapeHtml(t('Keine passenden Controller gefunden.'))}</div>`;
      }
      return;
    }

    list.innerHTML = '';
    filtered.forEach(controller => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'wlan-controller-item' + (
        controllerKey(controller.id) === controllerKey(currentWlanControllerId) ? ' active' : ''
      );
      item.innerHTML = `
        <span>${escapeHtml(controllerName(controller))}</span>
        <span class="wlan-controller-address">${escapeHtml(controllerHost(controller))}:${escapeHtml(controllerPort(controller))}</span>
        ${controller.site ? `<span class="wlan-controller-site">${escapeHtml(controller.site)}</span>` : ''}`;
      item.addEventListener('click', () => selectWlanController(controller.id));
      list.appendChild(item);
    });
  }

  function renderEmptyWlanWorkspace() {
    const action = currentSessionCanEdit()
      ? `<button class="primary" id="wlan-empty-add-controller" type="button">${escapeHtml(t('Controller hinzufügen'))}</button>`
      : `<div class="search-summary">${escapeHtml(t('Ein Administrator muss zuerst einen Controller einrichten.'))}</div>`;
    element('main-content').innerHTML = `
      <div class="panel-box">
        <div class="empty-state">
          <div>${escapeHtml(t('Noch kein WLAN-Controller konfiguriert.'))}</div>
          <div style="margin-top: 14px;">${action}</div>
        </div>
      </div>`;
    element('wlan-empty-add-controller')?.addEventListener('click', () => openWlanControllerModal());
  }

  function selectWlanController(id) {
    const controller = wlanControllers.find(candidate => controllerKey(candidate.id) === controllerKey(id));
    if (!controller) {
      toast(t('Der ausgewählte WLAN-Controller ist nicht mehr vorhanden.'), true);
      loadWlanControllers();
      return;
    }
    wlanDataSequence += 1;
    wlanTestConnectionSequence += 1;
    invalidateWlanConfiguration();
    currentWlanControllerId = controller.id;
    activeWlanTab = 'overview';
    resetWlanTableState();
    renderWlanControllerList();
    renderWlanControllerDetail(controller);
    showWlanTab('overview');
  }

  function renderWlanControllerDetail(controller) {
    if (!controller) {
      renderEmptyWlanWorkspace();
      return;
    }
    if (wlanConfiguration && controllerKey(wlanConfiguration.controllerId) !== controllerKey(controller.id)) {
      invalidateWlanConfiguration();
    }
    const canEdit = currentSessionCanEdit();
    const transport = controllerTransport(controller);
    const port = controllerPort(controller);
    const ownCredentials = controllerCredentialsMode(controller) === 'device';
    const credentialsText = controller.credentials_configured === true
      ? (ownCredentials ? t('Eigene Zugangsdaten eingerichtet') : t('Globale Zugangsdaten eingerichtet'))
      : (ownCredentials ? t('Eigene Zugangsdaten fehlen') : t('Globale Zugangsdaten fehlen'));
    const credentialsStatus = `<span class="wlan-pill ${controller.credentials_configured === true ? 'ok' : 'warning'}">${escapeHtml(credentialsText)}</span>`;
    const writeActions = canEdit ? `
      <button id="wlan-controller-test" type="button">${escapeHtml(t('Verbindung testen'))}</button>
      <button id="wlan-controller-credentials" type="button">${escapeHtml(t('Zugangsdaten'))}</button>
      <button id="wlan-controller-edit" type="button">${escapeHtml(t('Inventar bearbeiten'))}</button>
      <button class="danger" id="wlan-controller-delete" type="button">${escapeHtml(t('Löschen'))}</button>` : '';

    element('main-content').innerHTML = `
      <div class="panel-box">
        <div class="wlan-controller-heading">
          <div>
            <h2 class="wlan-controller-title">${escapeHtml(controllerName(controller))}</h2>
            <div class="wlan-controller-subtitle">${escapeHtml(controllerHost(controller))} · ${escapeHtml(platformLabel(controller.platform))}</div>
          </div>
          <div class="flex-row wlan-controller-actions">${writeActions}</div>
        </div>
        <div class="detail-grid" aria-label="${escapeHtml(t('Controllerdetails'))}">
          <div class="detail-item"><span class="detail-label">${escapeHtml(t('Standort'))}</span><div class="detail-value">${escapeHtml(controller.site || '—')}</div></div>
          <div class="detail-item"><span class="detail-label">${escapeHtml(t('Transport'))}</span><div class="detail-value">${escapeHtml(t('{transport} · Port {port}', { transport: transportLabel(transport, controller.platform), port }))}</div></div>
          <div class="detail-item"><span class="detail-label">${escapeHtml(t('Zugangsdaten'))}</span><div class="detail-value">${credentialsStatus}</div></div>
          <div class="detail-item"><span class="detail-label">${escapeHtml(t('Notizen'))}</span><div class="detail-value">${escapeHtml(controller.notes || '—')}</div></div>
        </div>
        <div id="wlan-capabilities" class="wlan-capabilities" aria-live="polite">${escapeHtml(t('Geräteinformationen werden geladen …'))}</div>
      </div>
      <div class="flex-row wlan-tabs" role="tablist" aria-label="${escapeHtml(t('WLAN-Controllerdaten'))}">
        <button class="tab-btn" data-wlan-tab="overview" type="button" role="tab">${escapeHtml(t('Übersicht'))}</button>
        <button class="tab-btn" data-wlan-tab="access-points" type="button" role="tab">${escapeHtml(t('Access Points'))}</button>
        <button class="tab-btn" data-wlan-tab="clients" type="button" role="tab">${escapeHtml(t('Clients'))}</button>
        <button class="tab-btn" data-wlan-tab="wlans" type="button" role="tab">${escapeHtml(t('WLANs'))}</button>
        <button class="tab-btn" data-wlan-tab="profiles" type="button" role="tab">${escapeHtml(t('Profile & Tags'))}</button>
      </div>
      <div id="wlan-tab-content"></div>`;

    element('wlan-controller-test')?.addEventListener('click', testWlanConnection);
    element('wlan-controller-credentials')?.addEventListener('click', () => openWlanCredentialsModal(controller));
    element('wlan-controller-edit')?.addEventListener('click', () => openWlanControllerModal(controller));
    element('wlan-controller-delete')?.addEventListener('click', () => deleteWlanController(controller));
    element('main-content').querySelectorAll('[data-wlan-tab]').forEach(button => {
      button.addEventListener('click', () => showWlanTab(button.dataset.wlanTab));
    });
    loadWlanConfiguration();
  }

  function showWlanTab(tab) {
    if (!isWlanWorkspace() || !selectedWlanController()) return;
    activeWlanTab = ['overview', 'access-points', 'clients', 'wlans', 'profiles'].includes(tab) ? tab : 'overview';
    wlanDataSequence += 1;
    element('main-content').querySelectorAll('[data-wlan-tab]').forEach(button => {
      const active = button.dataset.wlanTab === activeWlanTab;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', String(active));
    });
    if (activeWlanTab === 'overview') renderWlanOverview();
    if (activeWlanTab === 'access-points') renderAccessPointTab();
    if (activeWlanTab === 'clients') renderClientTab();
    if (['wlans', 'profiles'].includes(activeWlanTab)) renderWlanConfigurationTab();
  }

  function normalizeWlanEnvelope(payload, requestedOffset = 0, requestedLimit = PAGE_SIZE) {
    const legacyItems = Array.isArray(payload) ? payload : null;
    const source = !legacyItems && payload && typeof payload === 'object' ? payload : {};
    const items = (legacyItems || (Array.isArray(source.items) ? source.items : [])).filter(
      item => item && typeof item === 'object' && !Array.isArray(item),
    );
    const warnings = Array.isArray(source.warnings)
      ? source.warnings.map(warningText).filter(Boolean)
      : [];
    return {
      items,
      total: finiteInteger(source.total, items.length),
      offset: finiteInteger(source.offset, requestedOffset),
      limit: Math.max(1, finiteInteger(source.limit, requestedLimit)),
      collectedAt: firstValue(source, ['collected_at', 'collectedAt']),
      complete: source.complete !== false,
      warnings,
      cached: source.cached === true,
    };
  }

  function warningText(warning) {
    if (typeof warning === 'string') return warning;
    if (!warning || typeof warning !== 'object') return String(warning || '');
    return String(firstValue(warning, ['message', 'detail', 'warning', 'code'], t('Unbekannte Warnung')));
  }

  function formatWlanDate(value) {
    if (!value) return t('nicht verfügbar');
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    return new Intl.DateTimeFormat(uiLocale(), {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(parsed);
  }

  function envelopeWarnings(envelope) {
    const messages = [...envelope.warnings];
    if (!envelope.complete) messages.unshift(t('Die Abfrage ist unvollständig; es werden verfügbare Teilergebnisse angezeigt.'));
    if (messages.length === 0) return '';
    return `
      <div class="wlan-warning-box" role="status">
        <strong>${messages.length === 1 ? escapeHtml(t('Hinweis')) : escapeHtml(t('Hinweise zur Abfrage'))}</strong>
        <ul>${messages.map(message => `<li>${escapeHtml(message)}</li>`).join('')}</ul>
      </div>`;
  }

  function envelopeMeta(envelope) {
    const first = envelope.total === 0 ? 0 : envelope.offset + 1;
    const last = Math.min(envelope.offset + envelope.items.length, envelope.total);
    return `
      <div class="wlan-data-meta">
        <span>${escapeHtml(t('{first}–{last} von {total} Einträgen', { first, last, total: envelope.total }))}</span>
        <span class="wlan-data-meta-details">
          ${envelope.cached ? `<span class="wlan-pill">${escapeHtml(t('Cache'))}</span>` : `<span class="wlan-pill ok">${escapeHtml(t('Live-Abfrage'))}</span>`}
          ${envelope.complete ? `<span class="wlan-pill ok">${escapeHtml(t('Vollständig'))}</span>` : `<span class="wlan-pill warning">${escapeHtml(t('Teilresultat'))}</span>`}
          <span>${escapeHtml(t('Stand: {date}', { date: formatWlanDate(envelope.collectedAt) }))}</span>
        </span>
      </div>`;
  }

  function renderPagination(container, envelope, onPage) {
    const hasPrevious = envelope.offset > 0;
    const hasNext = envelope.offset + envelope.items.length < envelope.total;
    const first = envelope.total === 0 ? 0 : envelope.offset + 1;
    const last = Math.min(envelope.offset + envelope.items.length, envelope.total);
    const controls = document.createElement('div');
    controls.className = 'wlan-pagination';
    controls.innerHTML = `
      <span>${escapeHtml(t('{first}–{last} von {total}', { first, last, total: envelope.total }))}</span>
      <button class="wlan-page-previous" type="button" ${hasPrevious ? '' : 'disabled'}>${escapeHtml(t('Zurück'))}</button>
      <button class="wlan-page-next" type="button" ${hasNext ? '' : 'disabled'}>${escapeHtml(t('Weiter'))}</button>`;
    controls.querySelector('.wlan-page-previous').addEventListener('click', () => {
      if (hasPrevious) onPage(Math.max(0, envelope.offset - envelope.limit));
    });
    controls.querySelector('.wlan-page-next').addEventListener('click', () => {
      if (hasNext) onPage(envelope.offset + envelope.limit);
    });
    container.appendChild(controls);
  }

  function dataRequestIsCurrent(sequence, controllerId, tab) {
    return sequence === wlanDataSequence
      && isWlanWorkspace()
      && controllerKey(currentWlanControllerId) === controllerKey(controllerId)
      && activeWlanTab === tab;
  }

  function renderWlanOverview(forceRefresh = false) {
    const content = element('wlan-tab-content');
    content.innerHTML = `
      <div class="panel-box">
        <div class="wlan-summary-grid" aria-live="polite">
          <div class="wlan-summary-card"><div class="wlan-summary-label">${escapeHtml(t('Access Points'))}</div><div class="wlan-summary-value">…</div><div class="wlan-summary-detail">${escapeHtml(t('Wird abgefragt'))}</div></div>
          <div class="wlan-summary-card"><div class="wlan-summary-label">${escapeHtml(t('Clients am WLC'))}</div><div class="wlan-summary-value">…</div><div class="wlan-summary-detail">${escapeHtml(t('Wird abgefragt'))}</div></div>
          <div class="wlan-summary-card"><div class="wlan-summary-label">${escapeHtml(t('Plattform'))}</div><div class="wlan-summary-value" style="font-size:16px">${escapeHtml(platformLabel(selectedWlanController()?.platform))}</div><div class="wlan-summary-detail">${escapeHtml(t('{transport} · Port {port}', { transport: transportLabel(controllerTransport(selectedWlanController()), selectedWlanController()?.platform), port: controllerPort(selectedWlanController()) }))}</div></div>
          <div class="wlan-summary-card"><div class="wlan-summary-label">${escapeHtml(t('Datenstand'))}</div><div class="wlan-summary-value" style="font-size:16px">…</div><div class="wlan-summary-detail">${escapeHtml(t('{protocol}-Abfrage läuft', { protocol: transportProtocolName(controllerTransport(selectedWlanController())) }))}</div></div>
        </div>
        <div id="wlan-overview-messages"></div>
      </div>`;
    loadWlanOverview(forceRefresh);
  }

  async function loadWlanOverview(forceRefresh = false) {
    const controller = selectedWlanController();
    if (!controller) return;
    const controllerId = controller.id;
    const sequence = ++wlanDataSequence;
    const refresh = forceRefresh ? '&refresh=true' : '';
    const [apResult, clientResult] = await Promise.allSettled([
      api(`${WLAN_API}/${encodeControllerId(controllerId)}/access-points?offset=0&limit=1${refresh}`),
      api(`${WLAN_API}/${encodeControllerId(controllerId)}/clients?offset=0&limit=1${refresh}`),
    ]);
    if (!dataRequestIsCurrent(sequence, controllerId, 'overview')) return;

    const cards = element('wlan-tab-content').querySelectorAll('.wlan-summary-card');
    const messages = element('wlan-overview-messages');
    const errors = [];
    const envelopes = [];
    let apEnvelope = null;
    let clientEnvelope = null;
    if (apResult.status === 'fulfilled') {
      apEnvelope = normalizeWlanEnvelope(apResult.value, 0, 1);
      envelopes.push(apEnvelope);
    } else {
      errors.push(t('Access Points: {error}', { error: apResult.reason?.message || t('Abfrage fehlgeschlagen') }));
    }
    if (clientResult.status === 'fulfilled') {
      clientEnvelope = normalizeWlanEnvelope(clientResult.value, 0, 1);
      envelopes.push(clientEnvelope);
    } else {
      errors.push(t('Clients: {error}', { error: clientResult.reason?.message || t('Abfrage fehlgeschlagen') }));
    }

    cards[0].querySelector('.wlan-summary-value').textContent = apEnvelope ? String(apEnvelope.total) : '—';
    cards[0].querySelector('.wlan-summary-detail').textContent = apEnvelope
      ? (apEnvelope.complete ? t('Vom Controller gemeldet') : t('Teilresultat'))
      : t('Abfrage fehlgeschlagen');
    cards[1].querySelector('.wlan-summary-value').textContent = clientEnvelope ? String(clientEnvelope.total) : '—';
    cards[1].querySelector('.wlan-summary-detail').textContent = clientEnvelope
      ? (clientEnvelope.complete ? t('Aktuell sichtbar') : t('Teilresultat'))
      : t('Abfrage fehlgeschlagen');

    const timestamps = envelopes
      .map(envelope => envelope.collectedAt)
      .filter(Boolean)
      .sort();
    const newestTimestamp = timestamps.length ? timestamps[timestamps.length - 1] : null;
    cards[3].querySelector('.wlan-summary-value').textContent = formatWlanDate(newestTimestamp);
    cards[3].querySelector('.wlan-summary-detail').textContent = envelopes.some(envelope => envelope.cached)
      ? t('Mindestens ein Wert aus dem Cache')
      : (envelopes.length ? t('Live vom Controller') : t('Keine Daten'));

    const combinedWarnings = envelopes.flatMap(envelope => envelope.warnings);
    if (envelopes.some(envelope => !envelope.complete)) {
      combinedWarnings.unshift(t('Mindestens eine Abfrage lieferte nur Teilergebnisse.'));
    }
    messages.innerHTML = [
      errors.length ? `<div class="wlan-error-box">${errors.map(escapeHtml).join('<br>')}</div>` : '',
      combinedWarnings.length ? `<div class="wlan-warning-box"><strong>${escapeHtml(t('Hinweise zur Abfrage'))}</strong><ul>${combinedWarnings.map(message => `<li>${escapeHtml(message)}</li>`).join('')}</ul></div>` : '',
      `<div class="wlan-overview-source">${escapeHtml(t('Access Points und Clients werden unabhängig voneinander abgefragt. Ein Teilfehler blendet erfolgreiche Daten nicht aus.'))}</div>`,
      `<div style="margin-top:12px"><button id="wlan-overview-refresh" type="button">${escapeHtml(t('Daten neu vom Controller laden'))}</button></div>`,
    ].join('');
    element('wlan-overview-refresh')?.addEventListener('click', () => renderWlanOverview(true));
  }

  function apName(ap) {
    return String(firstValue(ap, ['name', 'ap_name', 'hostname', 'id'], '—'));
  }

  function formatRadios(radios) {
    if (!radios) return '—';
    if (Array.isArray(radios)) {
      if (radios.length === 0) return '—';
      return radios.map(radio => {
        if (typeof radio === 'string' || typeof radio === 'number') return String(radio);
        const band = radioBand(radio) ? `${radioBand(radio)} GHz` : firstValue(radio, ['band', 'radio_type', 'type', 'slot']);
        const channel = firstValue(radio, ['channel', 'channel_number']);
        return [band, channel ? t('Kanal {channel}', { channel }) : null].filter(Boolean).join(' · ') || t('Radio');
      }).join(', ');
    }
    return typeof radios === 'object'
      ? Object.entries(radios).map(([key, value]) => `${key}: ${value}`).join(', ')
      : String(radios);
  }

  function wlanStatus(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized) return { css: 'unknown', label: t('Unbekannt') };
    if ([
      'up',
      'connected',
      'registered',
      'joined',
      'run',
      'active',
      'associated',
      'client-status-associated',
      'client-status-run',
    ].includes(normalized)) {
      return { css: 'ok', label: String(value || t('Aktiv')) };
    }
    if (['down', 'disconnected', 'failed', 'error', 'not_registered', 'not registered'].includes(normalized)) {
      return { css: 'error', label: String(value || t('Nicht verbunden')) };
    }
    return { css: 'warning', label: String(value || t('Unbekannt')) };
  }

  function renderAccessPointTab() {
    const state = wlanTableState.accessPoints;
    element('wlan-tab-content').innerHTML = `
      <div class="panel-box">
        <div class="wlan-toolbar">
          <form id="wlan-ap-search-form" role="search">
            <div class="wlan-filter-field"><label for="wlan-ap-search">${escapeHtml(t('Access Points durchsuchen'))}</label><input id="wlan-ap-search" type="search" maxlength="100" value="${escapeHtml(state.q)}" placeholder="${escapeHtml(t('Name, MAC, IP, Modell …'))}"></div>
            <div class="wlan-filter-field"><label for="wlan-ap-status">${escapeHtml(t('Status'))}</label><input id="wlan-ap-status" list="wlan-ap-status-options" maxlength="100" value="${escapeHtml(state.status)}" placeholder="${escapeHtml(t('Alle Status'))}"><datalist id="wlan-ap-status-options"><option value="registered"><option value="up"><option value="down"><option value="unknown"></datalist></div>
            <button type="submit">${escapeHtml(t('Suchen'))}</button>
            <button id="wlan-ap-search-reset" type="button">${escapeHtml(t('Zurücksetzen'))}</button>
          </form>
          <button id="wlan-ap-refresh" type="button">${escapeHtml(t('Neu vom Controller laden'))}</button>
        </div>
        <div id="wlan-ap-results"><div class="empty-state" role="status">${escapeHtml(t('Lade Access Points …'))}</div></div>
      </div>`;
    element('wlan-ap-search-form').addEventListener('submit', event => {
      event.preventDefault();
      state.q = element('wlan-ap-search').value.trim();
      state.status = element('wlan-ap-status').value.trim();
      state.offset = 0;
      loadAccessPoints();
    });
    element('wlan-ap-search-reset').addEventListener('click', () => {
      element('wlan-ap-search').value = '';
      element('wlan-ap-status').value = '';
      state.q = '';
      state.status = '';
      state.offset = 0;
      loadAccessPoints();
    });
    element('wlan-ap-refresh').addEventListener('click', () => loadAccessPoints(true));
    loadAccessPoints();
  }

  async function loadAccessPoints(forceRefresh = false) {
    const controller = selectedWlanController();
    const container = element('wlan-ap-results');
    if (!controller || !container) return;
    const state = wlanTableState.accessPoints;
    const refreshButton = element('wlan-ap-refresh');
    if (forceRefresh && refreshButton?.disabled) return;
    const controllerId = controller.id;
    const sequence = ++wlanDataSequence;
    const refreshButtonLabel = t('Neu vom Controller laden');
    if (refreshButton) {
      refreshButton.disabled = true;
      if (forceRefresh) refreshButton.textContent = t('Lade neu …');
    }
    container.innerHTML = `<div class="empty-state" role="status">${escapeHtml(t('Lade Access Points …'))}</div>`;
    const params = new URLSearchParams({
      offset: String(state.offset),
      limit: String(PAGE_SIZE),
    });
    if (state.q) params.set('q', state.q);
    if (state.status) params.set('status', state.status);
    if (forceRefresh) params.set('refresh', 'true');

    try {
      const payload = await api(`${WLAN_API}/${encodeControllerId(controllerId)}/access-points?${params}`);
      if (!dataRequestIsCurrent(sequence, controllerId, 'access-points')) return;
      const envelope = normalizeWlanEnvelope(payload, state.offset, PAGE_SIZE);
      state.offset = envelope.offset;
      if (envelope.items.length === 0 && envelope.offset > 0 && envelope.total <= envelope.offset) {
        state.offset = 0;
        loadAccessPoints(false);
        return;
      }
      renderAccessPointResults(container, envelope);
    } catch (error) {
      if (!dataRequestIsCurrent(sequence, controllerId, 'access-points')) return;
      container.innerHTML = `
        <div class="wlan-error-box">${escapeHtml(t('Access Points konnten nicht geladen werden: {error}', { error: error.message }))}</div>
        <button id="wlan-ap-retry" type="button">${escapeHtml(t('Erneut versuchen'))}</button>`;
      element('wlan-ap-retry')?.addEventListener('click', () => loadAccessPoints(forceRefresh));
    } finally {
      if (dataRequestIsCurrent(sequence, controllerId, 'access-points') && refreshButton?.isConnected) {
        refreshButton.disabled = false;
        refreshButton.textContent = refreshButtonLabel;
      }
    }
  }

  function renderAccessPointResults(container, envelope) {
    const rows = envelope.items.map((ap, index) => {
      const name = apName(ap);
      const state = wlanStatus(firstValue(ap, ['state', 'status', 'oper_state']));
      const baseMac = firstValue(ap, ['base_mac', 'mac', 'mac_address'], '—');
      const ip = firstValue(ap, ['ip', 'ip_address', 'management_ip'], '—');
      const model = firstValue(ap, ['model', 'model_number', 'ap_model'], '—');
      const serial = firstValue(ap, ['serial', 'serial_number']);
      const location = firstValue(ap, ['location', 'site', 'site_name'], '—');
      const siteTag = firstValue(ap, ['site_tag', 'siteTag']);
      const rawClientCount = firstValue(ap, ['client_count', 'clients', 'associated_clients']);
      const clientCount = rawClientCount === null ? '—' : finiteInteger(rawClientCount, 0);
      const apFilter = name !== '—' ? name : String(baseMac === '—' ? '' : baseMac);
      const clientCell = apFilter
        ? `<button class="link-button wlan-ap-clients" type="button" data-row-index="${index}">${escapeHtml(clientCount)}</button>`
        : escapeHtml(clientCount);
      return `
        <tr>
          <td><button class="link-button wlan-ap-detail" type="button" data-row-index="${index}">${escapeHtml(name)}</button></td>
          <td><span class="wlan-status ${escapeHtml(state.css)}">${escapeHtml(state.label)}</span></td>
          <td>${escapeHtml(ip)}</td>
          <td>${escapeHtml(baseMac)}</td>
          <td>${escapeHtml(model)}${serial ? `<div class="wlan-cell-subtle">S/N ${escapeHtml(serial)}</div>` : ''}</td>
          <td>${escapeHtml(location)}${siteTag ? `<div class="wlan-cell-subtle">${escapeHtml(t('Site-Tag: {tag}', { tag: siteTag }))}</div>` : ''}</td>
          <td>${escapeHtml(formatRadios(ap.radios))}</td>
          <td>${clientCell}</td>
        </tr>`;
    }).join('');

    container.innerHTML = `
      ${envelopeWarnings(envelope)}
      ${envelopeMeta(envelope)}
      ${envelope.items.length === 0
        ? `<div class="empty-state">${wlanTableState.accessPoints.q ? escapeHtml(t('Keine Access Points entsprechen der Suche.')) : escapeHtml(t('Der Controller meldet keine Access Points.'))}</div>`
        : `<div class="wlan-table-wrap"><table aria-label="${escapeHtml(t('Access Points'))}">
            <thead><tr><th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('IP-Adresse'))}</th><th>${escapeHtml(t('Base-MAC'))}</th><th>${escapeHtml(t('Modell'))}</th><th>${escapeHtml(t('Standort'))}</th><th>${escapeHtml(t('Radios'))}</th><th>${escapeHtml(t('Clients'))}</th></tr></thead>
            <tbody>${rows}</tbody>
          </table></div>`}`;
    container.querySelectorAll('.wlan-ap-clients').forEach(button => {
      button.addEventListener('click', () => {
        const ap = envelope.items[Number(button.dataset.rowIndex)];
        wlanTableState.clients.ap = apName(ap) !== '—'
          ? apName(ap)
          : String(firstValue(ap, ['base_mac', 'mac', 'mac_address'], ''));
        wlanTableState.clients.q = '';
        wlanTableState.clients.offset = 0;
        showWlanTab('clients');
      });
    });
    container.querySelectorAll('.wlan-ap-detail').forEach(button => {
      button.addEventListener('click', () => openWlanApDetail(envelope.items[Number(button.dataset.rowIndex)]));
    });
    renderPagination(container, envelope, offset => {
      wlanTableState.accessPoints.offset = offset;
      loadAccessPoints();
    });
  }

  function renderClientTab() {
    const state = wlanTableState.clients;
    element('wlan-tab-content').innerHTML = `
      <div class="panel-box">
        <div class="wlan-toolbar">
          <form id="wlan-client-search-form" role="search">
            <div class="wlan-filter-field"><label for="wlan-client-search">${escapeHtml(t('Clients durchsuchen'))}</label><input id="wlan-client-search" type="search" maxlength="100" value="${escapeHtml(state.q)}" placeholder="${escapeHtml(t('MAC, IP, Benutzer, SSID …'))}"></div>
            <div class="wlan-filter-field"><label for="wlan-client-ap-filter">${escapeHtml(t('Access Point'))}</label><input id="wlan-client-ap-filter" type="search" maxlength="100" value="${escapeHtml(state.ap)}" placeholder="${escapeHtml(t('AP-Name oder MAC'))}"></div>
            <div class="wlan-filter-field"><label for="wlan-client-ssid-filter">${escapeHtml(t('SSID'))}</label><input id="wlan-client-ssid-filter" type="search" maxlength="100" value="${escapeHtml(state.ssid)}" placeholder="${escapeHtml(t('Alle SSIDs'))}"></div>
            <button type="submit">${escapeHtml(t('Filtern'))}</button>
            <button id="wlan-client-search-reset" type="button">${escapeHtml(t('Zurücksetzen'))}</button>
          </form>
          <button id="wlan-client-refresh" type="button">${escapeHtml(t('Neu vom Controller laden'))}</button>
        </div>
        <div id="wlan-client-results"><div class="empty-state" role="status">${escapeHtml(t('Lade Clients …'))}</div></div>
      </div>`;
    element('wlan-client-search-form').addEventListener('submit', event => {
      event.preventDefault();
      state.q = element('wlan-client-search').value.trim();
      state.ap = element('wlan-client-ap-filter').value.trim();
      state.ssid = element('wlan-client-ssid-filter').value.trim();
      state.offset = 0;
      loadWlanClients();
    });
    element('wlan-client-search-reset').addEventListener('click', () => {
      element('wlan-client-search').value = '';
      element('wlan-client-ap-filter').value = '';
      element('wlan-client-ssid-filter').value = '';
      state.q = '';
      state.ap = '';
      state.ssid = '';
      state.offset = 0;
      loadWlanClients();
    });
    element('wlan-client-refresh').addEventListener('click', () => loadWlanClients(true));
    loadWlanClients();
  }

  async function loadWlanClients(forceRefresh = false) {
    const controller = selectedWlanController();
    const container = element('wlan-client-results');
    if (!controller || !container) return;
    const state = wlanTableState.clients;
    const refreshButton = element('wlan-client-refresh');
    if (forceRefresh && refreshButton?.disabled) return;
    const controllerId = controller.id;
    const sequence = ++wlanDataSequence;
    const refreshButtonLabel = t('Neu vom Controller laden');
    if (refreshButton) {
      refreshButton.disabled = true;
      if (forceRefresh) refreshButton.textContent = t('Lade neu …');
    }
    container.innerHTML = `<div class="empty-state" role="status">${escapeHtml(t('Lade Clients …'))}</div>`;
    const params = new URLSearchParams({
      offset: String(state.offset),
      limit: String(PAGE_SIZE),
    });
    if (state.q) params.set('q', state.q);
    if (state.ap) params.set('ap', state.ap);
    if (state.ssid) params.set('ssid', state.ssid);
    if (forceRefresh) params.set('refresh', 'true');

    try {
      const payload = await api(`${WLAN_API}/${encodeControllerId(controllerId)}/clients?${params}`);
      if (!dataRequestIsCurrent(sequence, controllerId, 'clients')) return;
      const envelope = normalizeWlanEnvelope(payload, state.offset, PAGE_SIZE);
      state.offset = envelope.offset;
      if (envelope.items.length === 0 && envelope.offset > 0 && envelope.total <= envelope.offset) {
        state.offset = 0;
        loadWlanClients(false);
        return;
      }
      renderWlanClientResults(container, envelope);
    } catch (error) {
      if (!dataRequestIsCurrent(sequence, controllerId, 'clients')) return;
      container.innerHTML = `
        <div class="wlan-error-box">${escapeHtml(t('Clients konnten nicht geladen werden: {error}', { error: error.message }))}</div>
        <button id="wlan-client-retry" type="button">${escapeHtml(t('Erneut versuchen'))}</button>`;
      element('wlan-client-retry')?.addEventListener('click', () => loadWlanClients(forceRefresh));
    } finally {
      if (dataRequestIsCurrent(sequence, controllerId, 'clients') && refreshButton?.isConnected) {
        refreshButton.disabled = false;
        refreshButton.textContent = refreshButtonLabel;
      }
    }
  }

  function formatDuration(seconds) {
    const total = finiteInteger(seconds, 0);
    if (total < 60) return `${total} s`;
    if (total < 3600) return `${Math.floor(total / 60)} min`;
    if (total < 86400) return `${Math.floor(total / 3600)} h ${Math.floor((total % 3600) / 60)} min`;
    return `${Math.floor(total / 86400)} d ${Math.floor((total % 86400) / 3600)} h`;
  }

  function clientAssociation(client) {
    const duration = firstValue(client, ['connected_seconds', 'association_seconds', 'uptime_seconds']);
    if (duration !== null) return { value: formatDuration(duration), detail: null };
    const since = firstValue(client, ['associated_since', 'connected_since']);
    if (!since) return { value: '—', detail: null };
    const parsed = new Date(since);
    if (Number.isNaN(parsed.getTime())) return { value: String(since), detail: null };
    const elapsedSeconds = Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 1000));
    return { value: formatDuration(elapsedSeconds), detail: t('Seit {date}', { date: formatWlanDate(since) }) };
  }

  function renderWlanClientResults(container, envelope) {
    const rows = envelope.items.map((client, index) => {
      const mac = firstValue(client, ['mac', 'mac_address', 'client_mac'], '—');
      const ipv4 = firstValue(client, ['ipv4', 'ip', 'ip_address'], '—');
      const ipv6 = firstValue(client, ['ipv6', 'ipv6_address']);
      const hostname = firstValue(client, ['hostname', 'device_name'], '—');
      const username = firstValue(client, ['username', 'user']);
      const ap = firstValue(client, ['ap_name', 'access_point', 'ap'], '—');
      const apMac = firstValue(client, ['ap_mac', 'ap_base_mac']);
      const ssid = firstValue(client, ['ssid', 'wlan_name'], '—');
      const wlanId = firstValue(client, ['wlan_id', 'wlan']);
      const vlan = firstValue(client, ['vlan', 'vlan_id'], '—');
      const band = firstValue(client, ['band', 'radio_band'], '—');
      const channel = firstValue(client, ['channel', 'radio_channel']);
      const rssi = firstValue(client, ['rssi', 'signal_strength']);
      const snr = firstValue(client, ['snr', 'signal_to_noise']);
      const state = wlanStatus(firstValue(client, ['state', 'status']));
      const association = clientAssociation(client);
      return `
        <tr>
          <td>${escapeHtml(mac)}</td>
          <td>${escapeHtml(hostname)}${username ? `<div class="wlan-cell-subtle">${escapeHtml(username)}</div>` : ''}</td>
          <td>${escapeHtml(ipv4)}${ipv6 ? `<div class="wlan-cell-subtle">${escapeHtml(ipv6)}</div>` : ''}</td>
          <td><button class="link-button wlan-client-ap-link" type="button" data-row-index="${index}">${escapeHtml(ap)}</button>${apMac ? `<div class="wlan-cell-subtle">${escapeHtml(apMac)}</div>` : ''}</td>
          <td>${escapeHtml(ssid)}${wlanId !== null ? `<div class="wlan-cell-subtle">${escapeHtml(t('WLAN-ID {id}', { id: wlanId }))}</div>` : ''}</td>
          <td>${escapeHtml(vlan)}</td>
          <td>${escapeHtml(band)}${channel !== null ? `<div class="wlan-cell-subtle">${escapeHtml(t('Kanal {channel}', { channel }))}</div>` : ''}</td>
          <td>${rssi !== null ? `${escapeHtml(rssi)} dBm` : '—'}${snr !== null ? `<div class="wlan-cell-subtle">SNR ${escapeHtml(snr)} dB</div>` : ''}</td>
          <td><span class="wlan-status ${escapeHtml(state.css)}">${escapeHtml(state.label)}</span></td>
          <td>${escapeHtml(association.value)}${association.detail ? `<div class="wlan-cell-subtle">${escapeHtml(association.detail)}</div>` : ''}</td>
        </tr>`;
    }).join('');

    const filterDescription = [
      wlanTableState.clients.q ? t('Suche „{value}“', { value: wlanTableState.clients.q }) : '',
      wlanTableState.clients.ap ? t('AP „{value}“', { value: wlanTableState.clients.ap }) : '',
      wlanTableState.clients.ssid ? t('SSID „{value}“', { value: wlanTableState.clients.ssid }) : '',
    ].filter(Boolean).join(', ');
    container.innerHTML = `
      ${envelopeWarnings(envelope)}
      ${envelopeMeta(envelope)}
      ${envelope.items.length === 0
        ? `<div class="empty-state">${filterDescription ? escapeHtml(t('Keine WLAN-Clients für {filter} gefunden.', { filter: filterDescription })) : escapeHtml(t('Der Controller meldet aktuell keine Client-Einträge.'))}</div>`
        : `<div class="wlan-table-wrap"><table aria-label="${escapeHtml(t('Aktuelle WLAN-Clients'))}">
            <thead><tr><th>${escapeHtml(t('MAC-Adresse'))}</th><th>${escapeHtml(t('Gerät / Benutzer'))}</th><th>${escapeHtml(t('IP-Adresse'))}</th><th>${escapeHtml(t('Access Point'))}</th><th>${escapeHtml(t('SSID'))}</th><th>${escapeHtml(t('VLAN'))}</th><th>${escapeHtml(t('Band / Kanal'))}</th><th>${escapeHtml(t('Signal'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Verbunden'))}</th></tr></thead>
            <tbody>${rows}</tbody>
          </table></div>`}`;
    container.querySelectorAll('.wlan-client-ap-link').forEach(button => {
      button.addEventListener('click', () => {
        const client = envelope.items[Number(button.dataset.rowIndex)];
        const key = firstValue(client, ['ap_mac', 'ap_base_mac', 'ap_name', 'access_point', 'ap']);
        if (key) openWlanApDetail({ name: client.ap_name, mac: key });
      });
    });
    renderPagination(container, envelope, offset => {
      wlanTableState.clients.offset = offset;
      loadWlanClients();
    });
  }

  function invalidateWlanConfiguration() {
    wlanConfigurationSequence += 1;
    wlanConfiguration = null;
    closeWlanDeviceModal();
  }

  function configurationCurrent(sequence, controllerId, session) {
    return sequence === wlanConfigurationSequence && currentSession === session
      && isWlanWorkspace() && controllerKey(currentWlanControllerId) === controllerKey(controllerId);
  }

  async function loadWlanConfiguration() {
    const controller = selectedWlanController();
    if (!controller) return;
    const session = currentSession;
    const sequence = ++wlanConfigurationSequence;
    try {
      const snapshot = await api(`${WLAN_API}/${encodeControllerId(controller.id)}/configuration`);
      if (!configurationCurrent(sequence, controller.id, session)) return;
      wlanConfiguration = { ...snapshot, controllerId: controller.id };
      renderWlanCapabilities();
      if (['wlans', 'profiles'].includes(activeWlanTab)) renderWlanConfigurationTab();
      return wlanConfiguration;
    } catch (error) {
      if (!configurationCurrent(sequence, controller.id, session)) return;
      wlanConfiguration = { controllerId: controller.id, error: error.message };
      renderWlanCapabilities();
      if (['wlans', 'profiles'].includes(activeWlanTab)) renderWlanConfigurationTab();
    }
  }

  function configurationCatalog() {
    return Array.isArray(wlanConfiguration?.catalog) ? wlanConfiguration.catalog : [];
  }

  function configurationResource(resource) {
    return configurationCatalog().find(item => item.resource === resource);
  }

  function configurationEntries(resource) {
    const definition = configurationResource(resource);
    const entries = wlanConfiguration?.collections?.[definition?.collection || resource];
    return Array.isArray(entries) ? entries : [];
  }

  function resourceReason(resource) {
    const capabilities = wlanConfiguration?.capabilities || {};
    if (!currentSessionCanEdit()) return t('Lesender Zugriff: Änderungen erfordern Administratorrechte.');
    if (wlanConfiguration?.error) return wlanConfiguration.error;
    if (wlanConfiguration?.complete === false) return t('Die Konfigurationsabfrage ist unvollständig. Vor einer Änderung vollständig neu laden.');
    if (!(capabilities.supported_resources || []).includes(resource)) {
      return capabilities.resource_reasons?.[resource] || t('Diese Funktion wurde für den Controller nicht als unterstützt bestätigt.');
    }
    return '';
  }

  function persistenceText(persistence) {
    if (!persistence) return t('Speicherstand unbekannt');
    const status = persistence.status;
    if (persistence.dirty === true || ['dirty', 'unsaved', 'pending', 'not_saved'].includes(status)) {
      return t('Änderungen dieser Anwendung noch nicht dauerhaft gespeichert');
    }
    if (['saved', 'persisted'].includes(status)) return t('Dauerhaftes Speichern vom Controller bestätigt');
    if (status === 'failed') return t('Dauerhaftes Speichern fehlgeschlagen');
    return persistence.message || t('Kein vollständiger Vergleich zwischen Running und Startkonfiguration verfügbar');
  }

  function renderWlanCapabilities() {
    const container = element('wlan-capabilities');
    if (!container) return;
    if (!wlanConfiguration || wlanConfiguration.error) {
      container.innerHTML = `<span>${escapeHtml(wlanConfiguration?.error || t('Geräteinformationen werden geladen …'))}</span>
        <button id="wlan-config-reload" type="button">${escapeHtml(t('Erneut laden'))}</button>`;
    } else {
      const device = wlanConfiguration.device || {};
      const capabilities = wlanConfiguration.capabilities || {};
      const capabilityLabels = [
        ['writable_running', t('Running schreibbar')], ['candidate', t('Candidate')],
        ['confirmed_commit', t('Confirmed Commit')], ['rollback_on_error', t('Rollback bei Fehler')],
      ];
      const capabilityState = value => (value === true ? t('Ja') : value === false ? t('Nein') : t('Unbekannt'));
      container.innerHTML = `<div class="flex-row"><strong>${escapeHtml(device.model || t('Modell unbekannt'))}</strong>
        <span>IOS XE ${escapeHtml(device.version || t('Version unbekannt'))}</span>
        <span class="wlan-pill ${wlanConfiguration.complete === false ? 'warning' : 'ok'}">${wlanConfiguration.complete === false ? escapeHtml(t('Teilabfrage')) : escapeHtml(t('Konfiguration gelesen'))}</span>
        <button id="wlan-config-reload" type="button">${escapeHtml(t('Konfiguration neu laden'))}</button></div>
        <div class="flex-row wlan-capability-pills">${capabilityLabels.map(([key, label]) =>
          `<span class="wlan-pill ${capabilities[key] === true ? 'ok' : ''}">${escapeHtml(t('{label}: {value}', { label, value: capabilityState(capabilities[key]) }))}</span>`).join('')}</div>
        <div class="wlan-persistence">${escapeHtml(persistenceText(wlanConfiguration.persistence))}
          ${currentSessionCanEdit() ? `<button id="wlan-running-save" type="button" ${resourceReason('save') ? 'disabled' : ''} title="${escapeHtml(resourceReason('save'))}">${escapeHtml(t('Running dauerhaft speichern …'))}</button>` : ''}</div>
        <div class="wlan-cell-subtle">${escapeHtml(t('Stand {date}. Der Speicherstatus verfolgt Änderungen dieser Anwendung; fremde Änderungen können ebenfalls im Running enthalten sein.', { date: formatWlanDate(wlanConfiguration.collected_at) }))}</div>`;
    }
    element('wlan-config-reload')?.addEventListener('click', () => loadWlanConfiguration());
    element('wlan-running-save')?.addEventListener('click', () => openWlanConfigEditor('save', 'rpc', { key: 'controller', values: {} }));
  }

  function configValue(value, field = {}) {
    if (field.secret) return value === undefined || value === null || value === '' ? t('Nicht bekannt / unverändert') : t('Geschützt');
    if (value === null || value === undefined) return t('Unbekannt / nicht explizit konfiguriert');
    if (value === true) return t('Aktiviert');
    if (value === false) return t('Deaktiviert');
    if (Array.isArray(value)) return value.length ? value.map(item => configValue(item)).join(', ') : t('Keine');
    if (typeof value === 'object') return Object.entries(value).map(([key, item]) => `${key}: ${configValue(item)}`).join('; ');
    return String(value);
  }

  function referenceResource(reference) {
    return configurationCatalog().find(item => item.resource === reference || item.collection === reference);
  }

  function configReferenceMarkup(resource, key) {
    const target = configurationEntries(resource).find(entry => entry.key === key);
    return target ? `<button class="link-button wlan-field-reference" data-resource="${escapeHtml(resource)}" data-key="${escapeHtml(key)}" type="button">${escapeHtml(key)}</button>` : escapeHtml(key ?? t('Unbekannt'));
  }

  function configFieldMarkup(field, value) {
    const target = referenceResource(field.reference);
    if (target && value) return configReferenceMarkup(target.resource, value);
    if (field.type === 'mappings' && Array.isArray(value)) {
      return value.map(mapping => `${configReferenceMarkup('wlan', mapping.wlan_profile)} → ${configReferenceMarkup('policy_profile', mapping.policy_profile)}`).join('<br>') || escapeHtml(t('Keine'));
    }
    return escapeHtml(configValue(value, field));
  }

  function renderWlanConfigurationTab() {
    const container = element('wlan-tab-content');
    if (!container) return;
    if (!wlanConfiguration) {
      container.innerHTML = `<div class="panel-box" role="status">${escapeHtml(t('Lade WLANs, Profile und Tags …'))}</div>`;
      return;
    }
    if (wlanConfiguration.error) {
      container.innerHTML = `<div class="wlan-error-box">${escapeHtml(wlanConfiguration.error)}</div>`;
      return;
    }
    const definitions = configurationCatalog().filter(item => item.kind === 'config'
      && (activeWlanTab === 'wlans' ? item.resource === 'wlan' : !['wlan', 'ap_tags'].includes(item.resource)));
    container.innerHTML = `${envelopeWarnings({ complete: wlanConfiguration.complete !== false, warnings: (wlanConfiguration.warnings || []).map(warningText) })}
      <p class="wlan-modal-help">${escapeHtml(t('Konfigurierte Werte aus dem Controller. Fehlende Werte bleiben als unbekannt gekennzeichnet; wirksame und geerbte Radioeinstellungen stehen in den AP-Details.'))}</p>
      ${definitions.map(definition => {
        const entries = configurationEntries(definition.resource);
        const reason = resourceReason(definition.resource);
        const columns = (definition.fields || []).filter(field => !field.secret).slice(0, 5);
        return `<section class="panel-box"><div class="wlan-toolbar"><h3>${escapeHtml(definition.label)}</h3>
          ${currentSessionCanEdit() && definition.operations.includes('create') ? `<button class="wlan-config-create" data-resource="${escapeHtml(definition.resource)}" type="button" ${reason ? 'disabled' : ''} title="${escapeHtml(reason)}">${escapeHtml(t('Neu anlegen …'))}</button>` : ''}</div>
          ${reason ? `<p class="wlan-cell-subtle">${escapeHtml(reason)}</p>` : ''}
          ${entries.length ? `<div class="wlan-table-wrap"><table aria-label="${escapeHtml(definition.label)}"><thead><tr><th>${escapeHtml(definition.key_label || t('Name'))}</th>${columns.map(field => `<th>${escapeHtml(field.label)}</th>`).join('')}</tr></thead><tbody>
          ${entries.map((entry, index) => `<tr><td><button class="link-button wlan-config-open" data-resource="${escapeHtml(definition.resource)}" data-index="${index}" type="button">${escapeHtml(entry.key)}</button></td>${columns.map(field => `<td>${escapeHtml(configValue(entry.values?.[field.name], field))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
          : `<p class="wlan-modal-help">${escapeHtml(t('Keine Objekte in dieser Abfrage vorhanden.'))}</p>`}</section>`;
      }).join('') || `<div class="panel-box">${escapeHtml(t('Für diesen Transport stehen keine Konfigurationsobjekte bereit.'))}</div>`}`;
    container.querySelectorAll('.wlan-config-create').forEach(button => button.addEventListener('click', () => openWlanConfigEditor(button.dataset.resource, 'create')));
    container.querySelectorAll('.wlan-config-open').forEach(button => button.addEventListener('click', () => {
      openWlanConfigObject(button.dataset.resource, configurationEntries(button.dataset.resource)[Number(button.dataset.index)]);
    }));
  }

  function openWlanDeviceModal(title, context = {}) {
    const generation = ++wlanDeviceGeneration;
    wlanDeviceFocusReturn = document.activeElement;
    wlanDeviceContext = { ...context, generation, controllerId: currentWlanControllerId, session: currentSession };
    element('wlan-device-modal-title').textContent = title;
    element('wlan-device-modal-body').innerHTML = '';
    element('wlan-device-modal').classList.remove('hidden');
    element('wlan-device-close').focus();
    return wlanDeviceContext;
  }

  function closeWlanDeviceModal() {
    wlanDeviceGeneration += 1;
    wlanDeviceContext = null;
    const modal = element('wlan-device-modal');
    const wasOpen = modal && !modal.classList.contains('hidden');
    modal?.classList.add('hidden');
    if (element('wlan-device-modal-body')) element('wlan-device-modal-body').innerHTML = '';
    if (wasOpen && wlanDeviceFocusReturn?.isConnected) wlanDeviceFocusReturn.focus();
    wlanDeviceFocusReturn = null;
  }

  function deviceModalCurrent(context, privileged = false) {
    return context === wlanDeviceContext && context.generation === wlanDeviceGeneration
      && context.session === currentSession && isWlanWorkspace()
      && controllerKey(context.controllerId) === controllerKey(currentWlanControllerId)
      && !element('wlan-device-modal').classList.contains('hidden')
      && (!privileged || currentSessionCanEdit());
  }

  function configUsage(resource, key, visited = new Set()) {
    const marker = `${resource}:${key}`;
    if (visited.has(marker)) return { references: [], aps: [] };
    visited.add(marker);
    const references = [];
    const aps = new Map();
    for (const definition of configurationCatalog().filter(item => item.kind === 'config')) {
      for (const entry of configurationEntries(definition.resource)) {
        const usesTarget = (definition.fields || []).some(field => {
          const target = referenceResource(field.reference);
          if (target?.resource !== resource) return false;
          const value = entry.values?.[field.name];
          return Array.isArray(value) ? value.includes(key) : value === key;
        }) || (Array.isArray(entry.values?.mappings) && entry.values.mappings.some(mapping =>
          (resource === 'wlan' && mapping.wlan_profile === key)
          || (resource === 'policy_profile' && mapping.policy_profile === key)));
        if (!usesTarget) continue;
        references.push({ resource: definition.resource, key: entry.key, label: definition.label });
        const nested = configUsage(definition.resource, entry.key, visited);
        nested.aps.forEach(ap => aps.set(ap.radio_mac || ap.mac || ap.name, ap));
      }
    }
    for (const ap of wlanConfiguration?.access_points || []) {
      if ((['policy_tag', 'site_tag', 'rf_tag'].includes(resource) && ap[resource] === key)
          || (resource === 'ap_tags' && ap.ethernet_mac === key)) aps.set(ap.radio_mac || ap.mac || ap.name, ap);
    }
    return { references, aps: [...aps.values()] };
  }

  function openWlanConfigObject(resource, entry) {
    const definition = configurationResource(resource);
    if (!definition || !entry) return;
    openWlanDeviceModal(`${definition.label} · ${entry.key}`);
    const body = element('wlan-device-modal-body');
    const usage = configUsage(resource, entry.key);
    const reason = resourceReason(resource);
    body.innerHTML = `<p class="wlan-modal-help">${escapeHtml(t('Konfiguration auf dem Controller. Unbekannte Werte sind keine bestätigten Standardwerte.'))}</p>
      <dl class="wlan-value-grid">${(definition.fields || []).map(field => `<dt>${escapeHtml(field.label)}</dt><dd>${configFieldMarkup(field, entry.values?.[field.name])}</dd>`).join('')}</dl>
      <h3>${escapeHtml(t('Referenzen'))}</h3><div class="flex-row">${usage.references.map((item, index) => `<button class="link-button wlan-reference" data-index="${index}" type="button">${escapeHtml(item.label)} · ${escapeHtml(item.key)}</button>`).join('') || `<span class="wlan-modal-help">${escapeHtml(t('Keine Verwendung im gelesenen Konfigurationsumfang gefunden.'))}</span>`}</div>
      <h3>${escapeHtml(t('Zugeordnete Access Points'))}</h3><div class="flex-row">${usage.aps.map((ap, index) => `<button class="link-button wlan-object-ap" data-index="${index}" type="button">${escapeHtml(apName(ap))}</button>`).join('') || `<span class="wlan-modal-help">${escapeHtml(t('Keine AP-Zuordnung aus dieser Abfrage bekannt.'))}</span>`}</div>
      ${reason ? `<p class="wlan-warning-box">${escapeHtml(reason)}</p>` : ''}
      <div class="flex-row wlan-dialog-actions">${currentSessionCanEdit() ? ['update', 'clone', 'delete'].filter(operation => definition.operations.includes(operation)).map(operation =>
        `<button class="wlan-object-action ${operation === 'delete' ? 'danger' : ''}" data-operation="${operation}" type="button" ${reason ? 'disabled' : ''}>${escapeHtml(({ update: t('Bearbeiten …'), clone: t('Eigenes Profil ableiten …'), delete: t('Löschen …') })[operation])}</button>`).join('') : ''}</div>`;
    body.querySelectorAll('.wlan-reference').forEach(button => button.addEventListener('click', () => {
      const item = usage.references[Number(button.dataset.index)];
      openWlanConfigObject(item.resource, configurationEntries(item.resource).find(candidate => candidate.key === item.key));
    }));
    body.querySelectorAll('.wlan-field-reference').forEach(button => button.addEventListener('click', () => {
      openWlanConfigObject(button.dataset.resource, configurationEntries(button.dataset.resource).find(entry => entry.key === button.dataset.key));
    }));
    body.querySelectorAll('.wlan-object-ap').forEach(button => button.addEventListener('click', () => openWlanApDetail(usage.aps[Number(button.dataset.index)])));
    body.querySelectorAll('.wlan-object-action').forEach(button => button.addEventListener('click', () => openWlanConfigEditor(resource, button.dataset.operation, entry)));
  }

  async function openWlanApDetail(ap) {
    const context = openWlanDeviceModal(t('Access Point · {name}', { name: apName(ap) }));
    element('wlan-device-modal-body').innerHTML = `<p role="status">${escapeHtml(t('Lade aktuelle AP-Details …'))}</p>`;
    const key = firstValue(ap, ['radio_mac', 'ethernet_mac', 'mac', 'id', 'name']);
    if (!key) {
      renderWlanApDetail(ap, t('Keine eindeutige Kennung für eine aktuelle Detailabfrage vorhanden.'));
      return;
    }
    try {
      const detail = await api(`${WLAN_API}/${encodeControllerId(context.controllerId)}/access-points/${encodeURIComponent(key)}`);
      if (!deviceModalCurrent(context)) return;
      renderWlanApDetail(detail);
    } catch (error) {
      if (!deviceModalCurrent(context)) return;
      renderWlanApDetail(ap, error.message);
    }
  }

  function renderWlanApDetail(ap, readError = '') {
    const body = element('wlan-device-modal-body');
    element('wlan-device-modal-title').textContent = t('Access Point · {name}', { name: apName(ap) });
    const fields = [['name', t('Name')], ['status', t('Status')], ['admin_state', t('Adminstatus')], ['mode', t('Betriebsmodus')], ['ip', t('IP-Adresse')], ['model', t('Modell')], ['serial_number', t('Seriennummer')], ['location', t('Standorttext')], ['ethernet_mac', t('Ethernet-MAC')], ['radio_mac', t('Radio-MAC')], ['client_count', t('Clients')]];
    const unknown = t('Unbekannt');
    const resourceLabel = resource => configurationResource(resource)?.label || resource;
    const actions = ['ap_name', 'ap_location', 'ap_admin', 'ap_mode', 'ap_tags', 'ap_persist_tags', 'ap_restart'];
    const radios = Array.isArray(ap.radios) ? ap.radios : [];
    body.innerHTML = `${readError ? `<div class="wlan-warning-box">${escapeHtml(t('Aktuelle Detailabfrage fehlgeschlagen: {error}. Angezeigt wird der vorherige Datenstand; Aktionen sind gesperrt.', { error: readError }))}</div>` : ''}
      <dl class="wlan-value-grid">${fields.map(([key, label]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(configValue(ap[key]))}</dd>`).join('')}<dt>${escapeHtml(t('Laufzeit'))}</dt><dd>${ap.uptime_seconds == null ? escapeHtml(unknown) : escapeHtml(formatDuration(ap.uptime_seconds))}</dd></dl>
      <h3>${escapeHtml(t('Tags'))}</h3><p class="wlan-modal-help">${escapeHtml(t('Vom Controller gemeldete AP-Zuordnung. Die Tagdetails zeigen zugehörige Profile und WLANs.'))}</p><div class="wlan-ap-tags">${['policy_tag','site_tag','rf_tag'].map(resource => `<div><span class="detail-label">${escapeHtml(configurationResource(resource)?.label || resource.replace('_', ' '))}</span>
        ${ap[resource] ? `<button class="link-button wlan-ap-tag" data-resource="${resource}" type="button">${escapeHtml(ap[resource])}</button>` : `<span>${escapeHtml(unknown)}</span>`}</div>`).join('')}</div>
      <h3>${escapeHtml(t('Radios'))}</h3><p class="wlan-modal-help">${escapeHtml(t('Operative Werte zeigen den aktuellen Funkbetrieb. Profilvererbung und lokale Overrides werden vor Änderungen separat geprüft; Slot und Band stammen vom AP.'))}</p>
      ${radios.length ? `<div class="wlan-table-wrap"><table aria-label="${escapeHtml(t('AP-Radios'))}"><thead><tr><th>${escapeHtml(t('Slot / Band'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Kanal / Breite'))}</th><th>${escapeHtml(t('Leistung'))}</th><th>${escapeHtml(t('Clients'))}</th><th>${escapeHtml(t('Aktionen'))}</th></tr></thead><tbody>${radios.map((radio, index) => `<tr><td>${escapeHtml(radioSlot(radio) ?? unknown)} · ${escapeHtml(radioBand(radio) ? `${radioBand(radio)} GHz` : radio.band || unknown)}</td><td>${escapeHtml(radio.admin_state == null ? t('Adminstatus unbekannt') : configValue(radio.admin_state))}<div class="wlan-cell-subtle">${escapeHtml(t('Betrieb: {state}', { state: radio.state ?? radio.status ?? unknown }))}</div></td><td>${escapeHtml(radio.channel ?? unknown)} / ${escapeHtml(radio.channel_width ?? unknown)}<div class="wlan-cell-subtle">${escapeHtml(radioModeLabel(radio.channel_mode))}</div></td><td>${radio.power_level != null ? escapeHtml(t('Stufe {level}', { level: radio.power_level })) : escapeHtml(radio.tx_power ?? radio.power ?? unknown)}<div class="wlan-cell-subtle">${escapeHtml(radioModeLabel(radio.power_mode))}</div></td><td>${escapeHtml(radio.client_count ?? unknown)}</td><td>${currentSessionCanEdit() ? ['radio_admin','radio_channel','radio_width','radio_power'].map(resource => {
        const reason = readError || resourceReason(resource) || (!ap.radio_mac ? t('Radio-MAC unbekannt') : '') || (radioSlot(radio) == null || !radioBand(radio) ? t('Slot-/Bandzuordnung unbekannt') : '');
        return `<button class="wlan-radio-action" data-resource="${resource}" data-index="${index}" type="button" ${reason ? 'disabled' : ''} title="${escapeHtml(reason)}">${escapeHtml(resourceLabel(resource))}</button>`;
      }).join('') : escapeHtml(t('Lesender Zugriff'))}</td></tr>`).join('')}</tbody></table></div>` : `<p class="wlan-modal-help">${escapeHtml(t('Keine Radioinformationen vorhanden.'))}</p>`}
      <div class="flex-row wlan-dialog-actions"><button id="wlan-detail-clients" type="button">${escapeHtml(t('Clients dieses AP anzeigen'))}</button>${currentSessionCanEdit() ? actions.map(resource => {
        const reason = readError || resourceReason(resource) || (!(resource === 'ap_tags' ? ap.ethernet_mac : ap.radio_mac) ? t('Erforderlicher MAC-Typ nicht bekannt; keine sichere Adressierung möglich.') : '');
        return `<button class="wlan-ap-action ${resource === 'ap_restart' ? 'danger' : ''}" data-resource="${resource}" type="button" ${reason ? 'disabled' : ''} title="${escapeHtml(reason)}">${escapeHtml(resourceLabel(resource))} …</button>`;
      }).join('') : ''}</div>`;
    element('wlan-detail-clients').addEventListener('click', () => {
      wlanTableState.clients.ap = ap.radio_mac || ap.mac || ap.name || '';
      wlanTableState.clients.q = '';
      wlanTableState.clients.ssid = '';
      wlanTableState.clients.offset = 0;
      closeWlanDeviceModal();
      showWlanTab('clients');
    });
    body.querySelectorAll('.wlan-ap-tag').forEach(button => button.addEventListener('click', () => {
      const entry = configurationEntries(button.dataset.resource).find(item => item.key === ap[button.dataset.resource]);
      if (entry) openWlanConfigObject(button.dataset.resource, entry);
      else toast(t('Der Tag ist im geladenen Konfigurationsumfang nicht vorhanden. Konfiguration neu laden.'), true);
    }));
    body.querySelectorAll('.wlan-ap-action').forEach(button => button.addEventListener('click', () => {
      const resource = button.dataset.resource;
      const key = resource === 'ap_tags' ? ap.ethernet_mac : ap.radio_mac;
      const entry = resource === 'ap_tags' ? configurationEntries(resource).find(item => item.key === key) : null;
      const values = entry?.values || { ...ap, admin_state: ap.admin_state };
      openWlanConfigEditor(resource, resource === 'ap_tags' ? (entry ? 'update' : 'create') : 'rpc', { key, values }, { ap });
    }));
    body.querySelectorAll('.wlan-radio-action').forEach(button => button.addEventListener('click', () => {
      const radio = radios[Number(button.dataset.index)];
      openWlanConfigEditor(button.dataset.resource, 'rpc', { key: ap.radio_mac, values: radio }, { ap, radio });
    }));
  }

  function fieldOptions(field) {
    const target = referenceResource(field.reference);
    const referenceEntries = target ? configurationEntries(target.resource)
      : (wlanConfiguration?.collections?.[field.reference]
        || (wlanConfiguration?.references?.[field.reference] || []).map(value => ({ key: value, values: {} })));
    return field.reference ? referenceEntries.filter(entry => !field.band || entry.values?.band === field.band)
      .map(entry => ({ value: entry.key, label: entry.values?.name && entry.values.name !== entry.key ? `${entry.key} · ${entry.values.name}` : entry.key }))
      : (field.options || []).map(option => typeof option === 'object' ? option : { value: option, label: option });
  }

  function radioSlot(radio) {
    return radio.slot_id ?? radio.slot;
  }

  function radioModeLabel(mode) {
    return mode === 'auto' ? t('Automatisch / RRM') : mode === 'static' ? t('Lokaler Override') : t('Vererbung / Override unbekannt');
  }

  function rfProfileChannels(band) {
    const radios = (wlanConfiguration?.access_points || []).flatMap(ap => ap.radios || []).filter(radio => radioBand(radio) === band);
    if (!radios.length || radios.some(radio => !radio.supported_channels?.length)) return [];
    return radios[0].supported_channels.filter(channel => radios.every(radio => radio.supported_channels.includes(channel)));
  }

  function radioBand(radio) {
    const normalized = String(radio.band || '').toLowerCase().replace(/ghz|\s/g, '');
    return ({ '2.4': '2.4', '5': '5', '6': '6', 'dot11-2-dot-4--band': '2.4',
      'dot11-5--band': '5', 'dot11-6--band': '6', 'band-2-dot-4-': '2.4', 'band-5-': '5', 'band-6-': '6' })[normalized];
  }

  function selectOptions(options, value, blankLabel = t('Bitte auswählen')) {
    return `<option value="">${escapeHtml(blankLabel)}</option>${options.map(option =>
      `<option value="${escapeHtml(option.value)}" ${String(option.value) === String(value) ? 'selected' : ''}>${escapeHtml(option.label ?? option.value)}</option>`).join('')}`;
  }

  function mappingRowMarkup(type, value = {}) {
    if (type === 'mappings') {
      const wlanOptions = configurationEntries('wlan').map(entry => ({ value: entry.key, label: entry.key }));
      const policyOptions = configurationEntries('policy_profile').map(entry => ({ value: entry.key, label: entry.key }));
      return `<div class="wlan-mapping-row"><select data-mapping-key aria-label="${escapeHtml(t('WLAN-Profil'))}">${selectOptions(wlanOptions, value.wlan_profile, t('WLAN-Profil'))}</select>
        <select data-mapping-value aria-label="${escapeHtml(t('Policy-Profil'))}">${selectOptions(policyOptions, value.policy_profile, t('Policy-Profil'))}</select><button class="wlan-mapping-remove" type="button">${escapeHtml(t('Entfernen'))}</button></div>`;
    }
    return `<div class="wlan-mapping-row"><input data-mapping-key aria-label="${escapeHtml(t('Interface-Name'))}" maxlength="128" placeholder="${escapeHtml(t('Interface-Name'))}" value="${escapeHtml(value.interface_name || '')}">
      <input data-mapping-value aria-label="${escapeHtml(t('VLAN-ID'))}" type="number" min="1" max="4094" placeholder="${escapeHtml(t('VLAN-ID'))}" value="${escapeHtml(value.vlan_id ?? '')}"><button class="wlan-mapping-remove" type="button">${escapeHtml(t('Entfernen'))}</button></div>`;
  }

  function fieldMarkup(field, index, value, context) {
    const id = `wlan-edit-field-${index}`;
    const fixed = context.radio && ['slot_id', 'band'].includes(field.name);
    const supportedValues = context.radio && field.name === 'channel' ? context.radio.supported_channels
      : context.radio && field.name === 'power_level' ? context.radio.supported_power_levels : null;
    const missingRadioChoices = context.radio && ['channel','power_level'].includes(field.name) && !supportedValues?.length;
    const readonly = fixed || field.read_only || field.supported === false || missingRadioChoices || (field.immutable && context.operation === 'update');
    const disabled = readonly ? 'disabled' : '';
    const required = (field.required || (context.resource === 'wlan' && field.name === 'security')) && ['create', 'clone', 'rpc'].includes(context.operation) ? 'required' : '';
    const bounds = `${field.min != null ? `min="${escapeHtml(field.min)}"` : ''} ${field.max != null ? `max="${escapeHtml(field.max)}"` : ''}`;
    let options = supportedValues?.length ? supportedValues.map(item => ({ value: item, label: item })) : fieldOptions(field);
    if (context.radio && field.name === 'width') {
      const widths = (context.radio.supported_channel_widths || []).map(String);
      options = options.filter(option => option.value === 'auto' || widths.includes(option.value) || String(context.radio.channel_width) === option.value);
    }
    if (context.radio && field.name === 'mode') {
      const known = context.resource === 'radio_channel' ? context.radio.supported_channels : context.radio.supported_power_levels;
      if (!known?.length) options = options.filter(option => option.value !== 'static');
    }
    const type = field.type;
    let control;
    if (type === 'boolean' || type === 'bool') {
      control = `<select id="${id}" ${disabled} ${required}>${selectOptions([{ value: 'true', label: t('Aktiviert') }, { value: 'false', label: t('Deaktiviert') }], value, t('Unbekannt / unverändert'))}</select>`;
    } else if (type === 'multiselect') {
      control = `<select id="${id}" multiple size="${Math.max(3, Math.min(options.length, 6))}" ${disabled} ${required}>${options.map(option => `<option value="${escapeHtml(option.value)}" ${(Array.isArray(value) ? value.map(String) : []).includes(String(option.value)) ? 'selected' : ''}>${escapeHtml(option.label)}</option>`).join('')}</select>`;
    } else if (['mappings', 'vlan_mappings'].includes(type)) {
      control = `<div id="${id}" class="wlan-mappings" data-mapping-type="${type}"><div class="wlan-mapping-rows">${(Array.isArray(value) ? value : []).map(row => mappingRowMarkup(type, row)).join('')}</div>
        <button class="wlan-mapping-add" type="button" ${disabled}>${escapeHtml(t('Zuordnung hinzufügen'))}</button></div>`;
    } else if (options.length || field.reference || type === 'enum' || type === 'select') {
      const currentKnown = value == null || options.some(option => String(option.value) === String(value));
      control = `<select id="${id}" ${disabled} ${required}>${selectOptions(options, value, value == null ? t('Unbekannt / unverändert') : t('Bitte auswählen'))}${field.reference && !field.required ? `<option value="__remove_reference__">${escapeHtml(t('Referenz entfernen'))}</option>` : ''}${!currentKnown ? `<option value="${escapeHtml(value)}" selected disabled>${escapeHtml(t('{value} (nicht in den verfügbaren Referenzen)', { value }))}</option>` : ''}</select>`;
    } else {
      const inputType = field.secret ? 'password' : ['integer','number'].includes(type) ? 'number' : 'text';
      const display = field.secret ? '' : type === 'integer_list' && Array.isArray(value) ? value.join(', ') : value ?? '';
      const maxLength = field.max_length ?? (inputType === 'text' || field.secret ? field.max ?? 1024 : null);
      control = `<input id="${id}" type="${inputType}" value="${escapeHtml(display)}" ${disabled} ${required} ${bounds} ${maxLength ? `maxlength="${escapeHtml(maxLength)}"` : ''}
        ${inputType === 'number' ? 'step="1"' : field.min ? `minlength="${escapeHtml(field.min)}"` : ''} autocomplete="${field.secret ? 'new-password' : 'off'}" ${field.secret ? `placeholder="${escapeHtml(t('Leer lassen, um unverändert zu lassen'))}"` : ''}>`;
    }
    return `<div class="field"><label for="${id}">${escapeHtml(field.label)}${required ? ' *' : ''}</label>${control}
      <span class="wlan-field-help">${escapeHtml(field.help || '')}${field.reason ? ` ${escapeHtml(field.reason)}` : ''}${field.secret ? ` ${escapeHtml(t('Der vorhandene Schlüssel wird nicht angezeigt oder übernommen.'))}` : ''}${type === 'integer_list' ? ` ${escapeHtml(t('Werte mit Komma trennen.'))}` : ''}${fixed ? ` ${escapeHtml(t('Fest aus der gemeldeten Slot-/Bandzuordnung.'))}` : ''}</span>
      ${field.immutable && context.operation === 'update' ? `<span class="wlan-field-help">${escapeHtml(t('Unveränderlich. Für einen anderen Wert ein neues Profil ableiten.'))}</span>` : ''}
      ${missingRadioChoices ? `<span class="wlan-field-help">${escapeHtml(t('Für dieses Radio sind keine zulässigen Werte nachgewiesen. Ein individueller Override bleibt gesperrt; Automatisch/RRM ist separat verfügbar.'))}</span>` : ''}
      ${field.reference && !options.length ? `<span class="wlan-field-help">${escapeHtml(t('Keine vorhandenen Referenzen in dieser Abfrage nachgewiesen.'))}</span>` : ''}
      ${!['create','clone'].includes(context.operation) && !field.secret && !fixed ? `<span class="wlan-field-current">${escapeHtml(t('Bisher: {value}', { value: configValue(value, field) }))}</span>` : ''}</div>`;
  }

  function openWlanConfigEditor(resource, operation, entry = { key: '', values: {} }, extra = {}) {
    if (!requireEditPermission()) return;
    const definition = configurationResource(resource);
    const reason = resourceReason(resource);
    if (!definition || reason) {
      toast(reason || t('Für diese Aktion ist kein bestätigter Feldkatalog verfügbar.'), true);
      return;
    }
    if (!definition.operations.includes(operation)) {
      toast(t('Die gewünschte Aktion wird für dieses Objekt nicht unterstützt.'), true);
      return;
    }
    const operationLabels = { create: t('Anlegen'), update: t('Bearbeiten'), clone: t('Ableiten'), delete: t('Löschen'), rpc: t('Ausführen') };
    const context = openWlanDeviceModal(`${definition.label} · ${operationLabels[operation]}`, {
      resource, operation, definition, entry, ...extra, privileged: true,
    });
    renderWlanConfigEditor(context);
  }

  function renderWlanConfigEditor(context) {
    if (!deviceModalCurrent(context, true)) return;
    const { definition, operation, entry, radio } = context;
    const isNew = ['create', 'clone'].includes(operation);
    const values = { ...entry.values, ...context.draftValues };
    if (operation === 'clone' && context.resource === 'wlan' && !context.draftValues) {
      delete values.wlan_id;
      delete values.security;
    }
    if (radio) {
      values.slot_id = radioSlot(radio);
      values.band = radioBand(radio);
      if (context.resource === 'radio_width') values.width = radio.channel_width;
      if (context.resource === 'radio_channel' && !context.draftValues) values.mode = radio.channel_mode;
      if (context.resource === 'radio_power' && !context.draftValues) values.mode = radio.power_mode;
    }
    context.initialValues = { ...entry.values };
    const fields = operation === 'delete' ? [] : definition.fields || [];
    const body = element('wlan-device-modal-body');
    const target = [controllerName(selectedWlanController()), context.ap ? apName(context.ap) : null].filter(Boolean).join(' · ');
    body.innerHTML = `<p class="wlan-modal-help">${escapeHtml(t('{target}. Zuerst werden aktuelle Werte und Auswirkungen vom Controller geprüft. Änderungen werden erst nach Bestätigung der Vorschau angewendet.', { target }))}</p>
      ${context.resource === 'save' ? `<div class="wlan-warning-box">${escapeHtml(t('Dauerhaftes Speichern umfasst die gesamte laufende Controllerkonfiguration, einschließlich Änderungen anderer Personen. Auf APs gespeicherte Tags sind eine separate Aktion.'))}</div>` : ''}
      ${context.resource === 'ap_persist_tags' ? `<div class="wlan-warning-box">${escapeHtml(t('Diese Aktion speichert die Tags lokal auf diesem AP. Das dauerhafte Speichern der WLC-Konfiguration bleibt eine eigene Aktion.'))}</div>` : ''}
      ${context.resource.startsWith('radio_') ? `<p class="wlan-warning-box">${escapeHtml(t('Individuelle Radioeinstellungen überschreiben gegebenenfalls das RF-Profil. „Automatisch“ gibt die Auswahl an RRM zurück. Die erlaubten Werte werden anhand des Controllers geprüft.'))}</p>` : ''}
      ${operation === 'clone' ? `<p class="wlan-modal-help">${escapeHtml(t('Ausgangsprofil: {key}. {help} Die Zuordnung zu APs oder Tags erfolgt anschließend ausdrücklich.', { key: entry.key, help: definition.clone_help || t('Es werden die hier verwalteten Felder übernommen; weitere Eigenschaften erhalten Controller-Standardwerte.') }))}</p>` : ''}
      ${operation === 'delete' ? `<div class="wlan-warning-box">${escapeHtml(t('Das Objekt wird vom Controller entfernt. Bestehende Referenzen und betroffene Access Points werden vorab geprüft.'))}</div>` : ''}
      <form id="wlan-config-editor"><div class="field"><label for="wlan-edit-key">${escapeHtml(context.resource === 'save' ? t('Controller') : definition.key_label || t('Ziel'))}</label>
        <input id="wlan-edit-key" value="${escapeHtml(context.draftKey ?? (isNew && context.resource !== 'ap_tags' ? '' : entry.key))}" ${!isNew || context.resource === 'ap_tags' ? 'readonly' : ''} required maxlength="128" autocomplete="off"></div>
      <div class="wlan-editor-grid">${fields.map((field, index) => fieldMarkup(field, index, values[field.name], context)).join('')}</div>
      <div id="wlan-config-form-error" class="wlan-form-error" role="alert"></div><div class="flex-row wlan-dialog-actions"><button type="submit" class="primary" id="wlan-config-preview">${escapeHtml(t('Änderung prüfen und Vorschau anzeigen'))}</button></div></form>`;
    body.querySelectorAll('.wlan-mappings').forEach(container => {
      const rows = container.querySelector('.wlan-mapping-rows');
      const wireRemove = row => row.querySelector('.wlan-mapping-remove').addEventListener('click', () => row.remove());
      rows.querySelectorAll('.wlan-mapping-row').forEach(wireRemove);
      container.querySelector('.wlan-mapping-add').addEventListener('click', () => {
        const holder = document.createElement('div');
        holder.innerHTML = mappingRowMarkup(container.dataset.mappingType);
        const row = holder.firstElementChild;
        rows.appendChild(row);
        wireRemove(row);
        row.querySelector('[data-mapping-key]').focus();
      });
    });
    element('wlan-config-editor').addEventListener('submit', event => {
      event.preventDefault();
      previewWlanConfiguration(context);
    });
    const control = name => {
      const index = fields.findIndex(field => field.name === name);
      return index < 0 ? null : element(`wlan-edit-field-${index}`);
    };
    if (context.resource === 'ap_tags') {
      for (const field of fields.filter(candidate => candidate.reference)) {
        const input = control(field.name);
        const summary = document.createElement('div');
        summary.className = 'wlan-reference-summary';
        input.parentElement.appendChild(summary);
        const updateSummary = () => {
          const target = referenceResource(field.reference);
          const chosen = target && configurationEntries(target.resource).find(row => row.key === input.value);
          summary.innerHTML = chosen ? `<strong>${escapeHtml(chosen.key)}</strong><dl class="wlan-value-grid">${(target.fields || []).filter(item => chosen.values?.[item.name] != null && !item.secret).map(item =>
            `<dt>${escapeHtml(item.label)}</dt><dd>${escapeHtml(configValue(chosen.values[item.name], item))}</dd>`).join('')}</dl>`
            : escapeHtml(t('Keine Profilzuordnung für diese Auswahl bekannt.'));
        };
        input.addEventListener('change', updateSummary);
        updateSummary();
      }
    }
    if (context.radio && control('mode')) {
      const updateRadioMode = () => {
        const input = control(context.resource === 'radio_channel' ? 'channel' : 'power_level');
        if (!input) return;
        const known = context.resource === 'radio_channel' ? radio.supported_channels : radio.supported_power_levels;
        input.disabled = control('mode').value !== 'static' || !known?.length;
        input.required = !input.disabled;
      };
      control('mode').addEventListener('change', updateRadioMode);
      updateRadioMode();
    }
    if (context.resource === 'wlan' && control('security')) {
      const updateSecurity = () => {
        const security = control('security').value;
        const changing = ['create','clone'].includes(operation) || security !== entry.values?.security;
        const secret = control('psk');
        const aaa = control('authentication_list');
        if (secret) {
          secret.disabled = !security.includes('personal');
          secret.required = security.includes('personal') && changing;
          if (secret.disabled) secret.value = '';
        }
        if (aaa) {
          aaa.disabled = security.includes('personal');
          aaa.required = security.includes('enterprise') && changing;
        }
      };
      control('security').addEventListener('change', updateSecurity);
      updateSecurity();
    }
    if (context.resource === 'rf_profile' && control('channels')) {
      const updateRfChannels = () => {
        const channels = rfProfileChannels(control('band')?.value);
        control('channels').disabled = channels.length === 0;
        control('channels').title = channels.length
          ? t('Nachgewiesene Kanäle auf allen bekannten Radios dieses Bands: {channels}', { channels: channels.join(', ') })
          : t('Zulässige Kanäle der betroffenen Radios sind unbekannt; individuelle Kanalliste gesperrt.');
        let hint = element('wlan-rf-channel-hint');
        if (!hint) {
          hint = document.createElement('span');
          hint.id = 'wlan-rf-channel-hint';
          hint.className = 'wlan-field-help';
          control('channels').parentElement.appendChild(hint);
        }
        hint.textContent = control('channels').title;
      };
      control('band')?.addEventListener('change', updateRfChannels);
      updateRfChannels();
    }
  }

  function collectWlanConfigValues(context) {
    const values = {};
    if (context.operation === 'delete') return values;
    for (const [index, field] of (context.definition.fields || []).entries()) {
      if (field.read_only || field.supported === false || (field.immutable && context.operation === 'update')) continue;
      const input = element(`wlan-edit-field-${index}`);
      if (input.disabled && !(context.radio && ['slot_id','band'].includes(field.name))) continue;
      let value;
      if (context.radio && field.name === 'slot_id') value = radioSlot(context.radio);
      else if (context.radio && field.name === 'band') value = radioBand(context.radio);
      else if (field.reference && input.value === '__remove_reference__') value = '';
      else if (['mappings', 'vlan_mappings'].includes(field.type)) {
        value = [...input.querySelectorAll('.wlan-mapping-row')].map(row => {
          const key = row.querySelector('[data-mapping-key]').value.trim();
          const target = row.querySelector('[data-mapping-value]').value;
          if (!key || target === '') throw new Error(t('{field}: beide Werte einer Zuordnung sind erforderlich.', { field: field.label }));
          return field.type === 'mappings' ? { wlan_profile: key, policy_profile: target }
            : { interface_name: key, vlan_id: Number(target) };
        });
      } else if (field.type === 'multiselect') value = [...input.selectedOptions].map(option => option.value);
      else if (field.type === 'integer_list') {
        const raw = input.value.trim();
        value = raw ? raw.split(',').map(part => {
          if (!/^\d+$/.test(part.trim())) throw new Error(t('{field}: nur ganze Zahlen mit Komma trennen.', { field: field.label }));
          return Number(part.trim());
        }) : [];
      } else if (field.secret) {
        if (input.value === '') continue;
        value = input.value;
      } else if (['boolean','bool'].includes(field.type)) {
        if (input.value === '') continue;
        value = input.value === 'true';
      } else if (['integer','number'].includes(field.type)) {
        if (input.value === '') continue;
        value = Number(input.value);
        if (!Number.isInteger(value)) throw new Error(t('{field}: eine ganze Zahl ist erforderlich.', { field: field.label }));
      } else {
        value = input.value;
        if (value === '' && (field.reference || field.options?.length || field.type === 'enum')) continue;
        if (value === '' && context.initialValues[field.name] == null) continue;
      }
      if (context.operation === 'update' && !field.secret
          && JSON.stringify(value) === JSON.stringify(context.initialValues[field.name])) continue;
      values[field.name] = value;
    }
    return values;
  }

  async function previewWlanConfiguration(context) {
    if (!deviceModalCurrent(context, true) || context.busy) return;
    const button = element('wlan-config-preview');
    const errorElement = element('wlan-config-form-error');
    errorElement.textContent = '';
    let values;
    try {
      values = collectWlanConfigValues(context);
    } catch (error) {
      errorElement.textContent = error.message;
      return;
    }
    if (context.operation === 'update' && Object.keys(values).length === 0) {
      errorElement.textContent = t('Es wurden keine Felder geändert.');
      return;
    }
    const key = element('wlan-edit-key').value.trim();
    if (!key) {
      errorElement.textContent = t('Eine Zielkennung ist erforderlich.');
      return;
    }
    context.busy = true;
    button.disabled = true;
    context.draftKey = key;
    const secretNames = new Set((context.definition.fields || []).filter(field => field.secret).map(field => field.name));
    context.draftValues = Object.fromEntries(Object.entries(values).filter(([name]) => !secretNames.has(name)));
    try {
      const change = { resource: context.resource, operation: context.operation, key, values };
      if (context.operation === 'clone') change.source_key = context.entry.key;
      const preview = await api(`${WLAN_API}/${encodeControllerId(context.controllerId)}/configuration/preview`, {
        method: 'POST', body: JSON.stringify(change),
      });
      if (!deviceModalCurrent(context, true)) return;
      // The form is destroyed here: credentials are never kept for a second submission.
      renderWlanConfigPreview(context, preview);
    } catch (error) {
      if (!deviceModalCurrent(context, true)) return;
      errorElement.textContent = error.message;
      for (const [index, field] of (context.definition.fields || []).entries()) {
        if (field.secret && element(`wlan-edit-field-${index}`)) element(`wlan-edit-field-${index}`).value = '';
      }
    } finally {
      context.busy = false;
      if (deviceModalCurrent(context, true) && button.isConnected) button.disabled = false;
    }
  }

  function renderWlanConfigPreview(context, preview) {
    const body = element('wlan-device-modal-body');
    const diff = Array.isArray(preview.diff) ? preview.diff : [];
    const warnings = [...(preview.warnings || []), ...(preview.impact?.warnings || [])].map(warningText);
    const affected = preview.impact?.access_points || [];
    const clientCount = preview.impact?.client_count;
    const previewTarget = [controllerName(selectedWlanController()), context.definition.label, preview.change?.key ?? context.entry.key].join(' · ');
    const clientImpact = clientCount == null ? t('Clientanzahl unbekannt') : t('{count} Clients', { count: clientCount });
    body.innerHTML = `<p class="wlan-modal-help">${escapeHtml(t('Vorschau für {target}. Die Vorschau reserviert keine Konfiguration; unmittelbar vor dem Schreiben prüft der Server den Ausgangsstand erneut.', { target: previewTarget }))}</p>
      <div class="wlan-table-wrap"><table aria-label="${escapeHtml(t('Änderungsvorschau'))}"><thead><tr><th>${escapeHtml(t('Feld'))}</th><th>${escapeHtml(t('Bisher'))}</th><th>${escapeHtml(t('Danach'))}</th></tr></thead><tbody>${diff.map(item => {
        const field = (context.definition.fields || []).find(candidate => candidate.name === item.field) || {};
        return `<tr><th>${escapeHtml(item.label || field.label || item.field)}</th><td>${escapeHtml(configValue(item.before, field))}</td><td>${context.operation === 'delete' ? escapeHtml(t('Wird entfernt')) : escapeHtml(configValue(item.after, field))}</td></tr>`;
      }).join('') || `<tr><td colspan="3">${escapeHtml(t('Betriebsaktion ohne konfigurierbares Wertefeld.'))}</td></tr>`}</tbody></table></div>
      <h3>${escapeHtml(t('Auswirkungen'))}</h3><p>${escapeHtml(t('{count} betroffene Access Points · {clients}', { count: affected.length, clients: clientImpact }))}</p>
      <p class="wlan-affected-list">${affected.map(ap => escapeHtml(typeof ap === 'string' ? ap : apName(ap))).join(', ') || escapeHtml(t('Keine AP-Zuordnung in der Vorschau bekannt.'))}</p>
      ${warnings.length ? `<div class="wlan-warning-box"><ul>${warnings.map(message => `<li>${escapeHtml(message)}</li>`).join('')}</ul></div>` : ''}
      <p class="wlan-modal-help">${escapeHtml(t('{persistence}. Anwenden und dauerhaftes Speichern sind getrennte Schritte.', { persistence: persistenceText(preview.persistence) }))}</p>
      <p class="wlan-cell-subtle">${escapeHtml(t('Vorschau gültig bis {date}.', { date: formatWlanDate(preview.expires_at) }))}</p>
      <label class="wlan-confirm"><input id="wlan-config-confirm" type="checkbox"> ${escapeHtml(t('Ich habe Ziel, Werte und Auswirkungen geprüft und möchte diese Aktion ausführen.'))}</label>
      <div id="wlan-config-apply-error" class="wlan-form-error" role="alert"></div>
      <div class="flex-row wlan-dialog-actions"><button id="wlan-config-back" type="button">${escapeHtml(t('Eingaben erneut bearbeiten'))}</button><button id="wlan-config-apply" class="${['ap_restart','save'].includes(context.resource) || context.operation === 'delete' ? 'danger' : 'primary'}" type="button" disabled>${escapeHtml(t('Jetzt auf dem Controller anwenden'))}</button></div>`;
    element('wlan-config-back').addEventListener('click', () => renderWlanConfigEditor(context));
    element('wlan-config-confirm').addEventListener('change', () => {
      element('wlan-config-apply').disabled = !element('wlan-config-confirm').checked || !preview.preview_token;
    });
    element('wlan-config-apply').addEventListener('click', () => applyWlanConfiguration(context, preview));
  }

  async function applyWlanConfiguration(context, preview) {
    if (!deviceModalCurrent(context, true) || context.submitted || !preview.preview_token
        || !element('wlan-config-confirm').checked) return;
    context.submitted = true;
    element('wlan-config-apply').disabled = true;
    element('wlan-config-back').disabled = true;
    element('wlan-config-confirm').disabled = true;
    element('wlan-config-apply-error').textContent = t('Aktion läuft. Das Ergebnis wird anschließend vom Controller geprüft …');
    let result;
    try {
      result = await api(`${WLAN_API}/${encodeControllerId(context.controllerId)}/configuration/apply`, {
        method: 'POST', body: JSON.stringify({ preview_token: preview.preview_token }),
      });
    } catch (error) {
      result = { status: error.status && error.status < 500 ? 'rejected' : 'unknown',
        message: error.message, verified: false };
    }
    if (!deviceModalCurrent(context, true)) return;
    renderWlanConfigResult(context, result);
    loadWlanConfiguration();
  }

  function wlanVerificationText(context, result) {
    const labels = {
      matched: t('Zielzustand durch Rücklesen bestätigt.'),
      acknowledged: context.resource === 'save'
        ? t('Speicher-RPC vom Controller bestätigt; kein separater Vergleich mit der Startkonfiguration.')
        : t('Aktion vom Controller bestätigt; Zielzustand nicht separat zurückgelesen.'),
      secret_unverifiable: t('Lesbare Werte bestätigt; geheime Schlüssel können nicht zurückgelesen werden.'),
      mismatch: t('Zurückgelesene Gerätewerte weichen vom angeforderten Zielzustand ab.'),
      unavailable: t('Aktuelle Gerätewerte bzw. Aktionsabschluss konnten nicht geprüft werden.'),
      pending: t('Abschluss bzw. Zielzustand noch nicht bestätigt.'),
      matched_after_unknown: t('Zielwerte nach unklarem Ausgang am Gerät sichtbar; die ursprüngliche Ausführung bleibt unbestätigt.'),
      observed_after_unknown: t('Aktuelle AP-Werte nach unklarem Ausgang gelesen; der Aktionsabschluss bleibt unbestätigt.'),
      different_after_unknown: t('Nach unklarem Ausgang gelesene Gerätewerte bestätigen den angeforderten Zielzustand nicht.'),
      incomplete_after_unknown: t('Nach unklarem Ausgang nur unvollständige Gerätewerte verfügbar; keine vollständige Bestätigung.'),
    };
    return labels[result.verification] || t('Prüfergebnis nicht eindeutig verfügbar.');
  }

  function renderWlanConfigResult(context, result) {
    const labels = { applied: t('Angewendet'), rejected: t('Abgelehnt'), partial: t('Teilweise angewendet'), unknown: t('Ausgang unbekannt') };
    const status = Object.hasOwn(labels, result.status) ? result.status : 'unknown';
    element('wlan-device-modal-body').innerHTML = `<div class="${status === 'applied' ? 'wlan-result-ok' : 'wlan-warning-box'}" role="status"><h3>${escapeHtml(labels[status])}</h3><p>${escapeHtml(result.message || t('Der Controller lieferte keine zusätzliche Nachricht.'))}</p></div>
      ${result.warnings?.length ? `<div class="wlan-warning-box"><ul>${result.warnings.map(warning => `<li>${escapeHtml(warningText(warning))}</li>`).join('')}</ul></div>` : ''}
      <dl class="wlan-value-grid"><dt>${escapeHtml(t('Prüfung'))}</dt><dd>${escapeHtml(wlanVerificationText(context, result))}</dd><dt>${escapeHtml(t('Speicherstand'))}</dt><dd>${escapeHtml(persistenceText(result.persistence))}</dd><dt>${escapeHtml(t('Änderungs-ID'))}</dt><dd>${escapeHtml(result.change_id || t('Nicht verfügbar'))}</dd></dl>
      ${['unknown', 'partial'].includes(status) ? `<p class="wlan-warning-box">${escapeHtml(t('Die Aktion wird nicht automatisch wiederholt. Zuerst aktuelle Werte laden und den tatsächlichen Zustand prüfen; eine teilweise Ausführung kann bereits Auswirkungen haben.'))}</p>` : ''}
      <div class="flex-row wlan-dialog-actions"><button id="wlan-result-refresh" type="button">${escapeHtml(t('Aktuellen Zustand laden'))}</button><button id="wlan-result-close" type="button">${escapeHtml(t('Schließen'))}</button></div>`;
    element('wlan-result-close').addEventListener('click', closeWlanDeviceModal);
    element('wlan-result-refresh').addEventListener('click', async () => {
      if (context.ap) {
        openWlanApDetail(context.ap);
      } else {
        closeWlanDeviceModal();
        await loadWlanConfiguration();
      }
    });
  }

  function normalizeWlanPlatformCatalog(payload) {
    const rawPlatforms = Array.isArray(payload) ? payload : payload?.items;
    if (!Array.isArray(rawPlatforms)) return FALLBACK_WLAN_PLATFORMS;
    const platforms = rawPlatforms.map(platform => {
      if (!platform || typeof platform !== 'object' || Array.isArray(platform)) return null;
      const id = typeof platform.id === 'string' ? platform.id.trim() : '';
      if (!id) return null;
      const rawTransports = Array.isArray(platform.transports) ? platform.transports : [];
      const transports = rawTransports.map(transport => {
        if (!transport || typeof transport !== 'object' || Array.isArray(transport)) return null;
        const rawTransportId = typeof transport.id === 'string' ? transport.id.trim() : '';
        if (!rawTransportId) return null;
        const transportId = normalizeTransportId(rawTransportId);
        const rawPort = Number(transport.default_port);
        const rawLabel = typeof transport.label === 'string' ? transport.label.trim() : '';
        return {
          id: transportId,
          label: transportId === 'netconf' && rawLabel === 'NETCONF (SSH)'
            ? 'NETCONF (SSH/YANG)'
            : (rawLabel || transportId.toUpperCase()),
          default_port: Number.isInteger(rawPort) && rawPort >= 1 && rawPort <= 65535
            ? rawPort
            : (transportId === 'netconf' ? 830 : 443),
        };
      }).filter(Boolean);
      const fallback = FALLBACK_WLAN_PLATFORMS.find(entry => entry.id === id);
      const rawLabel = typeof platform.label === 'string' ? platform.label.trim() : '';
      const isLegacyRestconfLabel = id === 'catalyst_9800'
        && transports.length === 0
        && /restconf/i.test(rawLabel);
      return {
        id,
        label: rawLabel && !isLegacyRestconfLabel ? rawLabel : (fallback?.label || rawLabel || id),
        // Ältere Backends liefern nur id/label. Beide heute unterstützten
        // Transportwege bleiben dann trotzdem auswählbar.
        transports: transports.length ? transports : (fallback?.transports || DEFAULT_WLAN_TRANSPORTS),
      };
    }).filter(Boolean);
    return platforms.length ? platforms : FALLBACK_WLAN_PLATFORMS;
  }

  function updateWlanTransportHelp() {
    const platform = element('wlan-controller-platform').value || 'catalyst_9800';
    const transport = normalizeTransportId(element('wlan-controller-transport').value);
    const defaultPort = transportDefaultPort(platform, transport);
    element('wlan-controller-transport-help').textContent = transport === 'netconf'
      ? t('NETCONF nutzt SSH und YANG und standardmäßig Port {port}. Ein eigener Port bleibt beim Transportwechsel erhalten.', { port: defaultPort })
      : transport === 'restconf'
        ? t('RESTCONF nutzt HTTPS und standardmäßig Port {port}. Ein eigener Port bleibt beim Transportwechsel erhalten.', { port: defaultPort })
        : t('{transport} und standardmäßig Port {port}. Ein eigener Port bleibt beim Transportwechsel erhalten.', { transport: transportLabel(transport, platform), port: defaultPort });
  }

  function renderWlanTransportOptions(platform, preferredTransport) {
    const select = element('wlan-controller-transport');
    const requestedTransport = normalizeTransportId(preferredTransport);
    const transports = [...transportsForPlatform(platform)];
    select.innerHTML = transports.map(transport => `
      <option value="${escapeHtml(transport.id)}">${escapeHtml(transport.label)}</option>`).join('');
    select.value = requestedTransport;
    if (!select.value && transports.length) select.value = transports[0].id;
    return normalizeTransportId(select.value);
  }

  function updatePortForTransportChange(previousPlatform, previousTransport, nextPlatform, nextTransport) {
    const portField = element('wlan-controller-port');
    const currentPortText = portField.value.trim();
    const previousDefault = transportDefaultPort(previousPlatform, previousTransport);
    if (!currentPortText || Number(currentPortText) === previousDefault) {
      portField.value = String(transportDefaultPort(nextPlatform, nextTransport));
    }
  }

  function handleWlanPlatformChange() {
    const nextPlatform = element('wlan-controller-platform').value;
    const previousPlatform = wlanControllerSelectedPlatform;
    const previousTransport = wlanControllerSelectedTransport;
    const nextTransport = renderWlanTransportOptions(nextPlatform, previousTransport);
    updatePortForTransportChange(
      previousPlatform,
      previousTransport,
      nextPlatform,
      nextTransport,
    );
    wlanControllerSelectedPlatform = nextPlatform;
    wlanControllerSelectedTransport = nextTransport;
    updateWlanTransportHelp();
  }

  function handleWlanTransportChange() {
    const platform = element('wlan-controller-platform').value;
    const nextTransport = normalizeTransportId(element('wlan-controller-transport').value);
    updatePortForTransportChange(
      wlanControllerSelectedPlatform,
      wlanControllerSelectedTransport,
      platform,
      nextTransport,
    );
    wlanControllerSelectedPlatform = platform;
    wlanControllerSelectedTransport = nextTransport;
    updateWlanTransportHelp();
  }

  async function loadWlanPlatforms(
    selectedPlatform = 'catalyst_9800',
    selectedTransport = 'restconf',
    modalGeneration = wlanControllerModalGeneration,
    editingId = editingWlanControllerId,
    sessionAtStart = currentSession,
  ) {
    let platforms = FALLBACK_WLAN_PLATFORMS;
    try {
      platforms = normalizeWlanPlatformCatalog(await api('/api/wlan/platforms'));
    } catch {
      // Der 9800-Adapter und beide Transporte bleiben auch mit älteren
      // Backends oder bei einem vorübergehenden Metadatenfehler auswählbar.
    }
    const select = element('wlan-controller-platform');
    if (!select || !wlanControllerModalIsCurrent(
      modalGeneration,
      editingId,
      sessionAtStart,
    )) return;
    const currentPlatform = select.value || selectedPlatform;
    const currentTransport = element('wlan-controller-transport').value || selectedTransport;
    wlanPlatformCatalog = platforms;
    if (!platforms.some(platform => platform.id === currentPlatform)) {
      platforms = [...platforms, {
        id: currentPlatform,
        label: platformLabel(currentPlatform),
        transports: DEFAULT_WLAN_TRANSPORTS,
      }];
    }
    select.innerHTML = platforms.map(platform => `
      <option value="${escapeHtml(platform.id)}">${escapeHtml(platform.label || platformLabel(platform.id))}</option>`).join('');
    select.value = currentPlatform;
    if (!select.value && platforms.length) select.value = platforms[0].id;
    wlanControllerSelectedPlatform = select.value;
    wlanControllerSelectedTransport = renderWlanTransportOptions(
      wlanControllerSelectedPlatform,
      currentTransport,
    );
    updateWlanTransportHelp();
  }

  function openWlanControllerModal(controller = null) {
    if (!requireEditPermission()) return;
    const sessionAtStart = currentSession;
    const modalGeneration = ++wlanControllerModalGeneration;
    wlanControllerSaveSequence += 1;
    wlanControllerRevisionConflict = false;
    editingWlanControllerId = controller?.id ?? null;
    editingWlanControllerSnapshot = controller ? { ...controller } : null;
    const selectedPlatform = String(controller?.platform || 'catalyst_9800');
    const selectedTransport = controllerTransport(controller);
    wlanTestConnectionSequence += 1;
    element('wlan-controller-modal-title').textContent = controller
      ? t('WLAN-Controller bearbeiten')
      : t('WLAN-Controller hinzufügen');
    element('wlan-controller-name').value = controller ? controllerName(controller) : '';
    element('wlan-controller-host').value = controller ? controllerHost(controller).replace(/^—$/, '') : '';
    element('wlan-controller-port').value = controllerPort(controller);
    element('wlan-controller-site').value = controller?.site || '';
    element('wlan-controller-notes').value = controller?.notes || '';
    element('wlan-controller-edit-credentials')?.classList.toggle('hidden', !controller);
    if (element('wlan-controller-credentials-help')) {
      element('wlan-controller-credentials-help').textContent = !controller
        ? t('Neue Controller verwenden zunächst die globalen Zugangsdaten. Eigene Zugangsdaten lassen sich nach dem Anlegen festlegen.')
        : controllerCredentialsMode(controller) === 'device'
          ? t('Dieser Controller verwendet eigene Zugangsdaten. Zugangsdaten werden separat bearbeitet. Änderungen an diesem Formular zuerst speichern.')
          : t('Dieser Controller verwendet die globalen Zugangsdaten. Zugangsdaten werden separat bearbeitet. Änderungen an diesem Formular zuerst speichern.');
    }
    let visiblePlatforms = wlanPlatformCatalog;
    if (!visiblePlatforms.some(platform => platform.id === selectedPlatform)) {
      visiblePlatforms = [...visiblePlatforms, {
        id: selectedPlatform,
        label: platformLabel(selectedPlatform),
        transports: DEFAULT_WLAN_TRANSPORTS,
      }];
    }
    element('wlan-controller-platform').innerHTML = visiblePlatforms.map(platform => `
      <option value="${escapeHtml(platform.id)}">${escapeHtml(platform.label)}</option>`).join('');
    element('wlan-controller-platform').value = selectedPlatform;
    wlanControllerSelectedPlatform = selectedPlatform;
    wlanControllerSelectedTransport = renderWlanTransportOptions(selectedPlatform, selectedTransport);
    updateWlanTransportHelp();
    element('wlan-controller-modal-error').textContent = '';
    element('wlan-controller-save').disabled = false;
    element('wlan-controller-modal').classList.remove('hidden');
    loadWlanPlatforms(
      selectedPlatform,
      selectedTransport,
      modalGeneration,
      editingWlanControllerId,
      sessionAtStart,
    );
    element('wlan-controller-name').focus();
  }

  function closeWlanControllerModal() {
    const reloadAfterRevisionConflict = wlanControllerRevisionConflict;
    wlanControllerModalGeneration += 1;
    wlanControllerSaveSequence += 1;
    wlanControllerRevisionConflict = false;
    editingWlanControllerId = null;
    editingWlanControllerSnapshot = null;
    element('wlan-controller-modal-error').textContent = '';
    element('wlan-controller-modal').classList.add('hidden');
    if (reloadAfterRevisionConflict && currentSession && isWlanWorkspace()) {
      loadWlanControllers({ keepTab: true });
    }
  }

  function wlanControllerModalIsCurrent(generation, editingId, sessionAtStart) {
    return generation === wlanControllerModalGeneration
      && currentSession === sessionAtStart
      && currentSessionCanEdit()
      && controllerKey(editingWlanControllerId) === controllerKey(editingId)
      && !element('wlan-controller-modal').classList.contains('hidden');
  }

  async function saveWlanController() {
    if (!requireEditPermission()) return;
    const editingId = editingWlanControllerId;
    const originalController = editingWlanControllerSnapshot;
    const sessionAtStart = currentSession;
    const modalGeneration = wlanControllerModalGeneration;
    const saveSequence = ++wlanControllerSaveSequence;
    const name = element('wlan-controller-name').value.trim();
    const host = element('wlan-controller-host').value.trim();
    const port = Number(element('wlan-controller-port').value);
    const error = element('wlan-controller-modal-error');
    if (!name || !host) {
      error.textContent = t('Name und Hostname beziehungsweise IP-Adresse sind erforderlich.');
      return;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      error.textContent = t('Der Port muss zwischen 1 und 65535 liegen.');
      return;
    }
    const body = {
      name,
      host,
      platform: element('wlan-controller-platform').value,
      transport: normalizeTransportId(element('wlan-controller-transport').value),
      port,
      site: element('wlan-controller-site').value.trim(),
      notes: element('wlan-controller-notes').value.trim(),
    };
    const isCreate = editingId === null;
    if (!isCreate && typeof originalController?.revision_token !== 'string') {
      wlanControllerRevisionConflict = true;
      error.textContent = t('Der Controllerstand ist nicht mehr aktuell. Schließe den Dialog und öffne ihn nach dem Neuladen erneut.');
      element('wlan-controller-save').disabled = true;
      return;
    }
    const requestBody = isCreate
      ? body
      : { ...body, revision_token: originalController.revision_token };
    const preflightConnectionChanged = !isCreate && controllerConnectionChanged(originalController, body);
    const preflightCredentialsReset = preflightConnectionChanged
      && controllerHasCredentialOverride(originalController);
    if (preflightCredentialsReset && !confirm(
      t('Hostname, Port, Plattform oder Transport wurden geändert. Beim Speichern werden die eigenen WLAN-Zugangsdaten gelöscht. Der Controller benötigt anschließend erneut eigene Zugangsdaten oder eine bewusste Umstellung auf globale Zugangsdaten. Fortfahren?'),
    )) return;
    const button = element('wlan-controller-save');
    button.disabled = true;
    error.textContent = '';
    try {
      const path = isCreate ? WLAN_API : `${WLAN_API}/${encodeControllerId(editingId)}`;
      const saved = await api(path, {
        method: isCreate ? 'POST' : 'PUT',
        body: JSON.stringify(requestBody),
      });
      if (saveSequence !== wlanControllerSaveSequence
          || !wlanControllerModalIsCurrent(modalGeneration, editingId, sessionAtStart)) return;
      const savedControllerId = saved?.id ?? editingId;
      if (savedControllerId !== null && savedControllerId !== undefined) {
        currentWlanControllerId = savedControllerId;
      }
      const credentialsWereCleared = !isCreate
        && controllerHasCredentialOverride(originalController)
        && !controllerHasCredentialOverride(saved);
      if (isCreate || preflightConnectionChanged || credentialsWereCleared) {
        invalidateWlanConfiguration();
        activeWlanTab = 'overview';
        resetWlanTableState();
      }
      closeWlanControllerModal();
      const onboardingGeneration = wlanControllerModalGeneration;
      if (credentialsWereCleared) {
        toast(t('Controller gespeichert. Die bisherigen WLAN-Zugangsdaten wurden wegen des geänderten Verbindungsziels gelöscht.'));
      } else if (isCreate) {
        toast(saved?.credentials_configured === true
          ? t('WLAN-Controller hinzugefügt. Die globalen Zugangsdaten werden verwendet.')
          : t('WLAN-Controller hinzugefügt. Richte globale oder eigene Zugangsdaten ein.'));
      } else {
        toast(t('WLAN-Controller gespeichert.'));
      }
      await loadWlanControllers({ keepTab: false });
      if (currentSession !== sessionAtStart || !currentSessionCanEdit() || !isWlanWorkspace()) return;
      if (((isCreate && saved?.credentials_configured !== true) || credentialsWereCleared)
          && wlanControllerModalGeneration === onboardingGeneration
          && element('wlan-controller-modal').classList.contains('hidden')
          && controllerKey(currentWlanControllerId) === controllerKey(savedControllerId)) {
        const savedController = wlanControllers.find(
          controller => controllerKey(controller.id) === controllerKey(savedControllerId),
        );
        if (savedController) openWlanCredentialsModal(savedController);
      }
    } catch (saveError) {
      if (saveSequence === wlanControllerSaveSequence
          && wlanControllerModalIsCurrent(modalGeneration, editingId, sessionAtStart)) {
        const isRevisionConflict = !isCreate
          && saveError.status === 409
          && saveError.code === 'stale_controller_revision';
        if (isRevisionConflict) {
          wlanControllerRevisionConflict = true;
          editingWlanControllerSnapshot = editingWlanControllerSnapshot
            ? { ...editingWlanControllerSnapshot, revision_token: null }
            : null;
          error.textContent = saveError.message
            ? t('{message} Schließe dazu diesen Dialog.', { message: saveError.message })
            : t('Der Controller wurde zwischenzeitlich geändert. Schließe den Dialog, lade die Daten neu und öffne ihn erneut.');
          // Der veraltete Token darf nicht automatisch erneut gesendet werden.
          // Erst ein bewusstes Schließen lädt den aktuellen Stand in die Liste.
          wlanControllerSaveSequence += 1;
        } else {
          error.textContent = saveError.message;
        }
      }
    } finally {
      if (saveSequence === wlanControllerSaveSequence
          && wlanControllerModalIsCurrent(modalGeneration, editingId, sessionAtStart)) {
        button.disabled = false;
      }
    }
  }

  async function openWlanCredentialsModal(controller) {
    if (!requireEditPermission() || wlanCredentialsSaving) return;
    const sessionAtStart = currentSession;
    wlanCredentialsSession = sessionAtStart;
    const modalGeneration = ++wlanCredentialsModalGeneration;
    wlanCredentialsSaveSequence += 1;
    credentialsWlanControllerId = controller.id;
    wlanCredentialsConfigured = false;
    wlanGlobalCredentialsConfigured = false;
    wlanCredentialsRevisionToken = null;
    wlanCredentialsControllerRevisionToken = typeof controller?.revision_token === 'string'
      ? controller.revision_token
      : null;
    wlanCredentialsReloadControllersOnClose = false;
    element('wlan-credentials-modal-title').textContent = t('Zugangsdaten · {name}', { name: controllerName(controller) });
    element('wlan-credentials-username-label').textContent =
      t('{protocol}-Benutzername', { protocol: transportProtocolName(controllerTransport(controller)) });
    element('wlan-credentials-username').value = '';
    element('wlan-credentials-password').value = '';
    element('wlan-credentials-mode').value = controllerCredentialsMode(controller);
    element('wlan-credentials-global-status').textContent = '';
    element('wlan-credentials-status').textContent = t('Lade Status …');
    element('wlan-credentials-modal-error').textContent = '';
    element('wlan-credentials-modal').classList.remove('hidden');
    setWlanCredentialsFormDisabled(true);
    if (typeof wlanCredentialsControllerRevisionToken !== 'string') {
      wlanCredentialsReloadControllersOnClose = true;
      element('wlan-credentials-status').textContent = t('Der Controllerstand konnte nicht sicher übernommen werden.');
      element('wlan-credentials-modal-error').textContent =
        t('Schließe den Dialog, damit die Controllerliste neu geladen wird, und öffne ihn anschließend erneut.');
      return;
    }
    try {
      const info = await api(`${WLAN_API}/${encodeControllerId(controller.id)}/credentials`);
      if (!wlanCredentialsModalIsCurrent(modalGeneration, controller.id, sessionAtStart)) return;
      if (typeof info?.revision_token !== 'string'
          || typeof info?.controller_revision_token !== 'string') {
        wlanCredentialsReloadControllersOnClose = true;
        element('wlan-credentials-status').textContent = t('Der Zugangsdatenstand konnte nicht sicher geladen werden.');
        element('wlan-credentials-modal-error').textContent =
          t('Schließe den Dialog, damit die Controllerliste neu geladen wird, und versuche es erneut.');
        return;
      }
      if (info.controller_revision_token !== wlanCredentialsControllerRevisionToken) {
        wlanCredentialsReloadControllersOnClose = true;
        element('wlan-credentials-status').textContent = t('Der Controller wurde zwischenzeitlich geändert.');
        element('wlan-credentials-modal-error').textContent =
          t('Die Zugangsdaten können mit diesem Stand nicht geändert werden. Schließe den Dialog und öffne ihn nach dem Neuladen erneut.');
        return;
      }
      wlanCredentialsRevisionToken = info.revision_token;
      const mode = info?.mode || info?.credentials_source || controllerCredentialsMode(controller);
      wlanCredentialsConfigured = info?.override_configured
        ?? info?.credentials_override_configured
        ?? (mode === 'device' && info?.configured === true);
      wlanGlobalCredentialsConfigured = info?.global_configured === true;
      element('wlan-credentials-mode').value = mode;
      element('wlan-credentials-username').value = mode === 'device' ? info?.username || '' : '';
      updateWlanCredentialsMode();
      setWlanCredentialsFormDisabled(false);
      element(mode === 'device' ? 'wlan-credentials-username' : 'wlan-credentials-mode').focus();
    } catch (error) {
      if (wlanCredentialsModalIsCurrent(modalGeneration, controller.id, sessionAtStart)) {
        element('wlan-credentials-status').textContent = t('Der Status konnte nicht geladen werden. Schließe den Dialog und versuche es erneut.');
        element('wlan-credentials-modal-error').textContent = error.message;
      }
    }
  }

  function setWlanCredentialsFormDisabled(disabled) {
    const deviceMode = element('wlan-credentials-mode').value === 'device';
    element('wlan-credentials-mode').disabled = disabled;
    element('wlan-credentials-device-fields').classList.toggle('hidden', !deviceMode);
    element('wlan-credentials-username').disabled = disabled || !deviceMode;
    element('wlan-credentials-password').disabled = disabled || !deviceMode;
    element('wlan-credentials-save').disabled = disabled;
    element('wlan-credentials-cancel').disabled = wlanCredentialsSaving;
  }

  function updateWlanCredentialsMode(clearPassword = false) {
    const deviceMode = element('wlan-credentials-mode').value === 'device';
    if (clearPassword) {
      element('wlan-credentials-password').value = '';
      element('wlan-credentials-modal-error').textContent = '';
    }
    element('wlan-credentials-global-status').textContent = wlanGlobalCredentialsConfigured
      ? t('Globale Zugangsdaten sind eingerichtet.')
      : t('Globale Zugangsdaten fehlen. Sie können unter „Administration → Globale Zugangsdaten“ eingerichtet werden.');
    element('wlan-credentials-status').textContent = deviceMode
      ? (wlanCredentialsConfigured
        ? t('Eigene Zugangsdaten sind eingerichtet. Ein leeres Passwort behält das eigene Passwort bei.')
        : t('Für eigene Zugangsdaten sind Benutzername und Passwort erforderlich. Das globale Passwort wird nicht übernommen.'))
      : (wlanGlobalCredentialsConfigured
        ? t('Dieser Controller verwendet den vollständigen globalen Zugangsdaten-Satz. Beim Speichern werden vorhandene eigene Zugangsdaten entfernt.')
        : t('Dieser Controller kann erst verbunden werden, wenn globale Zugangsdaten eingerichtet oder eigene Zugangsdaten ausgewählt wurden.'));
    setWlanCredentialsFormDisabled(element('wlan-credentials-mode').disabled);
  }

  function wlanCredentialsModalIsCurrent(generation, controllerId, sessionAtStart) {
    return generation === wlanCredentialsModalGeneration
      && currentSession === sessionAtStart
      && currentSessionCanEdit()
      && controllerKey(credentialsWlanControllerId) === controllerKey(controllerId)
      && !element('wlan-credentials-modal').classList.contains('hidden');
  }

  function closeWlanCredentialsModal(force = false) {
    if (wlanCredentialsSaving && force !== true) return;
    const reloadControllers = wlanCredentialsReloadControllersOnClose;
    wlanCredentialsModalGeneration += 1;
    wlanCredentialsSaveSequence += 1;
    wlanCredentialsSaving = false;
    wlanCredentialsSession = null;
    credentialsWlanControllerId = null;
    wlanCredentialsConfigured = false;
    wlanGlobalCredentialsConfigured = false;
    wlanCredentialsRevisionToken = null;
    wlanCredentialsControllerRevisionToken = null;
    wlanCredentialsReloadControllersOnClose = false;
    element('wlan-credentials-username').value = '';
    element('wlan-credentials-password').value = '';
    element('wlan-credentials-mode').value = 'global';
    element('wlan-credentials-global-status').textContent = '';
    element('wlan-credentials-status').textContent = '';
    element('wlan-credentials-modal-error').textContent = '';
    setWlanCredentialsFormDisabled(true);
    element('wlan-credentials-modal').classList.add('hidden');
    if (reloadControllers && currentSession && isWlanWorkspace()) {
      loadWlanControllers({ keepTab: true });
    }
  }

  async function saveWlanCredentials() {
    if (!requireEditPermission() || credentialsWlanControllerId === null) return;
    if (element('wlan-credentials-save').disabled) return;
    const mode = element('wlan-credentials-mode').value;
    const username = element('wlan-credentials-username').value.trim();
    const password = element('wlan-credentials-password').value;
    const error = element('wlan-credentials-modal-error');
    if (typeof wlanCredentialsRevisionToken !== 'string'
        || typeof wlanCredentialsControllerRevisionToken !== 'string') {
      wlanCredentialsReloadControllersOnClose = true;
      error.textContent = t('Der Controller- oder Zugangsdatenstand ist nicht mehr aktuell. Schließe den Dialog und öffne ihn nach dem Neuladen erneut.');
      setWlanCredentialsFormDisabled(true);
      return;
    }
    if (!['global', 'device'].includes(mode)) return;
    if (mode === 'device' && (!username || (!password && !wlanCredentialsConfigured))) {
      error.textContent = wlanCredentialsConfigured
        ? t('Der Benutzername ist erforderlich.')
        : t('Beim erstmaligen Einrichten sind Benutzername und Passwort erforderlich.');
      return;
    }
    const button = element('wlan-credentials-save');
    const controllerId = credentialsWlanControllerId;
    const sessionAtStart = currentSession;
    const modalGeneration = wlanCredentialsModalGeneration;
    const saveSequence = ++wlanCredentialsSaveSequence;
    wlanCredentialsSaving = true;
    setWlanCredentialsFormDisabled(true);
    error.textContent = '';
    try {
      const updatedCredentials = await api(`${WLAN_API}/${encodeControllerId(controllerId)}/credentials`, {
        method: 'PUT',
        body: JSON.stringify({
          mode,
          ...(mode === 'device' ? { username, password: password || null } : {}),
          revision_token: wlanCredentialsRevisionToken,
          controller_revision_token: wlanCredentialsControllerRevisionToken,
        }),
      });
      if (saveSequence !== wlanCredentialsSaveSequence
          || !wlanCredentialsModalIsCurrent(modalGeneration, controllerId, sessionAtStart)) return;
      // Eine bereits laufende Listenabfrage darf den vom erfolgreichen PUT
      // gelieferten neuen Controller-Token nicht wieder überschreiben.
      controllerListSequence += 1;
      const controller = wlanControllers.find(item => controllerKey(item.id) === controllerKey(controllerId));
      if (controller) {
        controller.credentials_source = updatedCredentials?.mode || updatedCredentials?.credentials_source || mode;
        controller.credentials_configured = updatedCredentials?.configured
          ?? updatedCredentials?.credentials_configured
          ?? (mode === 'device' || wlanGlobalCredentialsConfigured);
        controller.credentials_override_configured = updatedCredentials?.override_configured
          ?? updatedCredentials?.credentials_override_configured
          ?? (mode === 'device');
        controller.revision_token = typeof updatedCredentials?.controller_revision_token === 'string'
          ? updatedCredentials.controller_revision_token
          : null;
      }
      closeWlanCredentialsModal(true);
      wlanDataSequence += 1;
      wlanTestConnectionSequence += 1;
      invalidateWlanConfiguration();
      toast(mode === 'global' ? t('Globale Zugangsdaten für den WLAN-Controller ausgewählt.') : t('Eigene WLAN-Zugangsdaten gespeichert.'));
      renderWlanControllerList();
      if (isWlanWorkspace()) await loadWlanControllers({ keepTab: true });
    } catch (saveError) {
      if (saveSequence === wlanCredentialsSaveSequence
          && wlanCredentialsModalIsCurrent(modalGeneration, controllerId, sessionAtStart)) {
        wlanCredentialsSaving = false;
        element('wlan-credentials-cancel').disabled = false;
        if (saveError.status === 409) {
          wlanCredentialsRevisionToken = null;
          wlanCredentialsControllerRevisionToken = null;
          wlanCredentialsReloadControllersOnClose = true;
          error.textContent = t('Der Controller oder seine Zugangsdaten wurden zwischenzeitlich geändert. Schließe den Dialog und öffne ihn nach dem Neuladen erneut.');
          // Der verbrauchte Token darf weder automatisch erneuert noch erneut
          // gesendet werden. Nur Abbrechen/Schließen bleibt möglich.
          wlanCredentialsSaveSequence += 1;
        } else {
          error.textContent = saveError.message;
          setWlanCredentialsFormDisabled(false);
        }
      }
    } finally {
      if (saveSequence === wlanCredentialsSaveSequence
          && wlanCredentialsModalIsCurrent(modalGeneration, controllerId, sessionAtStart)) {
        wlanCredentialsSaving = false;
        element('wlan-credentials-cancel').disabled = false;
        button.disabled = false;
      }
    }
  }

  async function testWlanConnection() {
    if (!requireEditPermission()) return;
    const controller = selectedWlanController();
    const button = element('wlan-controller-test');
    if (!controller || !button || button.disabled) return;
    const controllerId = controller.id;
    const sessionAtStart = currentSession;
    const requestSequence = ++wlanTestConnectionSequence;
    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = t('Teste …');
    try {
      const result = await api(`${WLAN_API}/${encodeControllerId(controllerId)}/test-connection`, { method: 'POST' });
      if (!wlanConnectionTestIsCurrent(requestSequence, controllerId, sessionAtStart)) return;
      const message = firstValue(result, ['message', 'detail'], t('Verbindung zum WLAN-Controller erfolgreich.'));
      if (result?.ok === false) {
        toast(String(message), true);
        return;
      }
      toast(String(message));
      if (activeWlanTab === 'overview') renderWlanOverview(true);
    } catch (error) {
      if (wlanConnectionTestIsCurrent(requestSequence, controllerId, sessionAtStart)) {
        toast(t('Verbindungstest fehlgeschlagen: {error}', { error: error.message }), true);
      }
    } finally {
      if (button.isConnected) {
        button.disabled = false;
        button.textContent = originalLabel;
      }
    }
  }

  function wlanConnectionTestIsCurrent(sequence, controllerId, sessionAtStart) {
    return sequence === wlanTestConnectionSequence
      && currentSession === sessionAtStart
      && currentSessionCanEdit()
      && isWlanWorkspace()
      && controllerKey(currentWlanControllerId) === controllerKey(controllerId);
  }

  async function deleteWlanController(controller) {
    if (!requireEditPermission()) return;
    if (!confirm(t('WLAN-Controller „{name}“ wirklich löschen?', { name: controllerName(controller) }))) return;
    const sessionAtStart = currentSession;
    try {
      await api(`${WLAN_API}/${encodeControllerId(controller.id)}`, { method: 'DELETE' });
      if (currentSession !== sessionAtStart) return;
      if (controllerKey(currentWlanControllerId) === controllerKey(controller.id)) currentWlanControllerId = null;
      toast(t('WLAN-Controller gelöscht.'));
      await loadWlanControllers();
    } catch (error) {
      if (currentSession !== sessionAtStart) return;
      toast(error.message, true);
    }
  }

  function clearWlanSensitiveFields() {
    element('wlan-credentials-username').value = '';
    element('wlan-credentials-password').value = '';
    element('wlan-device-modal-body')?.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
  }

  function closeWlanPrivilegedModals() {
    closeWlanControllerModal();
    closeWlanCredentialsModal(true);
    closeWlanDeviceModal();
  }

  function applyWlanSessionUi() {
    element('btn-add-wlan-controller').classList.toggle('hidden', !currentSessionCanEdit());
    if (wlanCredentialsSession && wlanCredentialsSession !== currentSession) closeWlanCredentialsModal(true);
    if (!currentSessionCanEdit()) closeWlanPrivilegedModals();
  }

  // Kept on window for the initial call below and for tests driving a session change directly.
  window.wlanApplySessionUi = applyWlanSessionUi;

  function rerenderWlanRoleSensitiveContent() {
    renderWlanControllerList();
    if (isWlanWorkspace()) {
      const controller = selectedWlanController();
      if (controller) {
        renderWlanControllerDetail(controller);
        showWlanTab(activeWlanTab);
      } else {
        renderEmptyWlanWorkspace();
      }
    }
  }

  function handleWlanCredentialsChanged() {
    controllerListSequence += 1;
    wlanDataSequence += 1;
    wlanTestConnectionSequence += 1;
    wlanCredentialsReloadControllersOnClose = false;
    closeWlanCredentialsModal(true);
    invalidateWlanConfiguration();
    if (currentSession && isWlanWorkspace()) return loadWlanControllers({ keepTab: true });
  }

  function resetWlanState() {
    wlanControllers = [];
    currentWlanControllerId = null;
    activeWlanTab = 'overview';
    controllerListSequence += 1;
    wlanDataSequence += 1;
    wlanTestConnectionSequence += 1;
    invalidateWlanConfiguration();
    resetWlanTableState();
    closeWlanControllerModal();
    closeWlanCredentialsModal(true);
    element('wlan-controller-list').innerHTML = '';
    element('wlan-controller-search').value = '';
  }

  registerSessionHooks({
    applySessionUi: applyWlanSessionUi,
    rerenderRoleSensitiveContent: rerenderWlanRoleSensitiveContent,
    clearSensitiveFields: clearWlanSensitiveFields,
    closePrivilegedModals: closeWlanPrivilegedModals,
    reset: resetWlanState,
    credentialsChanged: handleWlanCredentialsChanged,
  });

  element('nav-wlan').addEventListener('click', () => setWorkspaceMode('wlan'));
  element('wlan-controller-search').addEventListener('input', renderWlanControllerList);
  element('btn-add-wlan-controller').addEventListener('click', () => openWlanControllerModal());
  element('wlan-controller-platform').addEventListener('change', handleWlanPlatformChange);
  element('wlan-controller-transport').addEventListener('change', handleWlanTransportChange);
  element('wlan-controller-cancel').addEventListener('click', closeWlanControllerModal);
  element('wlan-controller-save').addEventListener('click', saveWlanController);
  element('wlan-controller-edit-credentials')?.addEventListener('click', () => {
    const controller = editingWlanControllerSnapshot;
    if (!controller || !requireEditPermission()) return;
    closeWlanControllerModal();
    openWlanCredentialsModal(controller);
  });
  element('wlan-credentials-mode').addEventListener('change', () => updateWlanCredentialsMode(true));
  element('wlan-credentials-cancel').addEventListener('click', closeWlanCredentialsModal);
  element('wlan-credentials-save').addEventListener('click', saveWlanCredentials);
  element('wlan-device-close').addEventListener('click', closeWlanDeviceModal);
  document.addEventListener('keydown', event => {
    if (event.key !== 'Tab' || element('wlan-device-modal').classList.contains('hidden')) return;
    const controls = [...element('wlan-device-modal').querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]')];
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  window.wlanApplySessionUi();
})();
