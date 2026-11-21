(() => {
  'use strict';

  const ADMIN_API = '/api/admin';
  const USERNAME_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
  const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const SECTIONS = ['auth', 'users', 'mappings', 'credentials', 'operations', 'port-profiles', 'audit', 'system-log', 'software-update'];
  // Sections that are static pages in #admin-pages instead of content rendered into #main-content.
  const PAGE_SECTIONS = { credentials: 'admin-page-credentials', 'software-update': 'admin-page-software-update' };

  let activeSection = 'auth';
  let adminDataSequence = 0;
  let authSettings = null;
  let adminUsers = [];
  let groupMappings = [];
  let auditEntries = [];
  let systemLogEntries = [];
  let operationsSettings = null;
  // Panel actions (save/test) currently running, keyed by action name.
  const runningActions = new Set();
  let userModalState = null;
  let mappingModalState = null;
  let portProfiles = [];
  let profileModalState = null;

  const element = id => document.getElementById(id);
  const isAdminSession = () => currentSession?.role === 'admin';
  const isAdminWorkspace = () => isWorkspaceActive('admin');
  const mainContent = () => element('main-content');

  function roleLabel(role) {
    if (role === 'admin') return t('Administrator');
    if (role === 'operator') return t('Operator');
    if (role === 'viewer') return t('Nur lesen');
    return t('Kein Zugriff');
  }

  function providerLabel(provider) {
    if (provider === 'local') return t('Lokales Konto');
    if (provider === 'ad') return t('Active Directory');
    if (provider === 'entra') return t('Microsoft Entra ID');
    return String(provider || '');
  }

  // SQLite timestamps ("YYYY-MM-DD HH:MM:SS") are UTC without a zone designator.
  function formatTimestamp(value) {
    if (!value) return '—';
    const text = String(value);
    const iso = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(text) ? text.replace(' ', 'T') + 'Z' : text;
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? text : date.toLocaleString(uiLocale());
  }

  function setText(id, text, isError = false) {
    const target = element(id);
    if (!target) return;
    target.textContent = text;
    target.classList.toggle('admin-form-error', isError);
  }

  function checked(id) {
    return element(id)?.checked === true;
  }

  function fieldValue(id) {
    return String(element(id)?.value ?? '').trim();
  }

  function adminSessionIsCurrent(sequence, session) {
    return sequence === adminDataSequence && currentSession === session && isAdminSession() && isAdminWorkspace();
  }

  function selectedAttr(value, expected) {
    return value === expected ? ' selected' : '';
  }

  function checkedAttr(value) {
    return value ? ' checked' : '';
  }

  // --- Navigation ------------------------------------------------------

  function renderSectionNav() {
    SECTIONS.forEach(section => {
      const button = element(`admin-nav-${section}`);
      if (!button) return;
      const active = section === activeSection;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
  }

  function showAdminPage(pageId) {
    Object.values(PAGE_SECTIONS).forEach(id => setElementHidden(id, id !== pageId));
    setElementHidden('admin-pages', !pageId);
    setElementHidden('main-content', Boolean(pageId));
  }

  function leaveAdminPages() {
    resetGlobalCredentialsPage();
    if (!softwareUpdateState.busy) resetSoftwareUpdate();
    showAdminPage(null);
  }

  function showAdminSection(section) {
    const previous = activeSection;
    activeSection = SECTIONS.includes(section) ? section : 'auth';
    renderSectionNav();
    if (!isAdminWorkspace()) return Promise.resolve();
    if (PAGE_SECTIONS[previous] && previous !== activeSection) leaveAdminPages();
    const pageId = PAGE_SECTIONS[activeSection];
    if (pageId) {
      // Drops in-flight loads of the dynamic sections so they cannot render behind the page.
      adminDataSequence += 1;
      showAdminPage(pageId);
      return activeSection === 'credentials' ? openGlobalCredentials() : openSoftwareUpdate();
    }
    showAdminPage(null);
    if (activeSection === 'users') return loadUsers();
    if (activeSection === 'mappings') return loadMappings();
    if (activeSection === 'audit') return loadAudit();
    if (activeSection === 'system-log') return loadSystemLog();
    if (activeSection === 'operations') return loadOperationsSettings();
    if (activeSection === 'port-profiles') return loadPortProfiles();
    return loadAuthSettings();
  }

  function renderLoading() {
    mainContent().innerHTML = `<div class="empty-state" role="status">${escapeHtml(t('Lade Daten …'))}</div>`;
  }

  function renderLoadError(error) {
    mainContent().innerHTML = `<div class="panel-box"><div class="wlan-error-box" role="alert">${escapeHtml(error.message)}</div></div>`;
  }

  async function loadSection(path, apply) {
    const sequence = ++adminDataSequence;
    const session = currentSession;
    renderLoading();
    try {
      const payload = await api(path);
      if (!adminSessionIsCurrent(sequence, session)) return;
      apply(payload);
    } catch (error) {
      if (!adminSessionIsCurrent(sequence, session)) return;
      renderLoadError(error);
    }
  }

  // --- Authentication settings -----------------------------------------

  function loadAuthSettings() {
    return loadSection(`${ADMIN_API}/auth-settings`, payload => {
      authSettings = payload && typeof payload === 'object' ? payload : {};
      renderAuthSettings();
    });
  }

  function renderLocalPanel(local) {
    const adminCount = Number(local?.admin_count) || 0;
    const warning = adminCount === 0
      ? `<div class="wlan-warning-box" role="alert">${escapeHtml(t('Kein lokales Administratorkonto vorhanden. Notfallzugang: python -m app.manage create-admin'))}</div>`
      : '';
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Lokale Konten'))}</h3>
      <p class="admin-muted">${escapeHtml(t('Die Anmeldung mit lokalen Konten ist immer aktiv. Einzelne Konten können gesperrt werden.'))}</p>
      <p>${escapeHtml(t('Lokale Administratoren: {count}', { count: adminCount }))}</p>
      ${warning}
    </div>`;
  }

  function renderGeneralPanel(general) {
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Allgemein'))}</h3>
      <div class="field"><label for="admin-general-url">${escapeHtml(t('Öffentliche Adresse der Anwendung'))}</label>
        <input id="admin-general-url" value="${escapeHtml(general?.public_base_url || '')}" placeholder="https://switchsteward.example.org" spellcheck="false" autocomplete="off">
        <small class="admin-muted">${escapeHtml(t('Erforderlich für Microsoft Entra ID. Ohne Pfad und ohne abschließenden Schrägstrich.'))}</small>
      </div>
      <p id="admin-general-message" role="status"></p>
      <div class="flex-row" style="justify-content: flex-end;">
        <button class="primary" type="button" data-admin-action="save-general">${escapeHtml(t('Speichern'))}</button>
      </div>
    </div>`;
  }

  function renderDefaultRoleOptions(value) {
    return `<option value="none"${selectedAttr(value, 'none')}>${escapeHtml(t('Kein Zugriff'))}</option>
      <option value="viewer"${selectedAttr(value, 'viewer')}>${escapeHtml(t('Nur lesen'))}</option>`;
  }

  function renderAdPanel(ad) {
    const settings = ad || {};
    const servers = Array.isArray(settings.servers) ? settings.servers.join('\n') : '';
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Active Directory'))}</h3>
      <label class="admin-check"><input id="admin-ad-enabled" type="checkbox"${checkedAttr(settings.enabled === true)}> ${escapeHtml(t('Aktiviert'))}</label>
      <div class="field"><label for="admin-ad-servers">${escapeHtml(t('Server (eine Adresse pro Zeile)'))}</label>
        <textarea id="admin-ad-servers" rows="3" spellcheck="false" placeholder="ldaps://dc01.example.org:636">${escapeHtml(servers)}</textarea>
      </div>
      <div class="field"><label for="admin-ad-domain">${escapeHtml(t('Domain'))}</label><input id="admin-ad-domain" value="${escapeHtml(settings.domain || '')}" spellcheck="false" autocomplete="off"></div>
      <div class="field"><label for="admin-ad-base-dn">${escapeHtml(t('Base-DN'))}</label><input id="admin-ad-base-dn" value="${escapeHtml(settings.base_dn || '')}" spellcheck="false" autocomplete="off"></div>
      <div class="field"><label for="admin-ad-ca-file">${escapeHtml(t('CA-Zertifikatsdatei (optional)'))}</label><input id="admin-ad-ca-file" value="${escapeHtml(settings.ca_cert_file || '')}" spellcheck="false" autocomplete="off"></div>
      <div class="flex-row">
        <div class="field"><label for="admin-ad-connect-timeout">${escapeHtml(t('Verbindungs-Timeout (s)'))}</label><input id="admin-ad-connect-timeout" type="number" min="1" max="120" step="1" value="${escapeHtml(settings.connect_timeout_seconds ?? 5)}"></div>
        <div class="field"><label for="admin-ad-receive-timeout">${escapeHtml(t('Antwort-Timeout (s)'))}</label><input id="admin-ad-receive-timeout" type="number" min="1" max="300" step="1" value="${escapeHtml(settings.receive_timeout_seconds ?? 10)}"></div>
      </div>
      <div class="field"><label for="admin-ad-default-role">${escapeHtml(t('Standardrolle ohne Gruppentreffer'))}</label>
        <select id="admin-ad-default-role">${renderDefaultRoleOptions(settings.default_role)}</select>
      </div>
      <details>
        <summary>${escapeHtml(t('Unsichere Ausnahmen'))}</summary>
        <div class="wlan-warning-box">${escapeHtml(t('Diese Optionen schwächen den Schutz der Anmeldedaten. Nur für Tests oder Übergangszeiten verwenden.'))}</div>
        <label class="admin-check"><input id="admin-ad-tls-validate" type="checkbox"${checkedAttr(settings.tls_validate !== false)}> ${escapeHtml(t('Serverzertifikat prüfen'))}</label>
        <label class="admin-check"><input id="admin-ad-allow-insecure" type="checkbox"${checkedAttr(settings.allow_insecure_ldap === true)}> ${escapeHtml(t('Unverschlüsseltes LDAP (ldap://) erlauben'))}</label>
        <label class="admin-check"><input id="admin-ad-allow-unverified" type="checkbox"${checkedAttr(settings.allow_unverified_ldaps === true)}> ${escapeHtml(t('LDAPS ohne Zertifikatsprüfung erlauben'))}</label>
      </details>
      <p id="admin-ad-message" role="status"></p>
      <div class="flex-row" style="justify-content: flex-end;">
        <button class="primary" type="button" data-admin-action="save-ad">${escapeHtml(t('Speichern'))}</button>
      </div>
      <h4>${escapeHtml(t('Testanmeldung'))}</h4>
      <p class="admin-muted">${escapeHtml(t('Prüft die gespeicherten Einstellungen. Es wird keine Sitzung erstellt.'))}</p>
      <div class="flex-row">
        <div class="field"><label for="admin-ad-test-username">${escapeHtml(t('Benutzername'))}</label><input id="admin-ad-test-username" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="admin-ad-test-password">${escapeHtml(t('Passwort'))}</label><input id="admin-ad-test-password" type="password" autocomplete="new-password"></div>
      </div>
      <div class="flex-row" style="justify-content: flex-end;">
        <button type="button" data-admin-action="test-ad">${escapeHtml(t('Testanmeldung'))}</button>
      </div>
      <div id="admin-ad-test-result" role="status"></div>
    </div>`;
  }

  function renderEntraPanel(entra) {
    const settings = entra || {};
    const cloud = settings.cloud || 'global';
    const secretPlaceholder = settings.client_secret_configured === true
      ? t('Gespeichert – leer lassen zum Beibehalten') : '';
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Microsoft Entra ID (OAuth 2.0 / OpenID Connect)'))}</h3>
      <label class="admin-check"><input id="admin-entra-enabled" type="checkbox"${checkedAttr(settings.enabled === true)}> ${escapeHtml(t('Aktiviert'))}</label>
      <div class="field"><label for="admin-entra-tenant">${escapeHtml(t('Tenant-ID'))}</label><input id="admin-entra-tenant" value="${escapeHtml(settings.tenant_id || '')}" spellcheck="false" autocomplete="off"></div>
      <div class="field"><label for="admin-entra-client-id">${escapeHtml(t('Client-ID'))}</label><input id="admin-entra-client-id" value="${escapeHtml(settings.client_id || '')}" spellcheck="false" autocomplete="off"></div>
      <div class="field"><label for="admin-entra-secret">${escapeHtml(t('Client-Secret'))}</label><input id="admin-entra-secret" type="password" autocomplete="new-password" placeholder="${escapeHtml(secretPlaceholder)}"></div>
      <label class="admin-check"><input id="admin-entra-clear-secret" type="checkbox"> ${escapeHtml(t('Gespeichertes Secret entfernen'))}</label>
      <div class="field"><label for="admin-entra-cloud">${escapeHtml(t('Cloud'))}</label>
        <select id="admin-entra-cloud">
          <option value="global"${selectedAttr(cloud, 'global')}>${escapeHtml(t('Weltweit (login.microsoftonline.com)'))}</option>
          <option value="usgov"${selectedAttr(cloud, 'usgov')}>${escapeHtml(t('US Government'))}</option>
          <option value="china"${selectedAttr(cloud, 'china')}>${escapeHtml(t('China (21Vianet)'))}</option>
        </select>
      </div>
      <div class="field"><label for="admin-entra-default-role">${escapeHtml(t('Standardrolle ohne Gruppentreffer'))}</label>
        <select id="admin-entra-default-role">${renderDefaultRoleOptions(settings.default_role)}</select>
      </div>
      <div class="field"><label for="admin-entra-redirect">${escapeHtml(t('Redirect-URI'))}</label>
        <div class="flex-row">
          <input id="admin-entra-redirect" readonly style="flex: 1;" value="${escapeHtml(settings.redirect_uri || '')}" placeholder="${escapeHtml(t('Erst nach Angabe der öffentlichen Adresse verfügbar'))}">
          <button type="button" data-admin-action="copy-redirect">${escapeHtml(t('Kopieren'))}</button>
        </div>
      </div>
      <p id="admin-entra-message" role="status"></p>
      <div class="flex-row" style="justify-content: flex-end;">
        <button type="button" data-admin-action="test-entra">${escapeHtml(t('Konfiguration prüfen'))}</button>
        <button class="primary" type="button" data-admin-action="save-entra">${escapeHtml(t('Speichern'))}</button>
      </div>
    </div>`;
  }

  function renderAuthSettings() {
    const settings = authSettings || {};
    mainContent().innerHTML = `<div class="admin-section">
      <h2>${escapeHtml(t('Authentifizierung'))}</h2>
      ${renderLocalPanel(settings.local)}
      ${renderGeneralPanel(settings.general)}
      ${renderAdPanel(settings.ad)}
      ${renderEntraPanel(settings.entra)}
    </div>`;
  }

  // Runs a panel action once at a time; ignores results that arrive after a session or view change.
  async function runPanelAction(name, messageId, request, onSuccess) {
    if (runningActions.has(name) || !isAdminSession()) return;
    const sequence = adminDataSequence;
    const session = currentSession;
    runningActions.add(name);
    setText(messageId, t('Wird ausgeführt …'));
    try {
      const result = await request();
      if (!adminSessionIsCurrent(sequence, session)) return;
      onSuccess(result);
    } catch (error) {
      if (!adminSessionIsCurrent(sequence, session)) return;
      setText(messageId, error.message, true);
    } finally {
      runningActions.delete(name);
    }
  }

  function saveGeneral() {
    const body = { public_base_url: fieldValue('admin-general-url') || null };
    return runPanelAction('save-general', 'admin-general-message',
      () => api(`${ADMIN_API}/auth-settings/general`, { method: 'PUT', body: JSON.stringify(body) }),
      () => {
        toast(t('Einstellungen gespeichert.'));
        void loadAuthSettings();
      });
  }

  function adSettingsBody() {
    return {
      enabled: checked('admin-ad-enabled'),
      servers: String(element('admin-ad-servers')?.value ?? '').split(/\r?\n/).map(line => line.trim()).filter(Boolean),
      domain: fieldValue('admin-ad-domain'),
      base_dn: fieldValue('admin-ad-base-dn'),
      tls_validate: checked('admin-ad-tls-validate'),
      ca_cert_file: fieldValue('admin-ad-ca-file') || null,
      connect_timeout_seconds: Number(fieldValue('admin-ad-connect-timeout')),
      receive_timeout_seconds: Number(fieldValue('admin-ad-receive-timeout')),
      allow_insecure_ldap: checked('admin-ad-allow-insecure'),
      allow_unverified_ldaps: checked('admin-ad-allow-unverified'),
      default_role: fieldValue('admin-ad-default-role') === 'viewer' ? 'viewer' : 'none',
    };
  }

  function saveAd() {
    const body = adSettingsBody();
    return runPanelAction('save-ad', 'admin-ad-message',
      () => api(`${ADMIN_API}/auth-settings/ad`, { method: 'PUT', body: JSON.stringify(body) }),
      () => {
        toast(t('Einstellungen gespeichert.'));
        void loadAuthSettings();
      });
  }

  function renderAdTestResult(result) {
    const groups = Array.isArray(result?.matched_groups) ? result.matched_groups : [];
    const groupList = groups.length
      ? `<ul>${groups.map(group => `<li>${escapeHtml(group?.label || group?.group_id || '')}
          <span class="admin-muted">${escapeHtml(group?.group_id || '')}</span> · ${escapeHtml(roleLabel(group?.role))}</li>`).join('')}</ul>`
      : `<p class="admin-muted">${escapeHtml(t('Keine zugeordnete Gruppe getroffen.'))}</p>`;
    const box = result?.ok === true ? 'wlan-warning-box admin-test-ok' : 'wlan-error-box';
    element('admin-ad-test-result').innerHTML = `<div class="${box}">
      <strong>${escapeHtml(result?.ok === true ? t('Anmeldung erfolgreich') : t('Anmeldung fehlgeschlagen'))}</strong>
      ${result?.message ? `<p>${escapeHtml(result.message)}</p>` : ''}
      <p>${escapeHtml(t('Ermittelte Rolle: {role}', { role: roleLabel(result?.role) }))}</p>
      ${groupList}
    </div>`;
  }

  function testAd() {
    if (runningActions.has('test-ad')) return Promise.resolve();
    const username = fieldValue('admin-ad-test-username');
    const passwordField = element('admin-ad-test-password');
    const password = String(passwordField?.value ?? '');
    if (!username || !password) {
      setText('admin-ad-message', t('Für die Testanmeldung Benutzername und Passwort angeben.'), true);
      return Promise.resolve();
    }
    if (passwordField) passwordField.value = '';
    element('admin-ad-test-result').innerHTML = '';
    return runPanelAction('test-ad', 'admin-ad-message',
      () => api(`${ADMIN_API}/auth-settings/ad/test`, { method: 'POST', body: JSON.stringify({ username, password }) }),
      result => {
        setText('admin-ad-message', '');
        renderAdTestResult(result);
      });
  }

  function entraSettingsBody() {
    const cloud = fieldValue('admin-entra-cloud');
    return {
      enabled: checked('admin-entra-enabled'),
      tenant_id: fieldValue('admin-entra-tenant'),
      client_id: fieldValue('admin-entra-client-id'),
      client_secret: String(element('admin-entra-secret')?.value ?? '') || null,
      clear_client_secret: checked('admin-entra-clear-secret'),
      cloud: ['global', 'usgov', 'china'].includes(cloud) ? cloud : 'global',
      default_role: fieldValue('admin-entra-default-role') === 'viewer' ? 'viewer' : 'none',
    };
  }

  function saveEntra() {
    if (runningActions.has('save-entra')) return Promise.resolve();
    const body = entraSettingsBody();
    const secretField = element('admin-entra-secret');
    if (secretField) secretField.value = '';
    return runPanelAction('save-entra', 'admin-entra-message',
      () => api(`${ADMIN_API}/auth-settings/entra`, { method: 'PUT', body: JSON.stringify(body) }),
      () => {
        toast(t('Einstellungen gespeichert.'));
        void loadAuthSettings();
      });
  }

  function testEntra() {
    return runPanelAction('test-entra', 'admin-entra-message',
      () => api(`${ADMIN_API}/auth-settings/entra/test`, { method: 'POST' }),
      result => {
        const parts = [result?.ok === true ? t('Konfiguration gültig.') : t('Konfiguration fehlerhaft.')];
        if (result?.issuer) parts.push(t('Aussteller: {issuer}', { issuer: result.issuer }));
        if (result?.message) parts.push(String(result.message));
        setText('admin-entra-message', parts.join(' '), result?.ok !== true);
      });
  }

  async function copyRedirectUri() {
    const value = fieldValue('admin-entra-redirect');
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      toast(t('Redirect-URI kopiert.'));
    } catch {
      element('admin-entra-redirect')?.select?.();
      toast(t('Kopieren nicht möglich. Bitte die Adresse manuell kopieren.'), true);
    }
  }

  // --- Operations ("Betrieb") ------------------------------------------

  // Panels of the operations section in display order; further panels are appended here.
  const OPERATIONS_PANELS = [renderBackupPanel, renderTransferPanel, renderFirmwarePanel, renderFirmwareImagesPanel, renderJobsPanel];

  function loadOperationsSettings() {
    return loadSection(`${ADMIN_API}/operations-settings`, applyOperationsSettings);
  }

  function applyOperationsSettings(payload) {
    operationsSettings = payload && typeof payload === 'object' ? payload : {};
    renderOperationsSettings();
  }

  function renderOperationsSettings() {
    const settings = operationsSettings || {};
    mainContent().innerHTML = `<div class="admin-section">
      <h2>${escapeHtml(t('Betrieb'))}</h2>
      ${OPERATIONS_PANELS.map(render => render(settings)).join('')}
    </div>`;
    void loadOperationsLists();
  }

  // --- Firmware images and scheduled jobs (operations section) ---------

  let firmwareImages = [];
  let firmwareDrivers = [];
  let adminJobs = [];

  function renderFirmwareImagesPanel() {
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Firmware-Images'))}</h3>
      <div id="admin-firmware-images"><p class="admin-muted">${escapeHtml(t('Wird geladen …'))}</p></div>
      <h4>${escapeHtml(t('Image hochladen'))}</h4>
      <div class="field"><label for="admin-firmware-file">${escapeHtml(t('Datei'))}</label><input id="admin-firmware-file" type="file"></div>
      <div id="admin-firmware-platforms"></div>
      <progress id="admin-firmware-progress" max="100" value="0" class="hidden"></progress>
      <p id="admin-firmware-images-message" role="status"></p>
      <div class="flex-row" style="justify-content: flex-end;">
        <button class="primary" type="button" data-admin-action="upload-firmware-image">${escapeHtml(t('Hochladen'))}</button>
      </div>
    </div>`;
  }

  function renderJobsPanel() {
    return `<div class="panel-box">
      <div class="flex-row" style="justify-content: space-between;">
        <h3>${escapeHtml(t('Geplante Aufgaben'))}</h3>
        <button type="button" data-admin-action="refresh-jobs">${escapeHtml(t('Aktualisieren'))}</button>
      </div>
      <div id="admin-jobs"><p class="admin-muted">${escapeHtml(t('Wird geladen …'))}</p></div>
      <p id="admin-jobs-message" role="status"></p>
    </div>`;
  }

  async function loadOperationsLists() {
    await Promise.all([loadFirmwareImages(), loadFirmwareDrivers(), loadAdminJobs()]);
  }

  async function fetchForAdmin(path, messageId, apply) {
    const sequence = adminDataSequence;
    const session = currentSession;
    try {
      const payload = await api(path);
      if (adminSessionIsCurrent(sequence, session)) apply(payload);
    } catch (error) {
      if (adminSessionIsCurrent(sequence, session)) setText(messageId, error.message, true);
    }
  }

  function loadFirmwareImages() {
    return fetchForAdmin('/api/firmware/images', 'admin-firmware-images-message', payload => {
      firmwareImages = Array.isArray(payload?.images) ? payload.images.filter(image => image && typeof image === 'object') : [];
      renderFirmwareImages();
    });
  }

  function loadFirmwareDrivers() {
    return fetchForAdmin('/api/switch-drivers', 'admin-firmware-images-message', payload => {
      firmwareDrivers = (Array.isArray(payload) ? payload : []).filter(driver => driver && typeof driver === 'object' && driver.id);
      element('admin-firmware-platforms').innerHTML = `<p>${escapeHtml(t('Plattformen'))}</p>${firmwareDrivers.map(driver => `
        <label class="admin-check"><input id="admin-firmware-platform-${escapeHtml(driver.id)}" type="checkbox"> ${escapeHtml(driver.label || driver.id)}</label>`).join('')}`;
    });
  }

  function loadAdminJobs() {
    return fetchForAdmin('/api/jobs', 'admin-jobs-message', payload => {
      adminJobs = Array.isArray(payload) ? payload.filter(job => job && typeof job === 'object') : [];
      renderAdminJobs();
    });
  }

  function formatSize(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes)) return '';
    return bytes >= 1024 ** 2 ? `${(bytes / 1024 ** 2).toFixed(1)} MiB` : `${Math.round(bytes / 1024)} KiB`;
  }

  function renderFirmwareImages() {
    const rows = firmwareImages.length ? firmwareImages.map(image => `<tr>
      <td>${escapeHtml(image.filename)}</td><td>${escapeHtml(formatSize(image.size))}</td>
      <td>${escapeHtml((Array.isArray(image.platforms) ? image.platforms : []).join(', '))}</td>
      <td style="font-family: var(--mono)">${escapeHtml(image.sha256 || '')}</td>
      <td>${escapeHtml(image.uploaded_by || '')} · ${escapeHtml(formatTimestamp(image.uploaded_at))}</td>
      <td class="table-actions"><button type="button" class="danger" data-admin-action="delete-firmware-image" data-image-id="${escapeHtml(image.id)}">${escapeHtml(t('Löschen'))}</button></td>
    </tr>`).join('') : `<tr><td colspan="6" class="admin-muted">${escapeHtml(t('Keine Firmware-Images vorhanden.'))}</td></tr>`;
    element('admin-firmware-images').innerHTML = `<table>
      <thead><tr><th>${escapeHtml(t('Datei'))}</th><th>${escapeHtml(t('Größe'))}</th><th>${escapeHtml(t('Plattformen'))}</th>
        <th>SHA-256</th><th>${escapeHtml(t('Hochgeladen'))}</th><th>${escapeHtml(t('Aktionen'))}</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  const JOB_STATUS = () => ({
    pending: t('Geplant'), running: t('Läuft'), done: t('Erledigt'), failed: t('Fehlgeschlagen'), cancelled: t('Abgebrochen'),
  });
  const JOB_KINDS = () => ({ reload: t('Neustart'), 'firmware-stage': t('Firmware-Übertragung') });

  function renderAdminJobs() {
    const rows = adminJobs.length ? adminJobs.map(job => `<tr>
      <td>${escapeHtml(JOB_KINDS()[job.kind] || job.kind)}</td><td>${escapeHtml(job.switch_name || '')}</td>
      <td>${escapeHtml(formatTimestamp(job.run_at))}</td><td>${escapeHtml(JOB_STATUS()[job.status] || job.status)}</td>
      <td>${escapeHtml(job.result?.message || '')}</td><td>${escapeHtml(job.created_by || '')}</td>
      <td class="table-actions">${job.status === 'pending'
        ? `<button type="button" class="danger" data-admin-action="cancel-job" data-job-id="${escapeHtml(job.id)}">${escapeHtml(t('Abbrechen'))}</button>` : ''}</td>
    </tr>`).join('') : `<tr><td colspan="7" class="admin-muted">${escapeHtml(t('Keine Aufgaben.'))}</td></tr>`;
    element('admin-jobs').innerHTML = `<table>
      <thead><tr><th>${escapeHtml(t('Aufgabe'))}</th><th>${escapeHtml(t('Switch'))}</th><th>${escapeHtml(t('Zeitpunkt'))}</th>
        <th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Ergebnis'))}</th><th>${escapeHtml(t('Von'))}</th><th>${escapeHtml(t('Aktionen'))}</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  function cancelJob(target) {
    const job = adminJobs.find(item => String(item.id) === String(target.dataset.jobId));
    if (!job || !confirm(t('Geplante Aufgabe abbrechen?'))) return Promise.resolve();
    return runPanelAction('cancel-job', 'admin-jobs-message',
      () => api(`/api/jobs/${encodeURIComponent(job.id)}`, { method: 'DELETE' }),
      () => {
        setText('admin-jobs-message', '');
        toast(t('Aufgabe abgebrochen.'));
        void loadAdminJobs();
      });
  }

  function deleteFirmwareImage(target) {
    const image = firmwareImages.find(item => String(item.id) === String(target.dataset.imageId));
    if (!image || !confirm(t('Firmware-Image {name} löschen?', { name: image.filename }))) return Promise.resolve();
    return runPanelAction('delete-firmware-image', 'admin-firmware-images-message',
      () => api(`/api/firmware/images/${encodeURIComponent(image.id)}`, { method: 'DELETE' }),
      () => {
        setText('admin-firmware-images-message', '');
        toast(t('Firmware-Image gelöscht.'));
        void loadFirmwareImages();
      });
  }

  // Streams the file with XMLHttpRequest so the upload progress can be shown.
  function sendFirmwareUpload(url, file, onProgress) {
    return new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open('POST', url);
      request.setRequestHeader('Content-Type', 'application/octet-stream');
      if (typeof csrfToken === 'string' && csrfToken) request.setRequestHeader('X-CSRF-Token', csrfToken);
      request.upload.onprogress = event => { if (event.lengthComputable) onProgress(event.loaded / event.total); };
      request.onload = () => {
        let payload = null;
        try { payload = JSON.parse(request.responseText || 'null'); } catch { payload = null; }
        if (request.status >= 200 && request.status < 300) { resolve(payload); return; }
        const detail = payload?.detail;
        const message = typeof detail === 'string' ? detail : (detail?.message || t('Upload fehlgeschlagen (HTTP {status}).', { status: request.status }));
        reject(Object.assign(new Error(message), { status: request.status }));
      };
      request.onerror = () => reject(new Error(t('Upload fehlgeschlagen: Verbindung unterbrochen.')));
      request.send(file);
    });
  }

  function uploadFirmwareImage() {
    if (runningActions.has('upload-firmware-image')) return Promise.resolve();
    const file = element('admin-firmware-file')?.files?.[0];
    const platforms = firmwareDrivers.map(driver => driver.id).filter(id => checked(`admin-firmware-platform-${id}`));
    if (!file) {
      setText('admin-firmware-images-message', t('Bitte eine Image-Datei auswählen.'), true);
      return Promise.resolve();
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(file.name)) {
      setText('admin-firmware-images-message', t('Ungültiger Dateiname. Erlaubt sind Buchstaben, Ziffern, Punkt, Binde- und Unterstrich.'), true);
      return Promise.resolve();
    }
    if (!platforms.length) {
      setText('admin-firmware-images-message', t('Bitte mindestens eine Plattform auswählen.'), true);
      return Promise.resolve();
    }
    const progress = element('admin-firmware-progress');
    const url = `/api/firmware/images?filename=${encodeURIComponent(file.name)}&platforms=${encodeURIComponent(platforms.join(','))}`;
    progress.value = 0;
    progress.classList.remove('hidden');
    return runPanelAction('upload-firmware-image', 'admin-firmware-images-message',
      () => sendFirmwareUpload(url, file, fraction => { progress.value = Math.round(fraction * 100); }),
      () => {
        setText('admin-firmware-images-message', '');
        toast(t('Firmware-Image hochgeladen.'));
        void loadFirmwareImages();
      }).finally(() => progress.classList.add('hidden'));
  }

  function resolvedPathHint(path) {
    return path ? `<small class="admin-muted">${escapeHtml(t('Aufgelöster Pfad: {path}', { path }))}</small>` : '';
  }

  function saveButton(action) {
    return `<div class="flex-row" style="justify-content: flex-end;">
        <button class="primary" type="button" data-admin-action="${action}">${escapeHtml(t('Speichern'))}</button>
      </div>`;
  }

  function renderBackupPanel(settings) {
    const backups = settings.backups || {};
    const encryption = backups.encryption === 'password' ? 'password' : 'none';
    const passwordPlaceholder = backups.password_configured === true ? t('Gespeichert – leer lassen zum Beibehalten') : '';
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Konfigurations-Backups'))}</h3>
      <p class="admin-muted">${escapeHtml(t('Backups entstehen automatisch vor und nach jedem „Config speichern“ und vor jeder Wiederherstellung.'))}</p>
      <div class="field"><label for="admin-backup-directory">${escapeHtml(t('Verzeichnis'))}</label>
        <input id="admin-backup-directory" value="${escapeHtml(backups.directory || '')}" spellcheck="false" autocomplete="off">
        ${resolvedPathHint(backups.resolved_directory)}
      </div>
      <div class="field"><label for="admin-backup-retention">${escapeHtml(t('Aufbewahrte Backups pro Switch'))}</label>
        <input id="admin-backup-retention" type="number" min="1" max="1000" step="1" value="${escapeHtml(backups.retention ?? 30)}">
      </div>
      <div class="field"><label for="admin-backup-encryption">${escapeHtml(t('Verschlüsselung'))}</label>
        <select id="admin-backup-encryption">
          <option value="none"${selectedAttr(encryption, 'none')}>${escapeHtml(t('Keine (Klartext, nur für den Server-Benutzer lesbar)'))}</option>
          <option value="password"${selectedAttr(encryption, 'password')}>${escapeHtml(t('Mit Passwort'))}</option>
        </select>
      </div>
      <div class="field"><label for="admin-backup-password">${escapeHtml(t('Backup-Passwort'))}</label>
        <input id="admin-backup-password" type="password" autocomplete="new-password" placeholder="${escapeHtml(passwordPlaceholder)}">
        <small class="admin-muted">${escapeHtml(t('Mindestens 12 Zeichen. Nur nötig beim Wechsel auf „Mit Passwort“ oder zum Ändern des Passworts; vorhandene Backups werden umgewandelt.'))}</small>
      </div>
      <div class="wlan-warning-box">${escapeHtml(t('Ohne das Passwort lassen sich verschlüsselte Backups nicht lesen. Offline entschlüsseln: python -m app.manage decrypt-backup DATEI'))}</div>
      <p id="admin-backup-message" role="status"></p>
      ${saveButton('save-backups')}
    </div>`;
  }

  function renderTransferPanel(settings) {
    const transfer = settings.transfer || {};
    const status = transfer.sftp_running === true ? t('SFTP-Server läuft.') : t('SFTP-Server läuft nicht.');
    const fingerprint = transfer.sftp_host_key_fingerprint
      ? `<p>${escapeHtml(t('Host-Key-Fingerprint: {fingerprint}', { fingerprint: transfer.sftp_host_key_fingerprint }))}</p>`
      : '';
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Dateitransfer zu den Switches'))}</h3>
      <p class="admin-muted">${escapeHtml(t('Switches laden Wiederherstellungen und Firmware selbst von SwitchSteward: Cisco und MikroTik per HTTP(S), Aruba und Netgear per SFTP.'))}</p>
      <div class="field"><label for="admin-transfer-base-url">${escapeHtml(t('Transfer-Adresse'))}</label>
        <input id="admin-transfer-base-url" value="${escapeHtml(transfer.base_url || '')}" placeholder="http://192.0.2.10:8000" spellcheck="false" autocomplete="off">
        <small class="admin-muted">${escapeHtml(t('Adresse, unter der die Switches SwitchSteward erreichen (ohne Pfad). Für Cisco wird http:// im Management-Netz empfohlen.'))}</small>
      </div>
      <div class="field"><label for="admin-transfer-token-minutes">${escapeHtml(t('Gültigkeit der Firmware-Downloads (Minuten)'))}</label>
        <input id="admin-transfer-token-minutes" type="number" min="5" max="1440" step="1" value="${escapeHtml(transfer.token_minutes ?? 120)}">
      </div>
      <h4>${escapeHtml(t('SFTP-Server'))}</h4>
      <label class="admin-check"><input id="admin-transfer-sftp-enabled" type="checkbox"${checkedAttr(transfer.sftp_enabled === true)}> ${escapeHtml(t('Eingebauten SFTP-Server aktivieren (nur lesend)'))}</label>
      <div class="flex-row">
        <div class="field"><label for="admin-transfer-sftp-bind">${escapeHtml(t('Bind-Adresse'))}</label><input id="admin-transfer-sftp-bind" value="${escapeHtml(transfer.sftp_bind || '0.0.0.0')}" spellcheck="false" autocomplete="off"></div>
        <div class="field"><label for="admin-transfer-sftp-port">${escapeHtml(t('Port'))}</label><input id="admin-transfer-sftp-port" type="number" min="1" max="65535" step="1" value="${escapeHtml(transfer.sftp_port ?? 2222)}"></div>
      </div>
      <div class="field"><label for="admin-transfer-sftp-host">${escapeHtml(t('Adresse für Switches (leer = Host der Transfer-Adresse)'))}</label>
        <input id="admin-transfer-sftp-host" value="${escapeHtml(transfer.sftp_host || '')}" spellcheck="false" autocomplete="off">
      </div>
      <p class="admin-muted">${escapeHtml(t('AOS-S und Netgear laden per SFTP nur von Port 22.'))}</p>
      <p>${escapeHtml(status)}</p>
      ${fingerprint}
      <p id="admin-transfer-message" role="status"></p>
      ${saveButton('save-transfer')}
    </div>`;
  }

  function renderFirmwarePanel(settings) {
    const firmware = settings.firmware || {};
    return `<div class="panel-box">
      <h3>${escapeHtml(t('Firmware-Ablage'))}</h3>
      <div class="field"><label for="admin-firmware-directory">${escapeHtml(t('Verzeichnis'))}</label>
        <input id="admin-firmware-directory" value="${escapeHtml(firmware.directory || '')}" spellcheck="false" autocomplete="off">
        ${resolvedPathHint(firmware.resolved_directory)}
      </div>
      <p id="admin-firmware-message" role="status"></p>
      ${saveButton('save-firmware')}
    </div>`;
  }

  function saveOperationsPanel(action, messageId, path, body) {
    return runPanelAction(action, messageId,
      () => api(`${ADMIN_API}/operations-settings/${path}`, { method: 'PUT', body: JSON.stringify(body) }),
      payload => {
        toast(t('Einstellungen gespeichert.'));
        applyOperationsSettings(payload);
      });
  }

  function saveBackups() {
    if (runningActions.has('save-backups')) return Promise.resolve();
    const encryption = fieldValue('admin-backup-encryption') === 'password' ? 'password' : 'none';
    const passwordField = element('admin-backup-password');
    const password = String(passwordField?.value ?? '');
    const body = {
      directory: fieldValue('admin-backup-directory'),
      retention: Number(fieldValue('admin-backup-retention')),
      encryption,
    };
    if (encryption === 'password' && password) {
      if (password.length < 12) {
        setText('admin-backup-message', t('Das Backup-Passwort muss mindestens 12 Zeichen lang sein.'), true);
        return Promise.resolve();
      }
      body.password = password;
    }
    if (passwordField) passwordField.value = '';
    return saveOperationsPanel('save-backups', 'admin-backup-message', 'backups', body);
  }

  function saveTransfer() {
    return saveOperationsPanel('save-transfer', 'admin-transfer-message', 'transfer', {
      base_url: fieldValue('admin-transfer-base-url') || null,
      token_minutes: Number(fieldValue('admin-transfer-token-minutes')),
      sftp_enabled: checked('admin-transfer-sftp-enabled'),
      sftp_bind: fieldValue('admin-transfer-sftp-bind'),
      sftp_port: Number(fieldValue('admin-transfer-sftp-port')),
      sftp_host: fieldValue('admin-transfer-sftp-host') || null,
    });
  }

  function saveFirmware() {
    return saveOperationsPanel('save-firmware', 'admin-firmware-message', 'firmware', {
      directory: fieldValue('admin-firmware-directory'),
    });
  }

  // --- Port profiles ---------------------------------------------------

  const PROFILE_NAME_PATTERN = /^[A-Za-z0-9 ._-]{1,64}$/;
  // Port part of a profile: port-configure field -> control (type, range for numbers).
  const PROFILE_PORT_FIELDS = [
    { key: 'description', id: 'profile-port-description', type: 'text' },
    { key: 'mode', id: 'profile-port-mode', type: 'text' },
    { key: 'access_vlan', id: 'profile-port-access-vlan', type: 'int', min: 1, max: 4094, label: () => t('Access VLAN') },
    { key: 'voice_vlan', id: 'profile-port-voice-vlan', type: 'int', min: 0, max: 4094, label: () => t('Voice-VLAN') },
    { key: 'native_vlan', id: 'profile-port-native-vlan', type: 'int', min: 1, max: 4094, label: () => t('Native VLAN') },
    { key: 'trunk_allowed_vlan', id: 'profile-port-trunk-allowed', type: 'text' },
    { key: 'edge_port', id: 'profile-port-edge', type: 'bool' },
    { key: 'speed', id: 'profile-port-speed', type: 'text' },
    { key: 'duplex', id: 'profile-port-duplex', type: 'text' },
    { key: 'poe_mode', id: 'profile-port-poe-mode', type: 'text' },
    { key: 'poe_standard', id: 'profile-port-poe-standard', type: 'text' },
  ];

  function loadPortProfiles() {
    return loadSection(`${ADMIN_API}/port-profiles`, payload => {
      portProfiles = Array.isArray(payload?.profiles) ? payload.profiles.filter(profile => profile && typeof profile === 'object') : [];
      renderPortProfiles();
    });
  }

  function profileSettingsText(settings) {
    const port = settings?.port && typeof settings.port === 'object' ? settings.port : {};
    const security = settings?.security && typeof settings.security === 'object' ? settings.security : {};
    const parts = [];
    const portItems = Object.entries(port).map(([key, value]) => `${key}=${value}`);
    if (portItems.length) parts.push(t('Port: {items}', { items: portItems.join(', ') }));
    if (Object.keys(security).length) parts.push(t('Sicherheit: {items}', { items: Object.keys(security).join(', ') }));
    return parts.join(' · ') || '—';
  }

  function renderPortProfiles() {
    const rows = portProfiles.length
      ? portProfiles.map(profile => {
        const id = escapeHtml(profile.id);
        return `<tr>
          <td>${escapeHtml(profile.name)}</td>
          <td>${escapeHtml(profile.description || '—')}</td>
          <td>${escapeHtml(profileSettingsText(profile.settings))}</td>
          <td>${escapeHtml(profile.updated_by || '—')}</td>
          <td>${escapeHtml(formatTimestamp(profile.updated_at))}</td>
          <td class="table-actions"><div class="table-actions-inner">
            <button type="button" data-admin-action="edit-port-profile" data-profile-id="${id}">${escapeHtml(t('Bearbeiten'))}</button>
            <button type="button" class="danger" data-admin-action="delete-port-profile" data-profile-id="${id}">${escapeHtml(t('Löschen'))}</button>
          </div></td>
        </tr>`;
      }).join('')
      : `<tr><td colspan="6" class="admin-muted">${escapeHtml(t('Keine Port-Profile vorhanden.'))}</td></tr>`;
    mainContent().innerHTML = `<div class="admin-section">
      <div class="flex-row" style="justify-content: space-between;">
        <h2>${escapeHtml(t('Port-Profile'))}</h2>
        <button class="primary" type="button" data-admin-action="create-port-profile">${escapeHtml(t('Port-Profil anlegen'))}</button>
      </div>
      <p class="admin-muted">${escapeHtml(t('Administratoren wenden Profile im Port-Dialog an. Nicht unterstützte Felder werden ausgelassen und gemeldet.'))}</p>
      <div class="panel-box"><table>
        <thead><tr>
          <th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Beschreibung'))}</th><th>${escapeHtml(t('Einstellungen'))}</th>
          <th>${escapeHtml(t('Geändert von'))}</th><th>${escapeHtml(t('Geändert am'))}</th><th>${escapeHtml(t('Aktionen'))}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`;
  }

  const findPortProfile = id => portProfiles.find(profile => String(profile.id) === String(id)) || null;

  function openPortProfileModal(profile = null) {
    if (!isAdminSession()) return;
    profileModalState = { profile, session: currentSession };
    element('admin-profile-modal-title').textContent = profile ? t('Port-Profil bearbeiten') : t('Port-Profil anlegen');
    element('admin-profile-name').value = profile ? String(profile.name ?? '') : '';
    element('admin-profile-description').value = profile ? String(profile.description ?? '') : '';
    const port = profile?.settings?.port || {};
    PROFILE_PORT_FIELDS.forEach(field => {
      const value = port[field.key];
      element(field.id).value = value === null || value === undefined ? '' : String(value);
    });
    fillSecurityForm('profile-sec', profile?.settings?.security || {});
    setText('admin-profile-modal-error', '');
    setElementHidden('admin-profile-modal', false);
    element('admin-profile-name').focus?.();
  }

  function closePortProfileModal() {
    if (modalOperations.has('admin-profile-modal')) return;
    profileModalState = null;
    setElementHidden('admin-profile-modal', true);
  }

  function forceClosePortProfileModal() {
    const operation = modalOperations.get('admin-profile-modal');
    if (operation) finishModalOperation(operation);
    profileModalState = null;
    setElementHidden('admin-profile-modal', true);
  }

  function profilePortSettings() {
    const port = {};
    for (const field of PROFILE_PORT_FIELDS) {
      const raw = fieldValue(field.id);
      if (!raw) continue;
      if (field.type === 'bool') port[field.key] = raw === 'true';
      else if (field.type === 'int') {
        const number = Number(raw);
        if (!/^\d+$/.test(raw) || number < field.min || number > field.max) {
          throw new Error(t('{field}: Bitte eine ganze Zahl von {min} bis {max} eingeben.', { field: field.label(), min: field.min, max: field.max }));
        }
        port[field.key] = number;
      } else port[field.key] = raw;
    }
    return port;
  }

  function portProfileBody() {
    const name = fieldValue('admin-profile-name');
    if (!PROFILE_NAME_PATTERN.test(name)) {
      return { error: t('Der Profilname darf 1–64 Zeichen aus Buchstaben, Ziffern, Leerzeichen, Punkt, Unterstrich und Bindestrich enthalten.') };
    }
    let port;
    let security;
    try {
      port = profilePortSettings();
      security = readSecurityForm('profile-sec');
    } catch (failure) {
      return { error: failure.message };
    }
    const settings = {};
    if (Object.keys(port).length) settings.port = port;
    if (Object.keys(security).length) settings.security = security;
    if (!settings.port && !settings.security) return { error: t('Ein Port-Profil benötigt Port- oder Sicherheitseinstellungen.') };
    return { body: { name, description: fieldValue('admin-profile-description') || null, settings } };
  }

  async function savePortProfile() {
    const state = profileModalState;
    if (!state || state.session !== currentSession || !isAdminSession()) return;
    const { body, error } = portProfileBody();
    if (error) {
      setText('admin-profile-modal-error', error, true);
      return;
    }
    const operation = beginModalOperation('admin-profile-modal');
    if (!operation) return;
    setText('admin-profile-modal-error', '');
    const path = state.profile
      ? `${ADMIN_API}/port-profiles/${encodeURIComponent(state.profile.id)}` : `${ADMIN_API}/port-profiles`;
    try {
      await api(path, { method: state.profile ? 'PUT' : 'POST', body: JSON.stringify(body) });
      if (!modalOperationIsCurrent(operation) || profileModalState !== state) return;
      finishModalOperation(operation);
      closePortProfileModal();
      toast(state.profile ? t('Port-Profil gespeichert.') : t('Port-Profil angelegt.'));
      if (isAdminWorkspace() && activeSection === 'port-profiles') void loadPortProfiles();
    } catch (failure) {
      if (!modalOperationIsCurrent(operation) || profileModalState !== state) return;
      setText('admin-profile-modal-error', failure.message, true);
    } finally {
      finishModalOperation(operation);
    }
  }

  async function deletePortProfile(profile) {
    if (!profile || !confirm(t('Port-Profil „{name}“ löschen?', { name: profile.name }))) return;
    const sequence = adminDataSequence;
    const session = currentSession;
    try {
      await api(`${ADMIN_API}/port-profiles/${encodeURIComponent(profile.id)}`, { method: 'DELETE' });
      if (!adminSessionIsCurrent(sequence, session)) return;
      toast(t('Port-Profil gelöscht.'));
      void loadPortProfiles();
    } catch (failure) {
      if (!adminSessionIsCurrent(sequence, session)) return;
      toast(failure.message, true);
    }
  }

  // --- Users -----------------------------------------------------------

  function loadUsers() {
    return loadSection(`${ADMIN_API}/users`, payload => {
      adminUsers = Array.isArray(payload) ? payload.filter(user => user && typeof user === 'object') : [];
      renderUsers();
    });
  }

  const ROLES = ['admin', 'operator', 'viewer'];
  const knownRole = role => ROLES.includes(role);

  function userRoleText(user) {
    if (knownRole(user.assigned_role)) return roleLabel(user.assigned_role);
    const derived = knownRole(user.last_role)
      ? ` (${roleLabel(user.last_role)})` : '';
    return t('Aus Gruppen ermitteln') + derived;
  }

  function renderUserRow(user) {
    const id = escapeHtml(user.id);
    const enabled = user.enabled === true || user.enabled === 1;
    return `<tr>
      <td>${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.display_name || '')}</td>
      <td>${escapeHtml(providerLabel(user.provider))}</td>
      <td>${escapeHtml(userRoleText(user))}</td>
      <td>${escapeHtml(enabled ? t('Aktiv') : t('Gesperrt'))}</td>
      <td>${escapeHtml(formatTimestamp(user.last_login_at))}</td>
      <td>${escapeHtml(Number(user.active_sessions) || 0)}</td>
      <td class="table-actions"><div class="table-actions-inner">
        <button type="button" data-admin-action="edit-user" data-user-id="${id}">${escapeHtml(t('Bearbeiten'))}</button>
        <button type="button" data-admin-action="revoke-user" data-user-id="${id}">${escapeHtml(t('Sitzungen beenden'))}</button>
        <button type="button" class="danger" data-admin-action="delete-user" data-user-id="${id}">${escapeHtml(t('Löschen'))}</button>
      </div></td>
    </tr>`;
  }

  function renderUsers() {
    const rows = adminUsers.length
      ? adminUsers.map(renderUserRow).join('')
      : `<tr><td colspan="8" class="admin-muted">${escapeHtml(t('Keine Benutzer vorhanden.'))}</td></tr>`;
    mainContent().innerHTML = `<div class="admin-section">
      <div class="flex-row" style="justify-content: space-between;">
        <h2>${escapeHtml(t('Benutzer'))}</h2>
        <button class="primary" type="button" data-admin-action="create-user">${escapeHtml(t('Lokalen Benutzer anlegen'))}</button>
      </div>
      <p class="admin-muted">${escapeHtml(t('Externe Benutzer werden bei ihrer ersten Anmeldung angelegt.'))}</p>
      <div class="panel-box"><table>
        <thead><tr>
          <th>${escapeHtml(t('Benutzer'))}</th><th>${escapeHtml(t('Anzeigename'))}</th><th>${escapeHtml(t('Anmeldeweg'))}</th>
          <th>${escapeHtml(t('Rolle'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Letzte Anmeldung'))}</th>
          <th>${escapeHtml(t('Sitzungen'))}</th><th>${escapeHtml(t('Aktionen'))}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`;
  }

  const findUser = id => adminUsers.find(user => String(user.id) === String(id)) || null;

  function setRoleOptions(select, includeDerived) {
    const options = [];
    if (includeDerived) options.push(`<option value="">${escapeHtml(t('Aus Gruppen ermitteln'))}</option>`);
    options.push(`<option value="admin">${escapeHtml(t('Administrator'))}</option>`);
    options.push(`<option value="operator">${escapeHtml(t('Operator'))}</option>`);
    options.push(`<option value="viewer">${escapeHtml(t('Nur lesen'))}</option>`);
    select.innerHTML = options.join('');
  }

  function clearUserPasswordFields() {
    ['admin-user-password', 'admin-user-password-confirm'].forEach(id => {
      const field = element(id);
      if (field) field.value = '';
    });
  }

  function openUserModal(user = null) {
    if (!isAdminSession()) return;
    const local = !user || user.provider === 'local';
    userModalState = { user, session: currentSession };
    element('admin-user-modal-title').textContent = user ? t('Benutzer bearbeiten') : t('Lokalen Benutzer anlegen');
    element('admin-user-provider').textContent = user
      ? t('Anmeldeweg: {provider}', { provider: providerLabel(user.provider) }) : '';
    const username = element('admin-user-username');
    username.value = user ? String(user.username ?? '') : '';
    username.disabled = Boolean(user);
    element('admin-user-display-name').value = user ? String(user.display_name ?? '') : '';
    const role = element('admin-user-role');
    setRoleOptions(role, !local);
    role.value = user ? (user.assigned_role || (local ? 'viewer' : '')) : 'viewer';
    setElementHidden('admin-user-enabled-field', !user);
    element('admin-user-enabled').checked = user ? (user.enabled === true || user.enabled === 1) : true;
    setElementHidden('admin-user-password-fields', !local);
    clearUserPasswordFields();
    element('admin-user-password-help').textContent = user
      ? t('Leer lassen, um das Passwort beizubehalten. Mindestens 12 Zeichen.')
      : t('Mindestens 12 Zeichen.');
    setText('admin-user-modal-error', '');
    setElementHidden('admin-user-modal', false);
    (user ? element('admin-user-display-name') : username).focus?.();
  }

  function closeUserModal() {
    if (modalOperations.has('admin-user-modal')) return;
    userModalState = null;
    clearUserPasswordFields();
    setElementHidden('admin-user-modal', true);
  }

  function forceCloseUserModal() {
    const operation = modalOperations.get('admin-user-modal');
    if (operation) finishModalOperation(operation);
    userModalState = null;
    clearUserPasswordFields();
    setElementHidden('admin-user-modal', true);
  }

  function passwordError(password) {
    if (password.length < 12 || password.length > 1024) return t('Das Passwort muss 12 bis 1024 Zeichen lang sein.');
    if (/[\u0000-\u001f\u007f]/.test(password)) return t('Das Passwort darf keine Steuerzeichen enthalten.');
    return '';
  }

  function userModalBody(state) {
    const user = state.user;
    const local = !user || user.provider === 'local';
    const password = local ? String(element('admin-user-password').value) : '';
    const confirmation = local ? String(element('admin-user-password-confirm').value) : '';
    const displayName = fieldValue('admin-user-display-name') || null;
    const role = fieldValue('admin-user-role');
    if (!user) {
      const username = fieldValue('admin-user-username');
      if (!USERNAME_PATTERN.test(username)) {
        return { error: t('Benutzername: 1–64 Zeichen aus Buchstaben, Ziffern sowie . _ @ -') };
      }
      if (!password) return { error: t('Bitte ein Passwort angeben.') };
    }
    if (password || confirmation) {
      const error = passwordError(password);
      if (error) return { error };
      if (password !== confirmation) return { error: t('Die Passwörter stimmen nicht überein.') };
    }
    if (!user) {
      return { body: { username: fieldValue('admin-user-username'), display_name: displayName, password, role: knownRole(role) ? role : 'viewer' } };
    }
    const body = {
      display_name: displayName,
      assigned_role: knownRole(role) ? role : (local ? 'viewer' : null),
      enabled: checked('admin-user-enabled'),
    };
    if (password) body.password = password;
    return { body };
  }

  async function saveUser() {
    const state = userModalState;
    if (!state || state.session !== currentSession || !isAdminSession()) return;
    const { body, error } = userModalBody(state);
    if (error) {
      setText('admin-user-modal-error', error, true);
      return;
    }
    const operation = beginModalOperation('admin-user-modal');
    if (!operation) return;
    setText('admin-user-modal-error', '');
    const path = state.user ? `${ADMIN_API}/users/${encodeURIComponent(state.user.id)}` : `${ADMIN_API}/users`;
    try {
      await api(path, { method: state.user ? 'PUT' : 'POST', body: JSON.stringify(body) });
      if (!modalOperationIsCurrent(operation) || userModalState !== state) return;
      finishModalOperation(operation);
      closeUserModal();
      toast(state.user ? t('Benutzer gespeichert.') : t('Benutzer angelegt.'));
      if (isAdminWorkspace() && activeSection === 'users') void loadUsers();
    } catch (failure) {
      if (!modalOperationIsCurrent(operation) || userModalState !== state) return;
      setText('admin-user-modal-error', failure.message, true);
    } finally {
      body.password = null;
      clearUserPasswordFields();
      finishModalOperation(operation);
    }
  }

  async function runUserAction(request, successMessage) {
    const sequence = adminDataSequence;
    const session = currentSession;
    try {
      await request();
      if (!adminSessionIsCurrent(sequence, session)) return;
      toast(successMessage);
      void loadUsers();
    } catch (error) {
      if (!adminSessionIsCurrent(sequence, session)) return;
      toast(error.message, true);
    }
  }

  function revokeUserSessions(user) {
    if (!user || !confirm(t('Alle Sitzungen von „{name}“ beenden?', { name: user.username }))) return Promise.resolve();
    return runUserAction(
      () => api(`${ADMIN_API}/users/${encodeURIComponent(user.id)}/revoke-sessions`, { method: 'POST' }),
      t('Sitzungen beendet.'));
  }

  function deleteUser(user) {
    if (!user || !confirm(t('Benutzer „{name}“ löschen?', { name: user.username }))) return Promise.resolve();
    return runUserAction(
      () => api(`${ADMIN_API}/users/${encodeURIComponent(user.id)}`, { method: 'DELETE' }),
      t('Benutzer gelöscht.'));
  }

  // --- Group mappings --------------------------------------------------

  function loadMappings() {
    return loadSection(`${ADMIN_API}/group-mappings`, payload => {
      groupMappings = Array.isArray(payload) ? payload.filter(mapping => mapping && typeof mapping === 'object') : [];
      renderMappings();
    });
  }

  function renderMappingTable(provider) {
    const entries = groupMappings.filter(mapping => mapping.provider === provider);
    const rows = entries.length ? entries.map(mapping => {
      const id = escapeHtml(mapping.id);
      return `<tr>
        <td><div>${escapeHtml(mapping.label || '')}</div><div class="admin-muted admin-group-id">${escapeHtml(mapping.group_id)}</div></td>
        <td>${escapeHtml(roleLabel(mapping.role))}</td>
        <td class="table-actions"><div class="table-actions-inner">
          <button type="button" data-admin-action="edit-mapping" data-mapping-id="${id}">${escapeHtml(t('Bearbeiten'))}</button>
          <button type="button" class="danger" data-admin-action="delete-mapping" data-mapping-id="${id}">${escapeHtml(t('Löschen'))}</button>
        </div></td>
      </tr>`;
    }).join('') : `<tr><td colspan="3" class="admin-muted">${escapeHtml(t('Keine Zuordnungen.'))}</td></tr>`;
    return `<div class="panel-box">
      <h3>${escapeHtml(providerLabel(provider))}</h3>
      <table>
        <thead><tr><th>${escapeHtml(t('Gruppe'))}</th><th>${escapeHtml(t('Rolle'))}</th><th>${escapeHtml(t('Aktionen'))}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }

  function renderMappings() {
    mainContent().innerHTML = `<div class="admin-section">
      <div class="flex-row" style="justify-content: space-between;">
        <h2>${escapeHtml(t('Gruppenzuordnung'))}</h2>
        <button class="primary" type="button" data-admin-action="create-mapping">${escapeHtml(t('Zuordnung hinzufügen'))}</button>
      </div>
      <p class="admin-muted">${escapeHtml(t('Änderungen gelten ab der nächsten Anmeldung.'))}</p>
      ${renderMappingTable('ad')}
      ${renderMappingTable('entra')}
    </div>`;
  }

  const findMapping = id => groupMappings.find(mapping => String(mapping.id) === String(id)) || null;

  function updateMappingPlaceholder() {
    const provider = fieldValue('admin-mapping-provider');
    element('admin-mapping-group-id').setAttribute('placeholder', provider === 'entra'
      ? t('Objekt-ID der Gruppe, z. B. 00000000-0000-0000-0000-000000000000')
      : t('DN der Gruppe, z. B. CN=Switch-Admins,OU=Groups,DC=example,DC=org'));
  }

  function openMappingModal(mapping = null) {
    if (!isAdminSession()) return;
    mappingModalState = { mapping, session: currentSession };
    element('admin-mapping-modal-title').textContent = mapping ? t('Zuordnung bearbeiten') : t('Zuordnung hinzufügen');
    const provider = element('admin-mapping-provider');
    provider.value = mapping?.provider === 'entra' ? 'entra' : 'ad';
    provider.disabled = Boolean(mapping);
    const groupId = element('admin-mapping-group-id');
    groupId.value = mapping ? String(mapping.group_id ?? '') : '';
    groupId.disabled = Boolean(mapping);
    element('admin-mapping-label').value = mapping ? String(mapping.label ?? '') : '';
    element('admin-mapping-role').value = knownRole(mapping?.role) ? mapping.role : 'viewer';
    updateMappingPlaceholder();
    setText('admin-mapping-modal-error', '');
    setElementHidden('admin-mapping-modal', false);
    (mapping ? element('admin-mapping-label') : groupId).focus?.();
  }

  function closeMappingModal() {
    if (modalOperations.has('admin-mapping-modal')) return;
    mappingModalState = null;
    setElementHidden('admin-mapping-modal', true);
  }

  function forceCloseMappingModal() {
    const operation = modalOperations.get('admin-mapping-modal');
    if (operation) finishModalOperation(operation);
    mappingModalState = null;
    setElementHidden('admin-mapping-modal', true);
  }

  function mappingModalBody(state) {
    const label = fieldValue('admin-mapping-label') || null;
    const role = knownRole(fieldValue('admin-mapping-role')) ? fieldValue('admin-mapping-role') : 'viewer';
    if (state.mapping) return { body: { label, role } };
    const provider = fieldValue('admin-mapping-provider') === 'entra' ? 'entra' : 'ad';
    const groupId = fieldValue('admin-mapping-group-id');
    if (provider === 'ad' && (!groupId.includes('=') || groupId.length > 1024)) {
      return { error: t('Für Active Directory den Distinguished Name der Gruppe angeben (z. B. CN=…,DC=…).') };
    }
    if (provider === 'entra' && !GUID_PATTERN.test(groupId)) {
      return { error: t('Für Microsoft Entra ID die Objekt-ID (GUID) der Gruppe angeben.') };
    }
    return { body: { provider, group_id: provider === 'entra' ? groupId.toLowerCase() : groupId, label, role } };
  }

  async function saveMapping() {
    const state = mappingModalState;
    if (!state || state.session !== currentSession || !isAdminSession()) return;
    const { body, error } = mappingModalBody(state);
    if (error) {
      setText('admin-mapping-modal-error', error, true);
      return;
    }
    const operation = beginModalOperation('admin-mapping-modal');
    if (!operation) return;
    setText('admin-mapping-modal-error', '');
    const path = state.mapping
      ? `${ADMIN_API}/group-mappings/${encodeURIComponent(state.mapping.id)}` : `${ADMIN_API}/group-mappings`;
    try {
      await api(path, { method: state.mapping ? 'PUT' : 'POST', body: JSON.stringify(body) });
      if (!modalOperationIsCurrent(operation) || mappingModalState !== state) return;
      finishModalOperation(operation);
      closeMappingModal();
      toast(t('Zuordnung gespeichert. Änderungen gelten ab der nächsten Anmeldung.'));
      if (isAdminWorkspace() && activeSection === 'mappings') void loadMappings();
    } catch (failure) {
      if (!modalOperationIsCurrent(operation) || mappingModalState !== state) return;
      setText('admin-mapping-modal-error', failure.message, true);
    } finally {
      finishModalOperation(operation);
    }
  }

  async function deleteMapping(mapping) {
    if (!mapping) return;
    const name = mapping.label || mapping.group_id;
    if (!confirm(t('Zuordnung „{name}“ löschen?', { name }))) return;
    const sequence = adminDataSequence;
    const session = currentSession;
    try {
      await api(`${ADMIN_API}/group-mappings/${encodeURIComponent(mapping.id)}`, { method: 'DELETE' });
      if (!adminSessionIsCurrent(sequence, session)) return;
      toast(t('Zuordnung gelöscht.'));
      void loadMappings();
    } catch (error) {
      if (!adminSessionIsCurrent(sequence, session)) return;
      toast(error.message, true);
    }
  }

  // --- Audit log and system log ---------------------------------------

  function auditProviderLabel(provider) {
    const labels = {
      ad: t('Active Directory'),
      local: t('Lokal'),
      entra: t('Microsoft Entra ID'),
      system: t('System'),
    };
    return labels[provider] || provider || '-';
  }

  function renderLogSection({ title, refreshAction, downloadAction, hint, tableId, headers, rows }) {
    const table = rows.length
      ? `<table id="${tableId}" class="log-table" aria-label="${escapeHtml(title)}">
          <thead><tr>${headers.map(header => `<th>${escapeHtml(header)}</th>`).join('')}</tr></thead>
          <tbody>${rows.join('')}</tbody>
        </table>`
      : `<div class="empty-state">${escapeHtml(t('Noch keine Einträge.'))}</div>`;
    mainContent().innerHTML = `<div class="admin-section">
      <div class="flex-row" style="justify-content: space-between;">
        <h2>${escapeHtml(title)}</h2>
        <div class="flex-row">
          <button type="button" data-admin-action="${refreshAction}">${escapeHtml(t('Aktualisieren'))}</button>
          <button type="button" data-admin-action="${downloadAction}">${escapeHtml(t('Download'))}</button>
        </div>
      </div>
      <p class="admin-muted">${escapeHtml(hint)}</p>
      <div class="panel-box log-table-wrap">${table}</div>
    </div>`;
  }

  function loadAudit() {
    return loadSection('/api/audit-log', payload => {
      auditEntries = Array.isArray(payload) ? payload : [];
      renderAudit();
    });
  }

  function renderAudit() {
    const rows = auditEntries.map(e => `<tr class="${e.status === 'error' ? 'log-row-error' : ''}">
        <td>${escapeHtml(e.ts)}</td>
        <td>${escapeHtml(e.username)}</td>
        <td>${escapeHtml(auditProviderLabel(e.auth_provider))}</td>
        <td>${escapeHtml(e.client_ip || '-')}</td>
        <td>${escapeHtml(e.switch_name || '-')}</td>
        <td>${escapeHtml(e.interface || '-')}</td>
        <td>${escapeHtml(e.action)}</td>
        <td class="log-message">${escapeHtml(e.detail || '')}</td>
      </tr>`);
    renderLogSection({
      title: t('Audit-Log'),
      refreshAction: 'refresh-audit',
      downloadAction: 'download-audit',
      hint: t('Die neuesten {count} Audit-Einträge. Der Download enthält die vollständigen Audit-Log-Dateien.', { count: auditEntries.length }),
      tableId: 'admin-audit-table',
      headers: [t('Zeit'), t('Benutzer'), t('Anmeldeweg'), t('Client-IP'), t('Ziel'), t('Interface'), t('Aktion'), t('Detail')],
      rows,
    });
    if (rows.length) makeColumnsResizable(element('admin-audit-table'), 'audit');
  }

  function loadSystemLog() {
    return loadSection(`${ADMIN_API}/logs/system?limit=500`, payload => {
      systemLogEntries = Array.isArray(payload) ? payload : [];
      renderSystemLog();
    });
  }

  function systemLogRowClass(level) {
    if (level === 'ERROR' || level === 'CRITICAL') return 'log-row-error';
    if (level === 'WARNING') return 'log-row-warning';
    return '';
  }

  function renderSystemLog() {
    const rows = systemLogEntries.map(entry => `<tr class="${systemLogRowClass(entry.level)}">
        <td>${escapeHtml(entry.ts)}</td>
        <td>${escapeHtml(entry.level)}</td>
        <td>${escapeHtml(entry.logger)}</td>
        <td>${escapeHtml(entry.request_id)}</td>
        <td class="log-message">${escapeHtml(entry.message)}</td>
      </tr>`);
    renderLogSection({
      title: t('System-Log'),
      refreshAction: 'refresh-system-log',
      downloadAction: 'download-system-log',
      hint: t('Die neuesten {count} Einträge aus system.log. Der Download enthält alle Dateien einschließlich rotierter Logs.', { count: systemLogEntries.length }),
      tableId: 'admin-system-log-table',
      headers: [t('Zeit'), t('Level'), t('Logger'), t('Request-ID'), t('Meldung')],
      rows,
    });
    if (rows.length) makeColumnsResizable(element('admin-system-log-table'), 'system-log');
  }

  async function downloadLog(action, path) {
    if (runningActions.has(action)) return;
    runningActions.add(action);
    try {
      await apiDownload(path);
    } catch (error) {
      toast(error.message, true);
    } finally {
      runningActions.delete(action);
    }
  }

  // --- Event wiring ----------------------------------------------------

  const ACTIONS = {
    'save-general': saveGeneral,
    'save-ad': saveAd,
    'test-ad': testAd,
    'save-entra': saveEntra,
    'test-entra': testEntra,
    'copy-redirect': copyRedirectUri,
    'create-user': () => openUserModal(),
    'edit-user': target => { const user = findUser(target.dataset.userId); if (user) openUserModal(user); },
    'revoke-user': target => revokeUserSessions(findUser(target.dataset.userId)),
    'delete-user': target => deleteUser(findUser(target.dataset.userId)),
    'create-mapping': () => openMappingModal(),
    'edit-mapping': target => { const mapping = findMapping(target.dataset.mappingId); if (mapping) openMappingModal(mapping); },
    'delete-mapping': target => deleteMapping(findMapping(target.dataset.mappingId)),
    'refresh-audit': loadAudit,
    'download-audit': () => downloadLog('download-audit', `${ADMIN_API}/logs/audit/download`),
    'refresh-system-log': loadSystemLog,
    'download-system-log': () => downloadLog('download-system-log', `${ADMIN_API}/logs/system/download`),
    'save-backups': saveBackups,
    'save-transfer': saveTransfer,
    'save-firmware': saveFirmware,
    'create-port-profile': () => openPortProfileModal(),
    'edit-port-profile': target => { const profile = findPortProfile(target.dataset.profileId); if (profile) openPortProfileModal(profile); },
    'delete-port-profile': target => deletePortProfile(findPortProfile(target.dataset.profileId)),
    'upload-firmware-image': uploadFirmwareImage,
    'delete-firmware-image': deleteFirmwareImage,
    'refresh-jobs': loadAdminJobs,
    'cancel-job': cancelJob,
  };

  function handleAdminClick(event) {
    if (!isAdminWorkspace() || !isAdminSession()) return;
    const target = event.target?.closest?.('[data-admin-action]');
    const action = target ? ACTIONS[target.dataset.adminAction] : null;
    if (action) void action(target);
  }

  // --- Session hooks ---------------------------------------------------

  function applyAdminSessionUi() {
    const admin = isAdminSession();
    setElementHidden('nav-admin', !admin);
    if (userModalState && (userModalState.session !== currentSession || !admin)) forceCloseUserModal();
    if (mappingModalState && (mappingModalState.session !== currentSession || !admin)) forceCloseMappingModal();
    if (profileModalState && (profileModalState.session !== currentSession || !admin)) forceClosePortProfileModal();
    if (!admin && isAdminWorkspace()) setWorkspaceMode('switches');
  }

  function clearAdminSensitiveFields() {
    clearUserPasswordFields();
    ['admin-ad-test-password', 'admin-entra-secret', 'admin-backup-password'].forEach(id => {
      const field = element(id);
      if (field) field.value = '';
    });
  }

  function closeAdminModals() {
    forceCloseUserModal();
    forceCloseMappingModal();
    forceClosePortProfileModal();
  }

  function rerenderAdminContent() {
    if (isAdminWorkspace() && isAdminSession()) void showAdminSection(activeSection);
  }

  function resetAdminState() {
    adminDataSequence += 1;
    activeSection = 'auth';
    authSettings = null;
    adminUsers = [];
    groupMappings = [];
    portProfiles = [];
    auditEntries = [];
    systemLogEntries = [];
    operationsSettings = null;
    runningActions.clear();
    closeAdminModals();
    renderSectionNav();
    showAdminPage(null);
  }

  registerWorkspace('admin', {
    navButtonId: 'nav-admin',
    sidebarId: 'admin-sidebar',
    isAvailable: isAdminSession,
    onEnter() {
      void showAdminSection(activeSection);
    },
    onLeave() {
      adminDataSequence += 1;
      clearAdminSensitiveFields();
      closeAdminModals();
      leaveAdminPages();
    },
  });

  registerSessionHooks({
    applySessionUi: applyAdminSessionUi,
    rerenderRoleSensitiveContent: rerenderAdminContent,
    clearSensitiveFields: clearAdminSensitiveFields,
    closePrivilegedModals: closeAdminModals,
    reset: resetAdminState,
  });

  element('nav-admin').addEventListener('click', () => setWorkspaceMode('admin'));
  SECTIONS.forEach(section => {
    element(`admin-nav-${section}`).addEventListener('click', () => { void showAdminSection(section); });
  });
  element('main-content').addEventListener('click', handleAdminClick);
  element('admin-user-cancel').addEventListener('click', closeUserModal);
  element('admin-user-save').addEventListener('click', saveUser);
  element('admin-mapping-cancel').addEventListener('click', closeMappingModal);
  element('admin-mapping-save').addEventListener('click', saveMapping);
  element('admin-mapping-provider').addEventListener('change', updateMappingPlaceholder);
  element('admin-profile-cancel').addEventListener('click', closePortProfileModal);
  element('admin-profile-save').addEventListener('click', savePortProfile);
  applyAdminSessionUi();
})();
