let csrfToken = null;
let currentSession = null;

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]));

const statusClass = value => {
  const normalized = String(value || '').trim().toLowerCase();
  return [
    'connected', 'notconnect', 'disabled', 'err-disabled', 'inactive', 'monitoring',
  ].includes(normalized) ? normalized : 'unknown';
};

// Login endpoints answer 401 for rejected credentials, never for an expired session.
const isAuthEndpoint = path => path === '/api/login' || String(path).startsWith('/api/auth/');

async function apiError(res, path, sessionAtStart) {
  const body = await res.json().catch(() => ({}));
  const detail = body.detail || t('Fehler {status}', { status: res.status });
  const errorMessage = typeof detail === 'string'
    ? detail
    : typeof detail?.message === 'string'
      ? detail.message
      : Array.isArray(detail) && detail.length && detail.every(item => typeof item?.msg === 'string')
        ? detail.map(item => item.msg.replace(/^Value error, /, '')).join(' ')
        : JSON.stringify(detail);
  const error = new Error(errorMessage);
  error.status = res.status;
  if (detail && typeof detail === 'object' && typeof detail.code === 'string') {
    error.code = detail.code;
  }
  if (res.status === 401
      && !isAuthEndpoint(path)
      && path !== '/api/me'
      && sessionAtStart
      && currentSession === sessionAtStart) {
    handleSessionExpired();
  }
  if (res.status === 403
      && path !== '/api/me'
      && sessionAtStart
      && currentSession === sessionAtStart) {
    await resyncSessionAfterForbidden(sessionAtStart);
  }
  return error;
}

const api = async (path, opts = {}) => {
  const sessionAtStart = currentSession;
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', 'X-UI-Language': uiLanguage, ...(opts.headers || {}) };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const res = await fetch(path, { credentials: 'same-origin', ...opts, headers });
  if (!res.ok) throw await apiError(res, path, sessionAtStart);
  return res.status === 204 ? null : res.json();
};

async function apiDownload(path) {
  const sessionAtStart = currentSession;
  const res = await fetch(path, { credentials: 'same-origin', headers: { 'X-UI-Language': uiLanguage } });
  if (!res.ok) throw await apiError(res, path, sessionAtStart);
  const match = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '');
  const filename = match ? match[1] : 'download.zip';
  const url = URL.createObjectURL(await res.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const columnWidthsStorageKey = 'switchsteward-column-widths';
const MIN_COLUMN_WIDTH = 48;

function readColumnWidthsStore() {
  const all = JSON.parse(localStorage.getItem(columnWidthsStorageKey) || '{}');
  return all && typeof all === 'object' && !Array.isArray(all) ? all : {};
}

function storedColumnWidths(key) {
  try {
    const widths = readColumnWidthsStore()[key];
    return Array.isArray(widths) && widths.every(width => Number.isFinite(width) && width >= MIN_COLUMN_WIDTH)
      ? widths : null;
  } catch {
    return null;
  }
}

function saveColumnWidths(key, widths) {
  try {
    let all = {};
    try { all = readColumnWidthsStore(); } catch { all = {}; }
    if (widths) all[key] = widths;
    else delete all[key];
    localStorage.setItem(columnWidthsStorageKey, JSON.stringify(all));
  } catch {
    // Column widths are a convenience; storage may be unavailable.
  }
}

function makeColumnsResizable(table, key) {
  if (!table) return;
  const headers = [...table.querySelectorAll('thead th')];
  table.classList.add('resizable-table');
  const apply = widths => {
    headers.forEach((th, index) => { th.style.width = `${widths[index]}px`; });
    table.style.width = `${widths.reduce((sum, width) => sum + width, 0)}px`;
    table.classList.add('is-sized');
  };
  const reset = () => {
    headers.forEach(th => { th.style.width = ''; });
    table.style.width = '';
    table.classList.remove('is-sized');
    saveColumnWidths(key, null);
  };
  const freeze = () => {
    const widths = headers.map(th => Math.round(th.getBoundingClientRect().width));
    apply(widths);
    return widths;
  };
  const saved = storedColumnWidths(key);
  if (saved && saved.length === headers.length) apply(saved);
  const label = t('Spaltenbreite ändern (Doppelklick setzt zurück)');
  headers.forEach((th, index) => {
    const handle = document.createElement('span');
    handle.className = 'column-resizer';
    handle.setAttribute('role', 'separator');
    handle.setAttribute('aria-orientation', 'vertical');
    handle.setAttribute('tabindex', '0');
    handle.setAttribute('aria-label', label);
    handle.title = label;
    handle.addEventListener('pointerdown', event => {
      event.preventDefault();
      const widths = freeze();
      const startX = event.clientX;
      const startWidth = widths[index];
      handle.setPointerCapture(event.pointerId);
      const move = moveEvent => {
        widths[index] = Math.max(MIN_COLUMN_WIDTH, Math.round(startWidth + moveEvent.clientX - startX));
        apply(widths);
      };
      const end = () => {
        handle.removeEventListener('pointermove', move);
        handle.removeEventListener('pointerup', end);
        handle.removeEventListener('pointercancel', end);
        saveColumnWidths(key, widths);
      };
      handle.addEventListener('pointermove', move);
      handle.addEventListener('pointerup', end);
      handle.addEventListener('pointercancel', end);
    });
    handle.addEventListener('keydown', event => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      const widths = freeze();
      widths[index] = Math.max(MIN_COLUMN_WIDTH, widths[index] + (event.key === 'ArrowRight' ? 16 : -16));
      apply(widths);
      saveColumnWidths(key, widths);
    });
    handle.addEventListener('dblclick', reset);
    th.appendChild(handle);
  });
}

let currentSwitchId = null;
let switches = [];
let switchGroups = [];
let globalSearchSequence = 0;
let switchSelectionSequence = 0;
let switchListSequence = 0;
let switchListRequest = null;
let neighborsRequestSequence = 0;
let summaryRequestSequence = 0;
let vlanRequestSequence = 0;
let backupRequestSequence = 0;
let configStatusRequestSequence = 0;
let interfaceInventoryRequestSequence = 0;
let interfaceInventoryActiveRequestSequence = 0;
let interfaceInventoryPollSequence = 0;
let interfaceMutationInProgress = false;
let interfaceMutationSequence = 0;
const interfaceRenderState = new WeakMap();
let clientInventoryRequestSequence = 0;
let forbiddenSessionResync = null;
const modalOperations = new Map();
const pendingSwitchActions = new Map();
let applicationVersionSequence = 0;
let softwareUpdateSequence = 0;
let softwareUpdateState = { session: null, candidate: null, busy: false, supported: false, maxBytes: null, phase: '' };

function resetSoftwareUpdate() {
  softwareUpdateSequence += 1;
  softwareUpdateState = { session: null, candidate: null, busy: false, supported: false, maxBytes: null, phase: '' };
  document.getElementById('software-update-file').value = '';
}

function showApplicationVersion(version) {
  const label = typeof version === 'string' && version ? version : t('unbekannt');
  document.getElementById('app-version').textContent = t('Version {version}', { version: label });
  document.getElementById('software-update-version').textContent = label;
}

async function loadApplicationVersion() {
  const session = currentSession;
  const sequence = ++applicationVersionSequence;
  try {
    const result = await api('/api/system/version');
    if (currentSession !== session || sequence !== applicationVersionSequence) return null;
    showApplicationVersion(result.current_version);
    return result;
  } catch (error) {
    if (currentSession === session && sequence === applicationVersionSequence) showApplicationVersion(null);
    throw error;
  }
}

function updateSoftwareControls() {
  const state = softwareUpdateState;
  const disabled = !currentSessionCanEdit() || state.session !== currentSession || state.busy || !state.supported;
  document.getElementById('software-update-file').disabled = disabled;
  document.getElementById('software-update-upload').disabled = disabled;
  document.getElementById('software-update-install').disabled = disabled || !state.candidate;
  setElementHidden('software-update-install', !state.candidate || state.phase === 'restarting' || state.phase === 'finished');
  setElementHidden('software-update-reload', state.phase !== 'finished');
}

function showSoftwareCandidate(candidate) {
  softwareUpdateState.candidate = candidate;
  const preview = document.getElementById('software-update-preview');
  preview.innerHTML = candidate
    ? `<strong>${escapeHtml(candidate.current_version)} → ${escapeHtml(candidate.version)}</strong>`
      + `<p>${escapeHtml(t('{count} Dateien geprüft.', { count: candidate.files }))}</p>`
      + `<p style="overflow-wrap:anywhere; font-size:11px;">SHA-256: ${escapeHtml(candidate.sha256)}</p>`
      + `<p>${escapeHtml(t('Die Installation startet den Server neu. Die Oberfläche ist währenddessen kurz nicht erreichbar.'))}</p>`
    : '';
  preview.classList.toggle('hidden', !candidate);
  updateSoftwareControls();
}

async function openSoftwareUpdate() {
  if (!requireEditPermission() || softwareUpdateState.busy) return;
  const sequence = ++softwareUpdateSequence;
  const session = currentSession;
  softwareUpdateState = { session, candidate: null, busy: true, supported: false, maxBytes: null, phase: 'loading' };
  document.getElementById('software-update-file').value = '';
  document.getElementById('software-update-status').textContent = t('Installationsstatus wird geladen …');
  document.getElementById('software-update-error').textContent = '';
  showSoftwareCandidate(null);
  try {
    const info = await loadApplicationVersion();
    if (sequence !== softwareUpdateSequence || currentSession !== session || !info) return;
    softwareUpdateState.supported = info.update_supported === true;
    softwareUpdateState.maxBytes = info.max_upload_bytes;
    softwareUpdateState.phase = 'ready';
    document.getElementById('software-update-status').textContent = info.update_supported
      ? (info.last_result?.message || t('Release-Archiv auswählen oder bereits geprüftes Archiv installieren.'))
      : t('Für Web-Updates über start.sh/start.ps1 oder python -m app.run starten.');
    if (info.pending && info.update_supported) showSoftwareCandidate(info.pending);
  } catch (error) {
    if (sequence === softwareUpdateSequence && currentSession === session) {
      document.getElementById('software-update-status').textContent = '';
      document.getElementById('software-update-error').textContent = error.message;
    }
  } finally {
    if (sequence === softwareUpdateSequence && currentSession === session) {
      softwareUpdateState.busy = false;
      updateSoftwareControls();
    }
  }
}

async function uploadSoftwareUpdate() {
  const state = softwareUpdateState;
  if (!requireEditPermission() || state.session !== currentSession || state.busy || !state.supported) return;
  const file = document.getElementById('software-update-file').files?.[0];
  const errorElement = document.getElementById('software-update-error');
  errorElement.textContent = '';
  showSoftwareCandidate(null);
  if (!file || !/\.(zip|tar\.gz|tgz)$/i.test(file.name) || file.size <= 0) {
    errorElement.textContent = t('Bitte ein nicht leeres Release-Archiv (.zip, .tar.gz oder .tgz) auswählen.');
    return;
  }
  if (Number.isFinite(state.maxBytes) && file.size > state.maxBytes) {
    errorElement.textContent = t('Das Archiv ist zu groß. Maximal {size} MiB sind erlaubt.', { size: Math.floor(state.maxBytes / 1024 / 1024) });
    return;
  }
  const sequence = softwareUpdateSequence;
  state.busy = true;
  state.phase = 'uploading';
  document.getElementById('software-update-status').textContent = t('Archiv wird hochgeladen und geprüft …');
  updateSoftwareControls();
  try {
    const candidate = await api('/api/system/updates', {
      method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Archive-Name': encodeURIComponent(file.name) }, body: file,
    });
    if (sequence !== softwareUpdateSequence || currentSession !== state.session) return;
    if (!candidate?.update_id || !candidate.version) throw new Error(t('Der Server hat kein gültiges geprüftes Release zurückgegeben.'));
    showSoftwareCandidate(candidate);
    document.getElementById('software-update-status').textContent = t('Archiv geprüft. Die neue Version kann jetzt installiert werden.');
  } catch (error) {
    if (sequence === softwareUpdateSequence && currentSession === state.session) {
      document.getElementById('software-update-status').textContent = '';
      errorElement.textContent = error.message;
    }
  } finally {
    if (sequence === softwareUpdateSequence && currentSession === state.session) {
      state.busy = false;
      state.phase = 'ready';
      updateSoftwareControls();
    }
  }
}

// Runs `check` up to `attempts` times with `intervalMs` pauses (also before the first attempt when
// `delayFirst` is set) until it returns true. Resolves to whether `check` succeeded.
async function waitFor(check, { attempts, intervalMs, delayFirst = false }) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (delayFirst || attempt > 0) await new Promise(resolve => setTimeout(resolve, intervalMs));
    if (await check(attempt)) return true;
  }
  return false;
}

async function pollSoftwareUpdate(sequence, session, candidate) {
  const deadline = Date.now() + 180000;
  const stale = () => sequence !== softwareUpdateSequence || currentSession !== session;
  let settled = false;
  await waitFor(async () => {
    if (stale()) return true;
    if (Date.now() >= deadline) return true;
    try {
      const options = typeof AbortSignal !== 'undefined' && AbortSignal.timeout
        ? { signal: AbortSignal.timeout(5000) } : {};
      const info = await api('/api/system/version', options);
      if (stale()) return true;
      const result = info.last_result;
      const sameUpdate = result?.update_id === candidate.update_id;
      const failed = sameUpdate && ['error', 'failed', 'rolled_back'].includes(result.status);
      const succeeded = sameUpdate && ['success', 'installed'].includes(result.status)
        && info.current_version === candidate.version;
      if (!failed && !succeeded) return Date.now() >= deadline;
      showApplicationVersion(info.current_version);
      softwareUpdateState.busy = false;
      softwareUpdateState.phase = 'finished';
      softwareUpdateState.candidate = null;
      document.getElementById('software-update-status').textContent = succeeded
        ? t('Version {version} ist installiert. Bitte die Seite neu laden.', { version: info.current_version })
        : t('Die Installation konnte nicht abgeschlossen werden.');
      document.getElementById('software-update-error').textContent = failed ? result.message || t('Installation fehlgeschlagen.') : '';
      updateSoftwareControls();
      settled = true;
      return true;
    } catch (error) {
      if (stale()) return true;
      if (error.status === 401 || error.status === 403) return true;
      // Während Installation und Neustart sind Verbindungsfehler erwartbar.
      return Date.now() >= deadline;
    }
  }, { attempts: 60, intervalMs: 3000, delayFirst: true });
  if (settled || stale()) return;
  softwareUpdateState.busy = false;
  softwareUpdateState.phase = 'finished';
  softwareUpdateState.candidate = null;
  document.getElementById('software-update-status').textContent = '';
  document.getElementById('software-update-error').textContent = t('Der Abschluss der Installation konnte noch nicht bestätigt werden. Bitte die Seite später neu laden und den Installationsstatus prüfen.');
  updateSoftwareControls();
}

async function installSoftwareUpdate() {
  const state = softwareUpdateState;
  if (!requireEditPermission() || state.session !== currentSession || state.busy || !state.supported || !state.candidate) return;
  const candidate = state.candidate;
  const sequence = softwareUpdateSequence;
  state.busy = true;
  state.phase = 'installing';
  document.getElementById('software-update-error').textContent = '';
  document.getElementById('software-update-status').textContent = t('Installation von Version {version} wird gestartet …', { version: candidate.version });
  updateSoftwareControls();
  try {
    const result = await api('/api/system/updates/install', { method: 'POST', body: JSON.stringify({ update_id: candidate.update_id }) });
    if (sequence !== softwareUpdateSequence || currentSession !== state.session) return;
    if (result?.status !== 'restarting') throw new Error(result?.message || t('Die Installation wurde nicht bestätigt.'));
    state.phase = 'restarting';
    document.getElementById('software-update-status').textContent = t('Installation läuft. Auf den Neustart des Servers wird gewartet …');
    updateSoftwareControls();
    void pollSoftwareUpdate(sequence, state.session, candidate);
  } catch (error) {
    if (sequence !== softwareUpdateSequence || currentSession !== state.session) return;
    // Auch bei Verbindungsabbruch kann der Neustart bereits begonnen haben.
    if (!error.status) {
      state.phase = 'restarting';
      document.getElementById('software-update-status').textContent = t('Verbindung unterbrochen. Der Installationsstatus wird nach dem Neustart geprüft …');
      updateSoftwareControls();
      void pollSoftwareUpdate(sequence, state.session, candidate);
    } else {
      state.busy = false;
      state.phase = 'ready';
      document.getElementById('software-update-status').textContent = '';
      document.getElementById('software-update-error').textContent = error.message;
      updateSoftwareControls();
    }
  }
}

document.getElementById('software-update-upload').addEventListener('click', uploadSoftwareUpdate);
document.getElementById('software-update-install').addEventListener('click', installSoftwareUpdate);
document.getElementById('software-update-file').addEventListener('change', () => {
  if (softwareUpdateState.busy) return;
  showSoftwareCandidate(null);
  document.getElementById('software-update-status').textContent = '';
  document.getElementById('software-update-error').textContent = '';
});
document.getElementById('software-update-reload').addEventListener('click', () => location.reload());

function beginModalOperation(modalId) {
  if (modalOperations.has(modalId)) return null;
  const controls = [...document.getElementById(modalId).querySelectorAll('input, select, textarea, button')];
  const operation = {
    modalId,
    session: currentSession,
    controls: controls.map(control => [control, control.disabled]),
  };
  controls.forEach(control => { control.disabled = true; });
  document.getElementById(modalId).querySelector('.modal')?.setAttribute('aria-busy', 'true');
  modalOperations.set(modalId, operation);
  return operation;
}

function modalOperationIsCurrent(operation) {
  return modalOperations.get(operation.modalId) === operation && currentSession === operation.session;
}

function finishModalOperation(operation) {
  if (modalOperations.get(operation.modalId) !== operation) return;
  operation.controls.forEach(([control, disabled]) => { control.disabled = disabled; });
  modalOperations.delete(operation.modalId);
  document.getElementById(operation.modalId).querySelector('.modal')?.removeAttribute('aria-busy');
}
const collapsedGroupsStorageKey = 'switchsteward-collapsed-groups';
let collapsedGroups = new Set();
try {
  const storedGroups = JSON.parse(localStorage.getItem(collapsedGroupsStorageKey) || '[]');
  if (Array.isArray(storedGroups)) collapsedGroups = new Set(storedGroups.filter(value => typeof value === 'string'));
} catch {
  collapsedGroups = new Set();
}

function toast(message, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function normalizeSessionPayload(payload) {
  const source = payload && typeof payload === 'object' ? payload : {};
  const role = ['admin', 'operator', 'viewer'].includes(source.role) ? source.role : 'viewer';
  return {
    username: typeof source.username === 'string' ? source.username : '',
    displayName: typeof source.display_name === 'string' ? source.display_name : '',
    provider: ['local', 'ad', 'entra'].includes(source.provider) ? source.provider : '',
    role,
    canEdit: role === 'admin' && source.can_edit === true,
    canOperate: (role === 'admin' || role === 'operator') && source.can_operate === true,
  };
}

function currentSessionCanEdit() {
  return currentSession?.role === 'admin' && currentSession?.canEdit === true;
}

function currentSessionCanOperate() {
  return (currentSession?.role === 'admin' || currentSession?.role === 'operator') && currentSession?.canOperate === true;
}

function setElementHidden(id, hidden) {
  document.getElementById(id)?.classList.toggle('hidden', hidden);
}

// --- Session hooks and workspace router -------------------------------

// Hooks: applySessionUi, rerenderRoleSensitiveContent, clearSensitiveFields, closePrivilegedModals,
// reset, credentialsChanged. Every hook is optional.
const sessionHooks = [];

function registerSessionHooks(hooks) {
  sessionHooks.push(hooks);
}

function runSessionHooks(name) {
  return sessionHooks.map(hooks => hooks[name]?.());
}

const workspaces = new Map();
let workspaceMode = 'switches';

function registerWorkspace(name, { navButtonId, sidebarId, onEnter, onLeave, isAvailable } = {}) {
  workspaces.set(name, { navButtonId, sidebarId, onEnter, onLeave, isAvailable });
}

function isWorkspaceActive(name) {
  return workspaceMode === name;
}

function applyWorkspaceUi() {
  workspaces.forEach((workspace, name) => {
    const active = name === workspaceMode;
    if (workspace.sidebarId) setElementHidden(workspace.sidebarId, !active);
    const navButton = workspace.navButtonId ? document.getElementById(workspace.navButtonId) : null;
    if (!navButton) return;
    navButton.classList.toggle('active', active);
    if (active) navButton.setAttribute('aria-current', 'page');
    else navButton.removeAttribute('aria-current');
  });
  setElementHidden('global-search-form', workspaceMode !== 'switches');
}

function setWorkspaceMode(name) {
  const target = workspaces.get(name);
  const next = target && target.isAvailable?.() !== false ? name : 'switches';
  const previous = workspaceMode;
  workspaceMode = next;
  if (previous !== next) workspaces.get(previous)?.onLeave?.(next);
  applyWorkspaceUi();
  workspaces.get(next)?.onEnter?.(previous);
}

// Returns to the switch workspace without running enter/leave callbacks (session reset).
function resetWorkspaceMode() {
  workspaceMode = 'switches';
  applyWorkspaceUi();
}

function clearSensitiveFields() {
  ['login-password', 'cred-username', 'cred-password', 'cred-enable'].forEach(id => {
    const field = document.getElementById(id);
    if (field) field.value = '';
  });
  clearSwitchCredentialInputs();
  runSessionHooks('clearSensitiveFields');
}

function closePrivilegedModals() {
  resetSoftwareUpdate();
  [...modalOperations.values()].forEach(finishModalOperation);
  ['switch-modal', 'group-modal', 'vlan-modal', 'interface-modal'].forEach(id => {
    setElementHidden(id, true);
  });
  closeSwitchCredentialsModal();
  resetGlobalCredentialsPage();
  interfaceModalSequence += 1;
  runSessionHooks('closePrivilegedModals');
}

function applySessionUi() {
  const canEdit = currentSessionCanEdit();
  if (switchCredentialsState?.session !== currentSession) closeSwitchCredentialsModal();
  if (globalCredentialsSession && globalCredentialsSession !== currentSession) resetGlobalCredentialsPage();
  if (softwareUpdateState.session && softwareUpdateState.session !== currentSession) resetSoftwareUpdate();
  if (!canEdit || copiedInterfaceSettings?.session !== currentSession) copiedInterfaceSettings = null;
  if (intfModalState.session && intfModalState.session !== currentSession) {
    interfaceModalSequence += 1;
    intfModalState.detailLoaded = false;
    setElementHidden('interface-modal', true);
    updateInterfaceModalControls();
  }
  const meUsername = document.getElementById('me-username');
  meUsername.textContent = currentSession?.displayName || currentSession?.username || '';
  if (currentSession?.provider) meUsername.setAttribute('title', authProviderLabel(currentSession.provider));
  else meUsername.removeAttribute('title');
  setElementHidden('me-role-badge', !currentSession || canEdit);
  const roleBadge = document.getElementById('me-role-badge');
  if (roleBadge) roleBadge.textContent = currentSession?.role === 'operator' ? t('Operator') : t('Nur-Lesezugriff');
  ['btn-add-group', 'btn-add-switch'].forEach(id => {
    setElementHidden(id, !canEdit);
  });
  if (!canEdit) {
    closePrivilegedModals();
    clearSensitiveFields();
  }
  runSessionHooks('applySessionUi');
}

function establishSession(payload) {
  const previousCanEdit = currentSessionCanEdit();
  csrfToken = typeof payload?.csrf_token === 'string' ? payload.csrf_token : null;
  currentSession = normalizeSessionPayload(payload);
  applySessionUi();
  if (previousCanEdit !== currentSessionCanEdit()) rerenderRoleSensitiveContent();
}

function rerenderRoleSensitiveContent() {
  renderSwitchList();
  runSessionHooks('rerenderRoleSensitiveContent');
  if (!isWorkspaceActive('switches')) return;
  if (currentSwitchId == null) return;
  const selectedSwitch = switches.find(sw => Number(sw.id) === Number(currentSwitchId));
  if (selectedSwitch) renderSwitchDetail(selectedSwitch);
}

async function resyncSessionAfterForbidden(sessionAtStart) {
  if (!sessionAtStart || currentSession !== sessionAtStart) return;
  if (forbiddenSessionResync?.session !== sessionAtStart) {
    const promise = (async () => {
      try {
        const response = await fetch('/api/me', {
          credentials: 'same-origin',
          headers: { 'Accept': 'application/json' },
        });
        if (response.status === 401) {
          if (currentSession === sessionAtStart) handleSessionExpired();
          return;
        }
        if (!response.ok) return;
        const payload = await response.json();
        if (currentSession === sessionAtStart) establishSession(payload);
      } catch {
        // Der ursprüngliche 403 bleibt für den aufrufenden Handler erhalten.
      }
    })();
    forbiddenSessionResync = { session: sessionAtStart, promise };
    promise.finally(() => {
      if (forbiddenSessionResync?.promise === promise) forbiddenSessionResync = null;
    });
  }
  await forbiddenSessionResync.promise;
}

function authProviderLabel(provider) {
  if (provider === 'local') return t('Lokales Konto');
  if (provider === 'ad') return t('Active Directory');
  if (provider === 'entra') return t('Microsoft Entra ID');
  return String(provider || '');
}

const LOGIN_PROVIDER_STORAGE_KEY = 'switchsteward.login-provider';
let loginMethods = null;
let loginMethodsSequence = 0;

function loginErrorMessage(code) {
  switch (code) {
    case 'entra_disabled':
      return t('Die Anmeldung mit Microsoft Entra ID ist deaktiviert oder nicht vollständig eingerichtet.');
    case 'entra_state':
      return t('Die Anmeldung mit Microsoft Entra ID ist abgelaufen oder ungültig. Bitte erneut versuchen.');
    case 'entra_denied':
      return t('Die Anmeldung mit Microsoft Entra ID wurde abgebrochen oder abgelehnt.');
    case 'entra_token':
      return t('Die Antwort von Microsoft Entra ID konnte nicht bestätigt werden.');
    case 'entra_unavailable':
      return t('Microsoft Entra ID ist derzeit nicht erreichbar. Bitte später erneut versuchen.');
    case 'entra_no_role':
      return t('Ihr Konto ist in SwitchSteward keiner Rolle zugeordnet.');
    case 'account_disabled':
      return t('Ihr Konto ist gesperrt.');
    default:
      return t('Die Anmeldung ist fehlgeschlagen.');
  }
}

// Reads `login_error` from the address bar once and removes it, so a reload does not repeat it.
function takeLoginErrorFromUrl() {
  const location = globalThis.location;
  if (!location?.search) return '';
  const url = new URL(location.href);
  const code = url.searchParams.get('login_error');
  if (code === null) return '';
  url.searchParams.delete('login_error');
  globalThis.history?.replaceState(globalThis.history.state, '', url.pathname + url.search + url.hash);
  return loginErrorMessage(code);
}

function readStoredLoginProvider() {
  try {
    return localStorage.getItem(LOGIN_PROVIDER_STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeLoginProvider(provider) {
  try {
    localStorage.setItem(LOGIN_PROVIDER_STORAGE_KEY, provider);
  } catch {
    // Without storage the next visit falls back to the default preselection.
  }
}

function applyLoginMethods(methods) {
  loginMethods = methods && typeof methods === 'object' ? methods : null;
  const adEnabled = loginMethods?.ad?.enabled === true;
  const entraEnabled = loginMethods?.entra?.enabled === true;
  const select = document.getElementById('login-provider');
  setElementHidden('login-provider-field', !adEnabled);
  if (adEnabled) {
    const stored = readStoredLoginProvider();
    select.value = stored === 'local' || stored === 'ad' ? stored : 'ad';
  } else {
    select.value = 'local';
  }
  setElementHidden('login-entra', !entraEnabled);
}

async function loadLoginMethods() {
  const sequence = ++loginMethodsSequence;
  try {
    const methods = await api('/api/auth/methods');
    if (sequence === loginMethodsSequence) applyLoginMethods(methods);
  } catch {
    // Local sign-in stays available when the method list cannot be loaded.
    if (sequence === loginMethodsSequence) applyLoginMethods(null);
  }
}

function selectedLoginProvider() {
  const field = document.getElementById('login-provider-field');
  if (field.classList.contains('hidden')) return 'local';
  return document.getElementById('login-provider').value === 'ad' ? 'ad' : 'local';
}

function entraLoginUrl() {
  const url = loginMethods?.entra?.login_url;
  // Only same-origin absolute paths; never follow a server-supplied foreign URL.
  return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') ? url : '/api/auth/entra/login';
}

function showLoginView(message = '') {
  setElementHidden('app', true);
  setElementHidden('login-screen', false);
  setElementHidden('login-form-controls', false);
  setElementHidden('login-submit', false);
  setElementHidden('login-retry', true);
  document.getElementById('login-title').textContent = t('Anmelden');
  document.getElementById('login-error').textContent = message;
  void loadLoginMethods();
}

function showSessionCheckError(error) {
  setElementHidden('app', true);
  setElementHidden('login-screen', false);
  setElementHidden('login-form-controls', true);
  setElementHidden('login-submit', true);
  setElementHidden('login-retry', false);
  setElementHidden('login-provider-field', true);
  setElementHidden('login-entra', true);
  loginMethodsSequence += 1;
  document.getElementById('login-title').textContent = t('Anmeldestatus nicht verfügbar');
  document.getElementById('login-error').textContent = error?.status
    ? t('Der Anmeldestatus konnte nicht geprüft werden: {message}', { message: error.message })
    : t('Der Server ist derzeit nicht erreichbar. Bitte prüfen Sie die Verbindung und versuchen Sie es erneut.');
  document.getElementById('login-password').value = '';
}

function handleSessionExpired() {
  csrfToken = null;
  currentSession = null;
  currentSwitchId = null;
  switches = [];
  switchGroups = [];
  globalSearchSequence += 1;
  switchSelectionSequence += 1;
  switchListSequence += 1;
  switchListRequest = null;
  cancelInterfaceInventoryWork();
  interfaceInventoryActiveRequestSequence = 0;
  interfaceMutationInProgress = false;
  interfaceMutationSequence += 1;
  pendingSwitchActions.clear();
  closePrivilegedModals();
  clearSensitiveFields();
  editingGroupId = null;
  editingSwitchId = null;
  intfModalState.switchId = null;
  intfModalState.port = null;
  intfModalState.detailLoaded = false;
  intfModalState.saving = false;
  vlanModalState = null;
  vlanTabData.clear();
  configStatusRequestSequence += 1;
  document.getElementById('switch-list').innerHTML = '';
  document.getElementById('switch-search').value = '';
  document.getElementById('global-search-input').value = '';
  document.getElementById('main-content').innerHTML = `<div class="empty-state">${escapeHtml(t('Wähle links einen Switch aus.'))}</div>`;
  runSessionHooks('reset');
  resetWorkspaceMode();
  applySessionUi();
  showLoginView(t('Sitzung abgelaufen. Bitte erneut anmelden.'));
}

function requireEditPermission() {
  if (currentSessionCanEdit()) return true;
  toast(t('Nur Administratoren dürfen Änderungen vornehmen.'), true);
  return false;
}

function attachTableFilters(container, rowSelector, noResultsSelector, additionalPredicate = () => true) {
  const filterInputs = [...container.querySelectorAll('.table-filter')];
  const rows = [...container.querySelectorAll(rowSelector)].map(row => ({
    row,
    cells: [...row.children].map(cell => cell.textContent.toLocaleLowerCase('de')),
    hidden: row.classList.contains('hidden'),
  }));
  const noResults = container.querySelector(noResultsSelector);
  const applyFilters = () => {
    const filters = filterInputs.map(input => ({
      column: Number(input.dataset.column),
      value: input.value.trim().toLocaleLowerCase('de'),
    })).filter(filter => filter.value);
    let visibleRows = 0;
    rows.forEach(entry => {
      const { row, cells } = entry;
      const matches = additionalPredicate(row) && filters.every(filter =>
        (cells[filter.column] || '').includes(filter.value)
      );
      if (entry.hidden === matches) {
        row.classList.toggle('hidden', !matches);
        entry.hidden = !matches;
      }
      if (matches) visibleRows += 1;
    });
    noResults.classList.toggle('hidden', visibleRows !== 0);
  };
  filterInputs.forEach(input => {
    input.addEventListener('input', applyFilters);
  });
  return applyFilters;
}

function normalizeGlobalSearchPayload(payload) {
  const envelope = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
  const rawResults = envelope.results;
  const rawFailedSwitches = Array.isArray(envelope.failed_switches) ? envelope.failed_switches : [];
  const count = value => {
    if (value === null || value === undefined || value === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? Math.trunc(parsed) : null;
  };
  return {
    results: (Array.isArray(rawResults) ? rawResults : [])
      .filter(result => result && typeof result === 'object' && !Array.isArray(result)),
    failedSwitches: rawFailedSwitches
      .filter(result => result && typeof result === 'object' && !Array.isArray(result)),
    skippedSwitches: (Array.isArray(envelope.skipped_switches) ? envelope.skipped_switches : [])
      .filter(result => result && typeof result === 'object' && !Array.isArray(result)),
    switchesScanned: count(envelope.switches_scanned),
    switchesTotal: count(envelope.switches_total),
  };
}

function foldGlobalSearchText(value) {
  const text = String(value ?? '');
  let folded = '';
  const positions = [];
  let offset = 0;
  for (const character of text) {
    // Entspricht für deutsche Gerätenamen dem Python-casefold des Backends,
    // während die Positionsabbildung ein korrektes Highlighting ermöglicht.
    const foldedCharacter = character.toLocaleLowerCase('de').replace(/ß/g, 'ss');
    folded += foldedCharacter;
    for (let index = 0; index < foldedCharacter.length; index += 1) {
      positions.push({ start: offset, end: offset + character.length });
    }
    offset += character.length;
  }
  return { folded, positions };
}

function globalSearchTextMatch(value, query) {
  const text = String(value ?? '');
  const needle = String(query ?? '').trim();
  if (!text || !needle) return null;
  const foldedText = foldGlobalSearchText(text);
  const foldedNeedle = foldGlobalSearchText(needle).folded;
  const foldedStart = foldedText.folded.indexOf(foldedNeedle);
  if (foldedStart < 0 || !foldedNeedle) return null;
  const foldedEnd = foldedStart + foldedNeedle.length - 1;
  return {
    start: foldedText.positions[foldedStart].start,
    end: foldedText.positions[foldedEnd].end,
    exact: foldedText.folded === foldedNeedle,
  };
}

function globalSearchMacMatch(value, query) {
  const text = String(value ?? '');
  const rawQuery = String(query ?? '').trim();
  if (!text || !/^[0-9a-f.\s:-]+$/i.test(rawQuery)) return null;
  const needle = rawQuery.replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (needle.length < 2) return null;
  const positions = [];
  let compactMac = '';
  for (let index = 0; index < text.length; index += 1) {
    if (/[0-9a-f]/i.test(text[index])) {
      positions.push(index);
      compactMac += text[index].toLowerCase();
    }
  }
  const compactStart = compactMac.indexOf(needle);
  if (compactStart < 0) return null;
  return {
    start: positions[compactStart],
    end: positions[compactStart + needle.length - 1] + 1,
    exact: compactMac === needle,
  };
}

function renderGlobalSearchMatch(value, match) {
  const text = String(value ?? '');
  if (!match) return escapeHtml(text || '—');
  return `${escapeHtml(text.slice(0, match.start))}<mark class="search-match">${escapeHtml(text.slice(match.start, match.end))}</mark>${escapeHtml(text.slice(match.end))}`;
}

function globalSearchMatchDetail(match, field) {
  if (!match) return '';
  const labels = field === 'mac'
    ? [t('Exakter MAC-Treffer'), t('Teiltreffer in der MAC-Adresse')]
    : [t('Exakter Namenstreffer'), t('Teiltreffer im Gerätenamen')];
  const label = labels[match.exact ? 0 : 1];
  return `<div class="search-match-detail">${escapeHtml(label)}</div>`;
}

// Switches whose driver/model lacks client search are reported by the API instead of being queried.
function renderGlobalSearchSkipped(skippedSwitches) {
  if (!skippedSwitches.length) return '';
  const entries = skippedSwitches.map(sw => {
    const name = String(sw.name || sw.id || t('Unbekannt'));
    return sw.reason ? `${name} (${sw.reason})` : name;
  });
  return `<div class="search-warning global-search-skipped">${escapeHtml(t('Nicht durchsucht (inkompatibel): {switches}', { switches: entries.join(', ') }))}</div>`;
}

function renderGlobalSearchResults(payload, query) {
  const main = document.getElementById('main-content');
  const normalized = normalizeGlobalSearchPayload(payload);
  const results = normalized.results;
  const failedSwitches = normalized.failedSwitches;
  const failedWarning = failedSwitches.length
    ? `<details class="search-warning"><summary>${escapeHtml(t('{count} Switch(es) konnten nicht abgefragt werden', { count: failedSwitches.length }))}</summary><div>${failedSwitches.map(sw => escapeHtml(sw.name || sw.id || t('Unbekannt'))).join(', ')}</div></details>`
    : '';
  const warning = failedWarning + renderGlobalSearchSkipped(normalized.skippedSwitches);
  const hitLabel = t('{count} Treffer', { count: results.length });
  const scanSummary = normalized.switchesScanned !== null && normalized.switchesTotal !== null
    ? ` · ${t('{scanned} von {total} Switches abgefragt', { scanned: normalized.switchesScanned, total: normalized.switchesTotal })}`
    : '';
  const summary = `${hitLabel}${scanSummary}`;

  if (results.length === 0) {
    main.innerHTML = `
      <div class="panel-box">
        <strong style="font-family: var(--mono)">${escapeHtml(t('Globale Gerätesuche'))}</strong>
        <div class="search-summary">${escapeHtml(summary)}</div>
        ${warning}
        <div class="empty-state">${escapeHtml(t('Keine aktiven Clients passend zu „{query}“ gefunden.', { query }))}</div>
      </div>
    `;
    return;
  }

  const rows = results.map(client => {
    const name = client.device_name || '—';
    const mac = client.mac || '—';
    const nameMatch = client.device_name ? globalSearchTextMatch(client.device_name, query) : null;
    const macMatch = client.mac ? globalSearchMacMatch(client.mac, query) : null;
    const switchId = Number(client.switch_id);
    const switchName = client.switch_name || client.switch_ip || '—';
    const switchLink = Number.isInteger(switchId) && switchId > 0
      ? `<button class="link-button search-switch-link" data-switch-id="${escapeHtml(switchId)}">${escapeHtml(switchName)}</button>`
      : escapeHtml(switchName);
    return `
    <tr class="global-search-result-row">
      <td>${renderGlobalSearchMatch(name, nameMatch)}${globalSearchMatchDetail(nameMatch, 'name')}</td>
      <td>${renderGlobalSearchMatch(mac, macMatch)}${globalSearchMatchDetail(macMatch, 'mac')}</td>
      <td>${escapeHtml(client.ip || '—')}</td>
      <td>${switchLink}</td>
      <td>${escapeHtml(client.site || '—')}</td>
      <td>${escapeHtml(client.vlan || '—')}</td>
      <td>${escapeHtml(client.interface || '—')}</td>
    </tr>
  `;
  }).join('');
  main.innerHTML = `
    <div class="panel-box">
      <strong style="font-family: var(--mono)">${escapeHtml(t('Globale Gerätesuche: {query}', { query }))}</strong>
      <div class="search-summary">${escapeHtml(summary)}</div>
      ${warning}
    </div>
    <div class="panel-box" style="overflow-x: auto;">
      <div class="search-result-heading"><strong>${escapeHtml(t('Ergebnisliste'))}</strong><span>${escapeHtml(hitLabel)}</span></div>
      <table aria-label="${escapeHtml(t('Globale Suchergebnisse'))}">
        <thead><tr><th>${escapeHtml(t('Gerätename'))}</th><th>${escapeHtml(t('MAC-Adresse'))}</th><th>${escapeHtml(t('IP-Adresse'))}</th><th>Switch</th><th>${escapeHtml(t('Standort'))}</th><th>VLAN</th><th>${escapeHtml(t('Port'))}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
  main.querySelectorAll('.search-switch-link').forEach(link => {
    link.addEventListener('click', () => selectSwitch(Number(link.dataset.switchId)));
  });
}

// --- Auth / Bootstrap -------------------------------------------------

async function bootstrap() {
  const retryButton = document.getElementById('login-retry');
  retryButton.disabled = true;
  const loginError = takeLoginErrorFromUrl();
  try {
    const me = await api('/api/me');
    establishSession(me);
    await showApp();
  } catch (error) {
    if (error.status === 401) {
      handleSessionExpired();
      showLoginView(loginError);
    } else {
      showSessionCheckError(error);
    }
  } finally {
    retryButton.disabled = false;
  }
}

document.getElementById('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submitButton = document.getElementById('login-submit');
  if (submitButton.disabled || submitButton.classList.contains('hidden')) return;
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const provider = selectedLoginProvider();
  const errEl = document.getElementById('login-error');
  errEl.textContent = '';
  submitButton.disabled = true;
  try {
    const session = await api('/api/login', {
      method: 'POST', body: JSON.stringify({ provider, username, password }),
    });
    if (!document.getElementById('login-provider-field').classList.contains('hidden')) storeLoginProvider(provider);
    establishSession(session);
    await showApp();
  } catch (e) {
    errEl.textContent = e.message;
  } finally {
    document.getElementById('login-password').value = '';
    submitButton.disabled = false;
  }
});

document.getElementById('login-retry').addEventListener('click', bootstrap);

document.getElementById('login-entra').addEventListener('click', () => {
  location.assign(entraLoginUrl());
});

document.getElementById('btn-logout').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
    location.reload();
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
});

async function showApp() {
  const sessionAtStart = currentSession;
  applySessionUi();
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  void loadApplicationVersion().catch(() => {});
  try {
    await loadSwitches({ reuseInFlight: true });
  } catch (error) {
    if (error.status === 401 || currentSession !== sessionAtStart || !isWorkspaceActive('switches')) return;
    document.getElementById('main-content').innerHTML =
      '<div class="empty-state" style="color: var(--danger)">' + escapeHtml(error.message) + '</div>';
  }
}

document.getElementById('global-search-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!isWorkspaceActive('switches')) setWorkspaceMode('switches');
  const input = document.getElementById('global-search-input');
  const button = document.getElementById('global-search-submit');
  if (button.disabled) return;
  const query = input.value.trim();
  if (query.length < 2) {
    toast(t('Bitte mindestens zwei Zeichen eingeben.'), true);
    input.focus();
    return;
  }

  const searchSequence = ++globalSearchSequence;
  switchSelectionSequence += 1;
  cancelInterfaceInventoryWork();
  currentSwitchId = null;
  renderSwitchList();
  button.disabled = true;
  button.textContent = t('Suche …');
  document.getElementById('main-content').innerHTML = `
    <div class="panel-box">
      <strong style="font-family: var(--mono)">${escapeHtml(t('Globale Gerätesuche: {query}', { query }))}</strong>
      <div class="empty-state" role="status">${escapeHtml(t('Durchsuche alle Switches … Das kann einen Moment dauern.'))}</div>
    </div>
  `;

  try {
    const payload = await api(`/api/clients/search?q=${encodeURIComponent(query)}`);
    if (searchSequence === globalSearchSequence) renderGlobalSearchResults(payload, query);
  } catch (e) {
    if (searchSequence !== globalSearchSequence) return;
    document.getElementById('main-content').innerHTML = `
      <div class="panel-box">
        <strong style="font-family: var(--mono)">${escapeHtml(t('Globale Gerätesuche'))}</strong>
        <div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>
      </div>
    `;
  } finally {
    button.disabled = false;
    button.textContent = t('Suchen');
  }
});

// Escape closes the topmost visible dialog through its own close button, so the close handler keeps
// its guards. Dialogs with a running operation stay open; a disabled close button is never clicked.
function closeTopmostModal() {
  const open = [...document.querySelectorAll('.modal-backdrop')]
    .filter(backdrop => backdrop.id !== 'login-screen' && !backdrop.classList.contains('hidden'));
  const topmost = open[open.length - 1];
  if (!topmost || modalOperations.has(topmost.id)) return false;
  if (topmost.querySelector('.modal')?.getAttribute('aria-busy') === 'true') return false;
  const closeButton = topmost.querySelector('[data-modal-close]');
  if (!closeButton || closeButton.disabled) return false;
  closeButton.click();
  return true;
}

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeTopmostModal();
});

