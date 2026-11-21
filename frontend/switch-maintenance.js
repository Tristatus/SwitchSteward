// Tab "Wartung": firmware staging/activation and reloads. Loaded after switches.js.

let maintenanceRequestSequence = 0;
let maintenanceJobPollSequence = 0;
const MAINTENANCE_JOB_POLL_MS = 10000;
let maintenanceState = null;

// Server timestamps are UTC ("YYYY-MM-DD HH:MM:SS" or ISO); shown in the browser's local time.
function formatUtcTimestamp(value) {
  if (!hasValue(value)) return '—';
  const text = String(value);
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(text) ? text : `${text.replace(' ', 'T')}Z`;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? text : date.toLocaleString(uiLocale());
}

// <input type="datetime-local"> value (browser time zone) → UTC ISO string, or null when invalid.
function localDateTimeToUtcIso(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(String(value || ''))) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function formatByteSize(value) {
  const bytes = Number(value);
  if (value == null || !Number.isFinite(bytes)) return '—';
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

function jobStatusLabel(status) {
  return {
    pending: t('Geplant'), running: t('Läuft'), done: t('Erledigt'), failed: t('Fehlgeschlagen'), cancelled: t('Abgebrochen'),
  }[status] || String(status || '—');
}

function jobKindLabel(kind) {
  return { reload: t('Neustart'), 'firmware-stage': t('Firmware-Übertragung') }[kind] || String(kind || '—');
}

function maintenanceIsCurrent(sequence, container) {
  return sequence === maintenanceRequestSequence && container === document.getElementById('maintenance-container');
}

async function loadMaintenance(switchId) {
  const container = document.getElementById('maintenance-container');
  if (!container) return;
  const sequence = ++maintenanceRequestSequence;
  maintenanceJobPollSequence += 1;
  const sw = switchById(switchId);
  const firmwareState = featureState(sw, 'firmware');
  container.innerHTML = `<div class="empty-state">${escapeHtml(t('Lade Wartungsdaten …'))}</div>`;
  if (!container.dataset.maintenanceBound) {
    container.dataset.maintenanceBound = '1';
    container.addEventListener('click', handleMaintenanceClick);
  }
  let firmware = null;
  let jobs = [];
  let error = '';
  try {
    if (firmwareState.supported) {
      firmware = await api(`/api/switches/${switchId}/firmware`);
      jobs = Array.isArray(firmware?.jobs) ? firmware.jobs : [];
    } else {
      jobs = await api(`/api/switches/${switchId}/jobs`);
    }
  } catch (e) {
    error = e.message;
  }
  if (!maintenanceIsCurrent(sequence, container)) return;
  maintenanceState = {
    switchId: Number(switchId), firmware, firmwareState, jobs: Array.isArray(jobs) ? jobs : [], error, sequence,
  };
  renderMaintenance(container);
  scheduleMaintenanceJobPoll();
}

function renderMaintenance(container) {
  const state = maintenanceState;
  const canEdit = currentSessionCanEdit();
  const reloadState = featureState(switchById(state.switchId), 'reload');
  const errorBox = state.error ? `<div class="wlan-error-box">${escapeHtml(state.error)}</div>` : '';
  container.innerHTML = `
    ${errorBox}
    ${renderFirmwareArea(state, canEdit)}
    <div class="panel-box">
      <h4>${escapeHtml(t('Neustart'))}</h4>
      ${reloadState.supported ? (canEdit ? `
        <div class="flex-row">
          <button class="danger" type="button" data-maintenance-action="reload-now">${escapeHtml(t('Jetzt neu starten'))}</button>
          <input id="maintenance-reload-at" type="datetime-local" aria-label="${escapeHtml(t('Zeitpunkt des Neustarts'))}">
          <button type="button" data-maintenance-action="reload-schedule">${escapeHtml(t('Neustart planen'))}</button>
        </div>` : '') : `<p class="admin-muted">${escapeHtml(incompatibleTitle(reloadState))}</p>`}
      <p id="maintenance-message" role="status"></p>
      <div id="maintenance-scheduled">${renderScheduledReloads(state.jobs, canEdit)}</div>
    </div>
    <div class="panel-box">
      <h4>${escapeHtml(t('Aufgaben'))}</h4>
      <div id="maintenance-jobs">${renderMaintenanceJobs(state.jobs)}</div>
    </div>
  `;
}

function renderFirmwareArea(state, canEdit) {
  if (!state.firmwareState.supported) {
    return `<div class="panel-box"><h4>${escapeHtml(t('Firmware'))}</h4>
      <p class="admin-muted">${escapeHtml(incompatibleTitle(state.firmwareState))}</p></div>`;
  }
  const firmware = state.firmware || {};
  const warnings = (Array.isArray(firmware.warnings) ? firmware.warnings : [])
    .map(warning => `<div class="wlan-warning-box">${escapeHtml(warning)}</div>`).join('');
  const images = Array.isArray(firmware.images) ? firmware.images : [];
  const rows = images.length ? images.map(image => {
    const id = escapeHtml(image.id);
    const actions = canEdit ? `<div class="table-actions-inner">
        <button type="button" data-maintenance-action="firmware-stage" data-image-id="${id}">${escapeHtml(t('Übertragen'))}</button>
        <button type="button" data-maintenance-action="firmware-activate" data-image-id="${id}">${escapeHtml(t('Aktivieren'))}</button>
      </div>` : '';
    return `<tr><td>${escapeHtml(image.filename)}</td><td>${escapeHtml(formatByteSize(image.size))}</td>
      <td style="font-family: var(--mono)">${escapeHtml(image.sha256 || '')}</td><td class="table-actions">${actions}</td></tr>`;
  }).join('') : `<tr><td colspan="4" class="admin-muted">${escapeHtml(t('Keine kompatiblen Firmware-Images vorhanden.'))}</td></tr>`;
  const bootImages = Array.isArray(firmware.boot_images) ? firmware.boot_images.join(', ') : '';
  const activation = canEdit && images.length ? `
    <div class="flex-row">
      <label for="maintenance-activate-reload">${escapeHtml(t('Nach dem Aktivieren'))}</label>
      <select id="maintenance-activate-reload">
        <option value="none">${escapeHtml(t('Nicht neu starten'))}</option>
        <option value="now">${escapeHtml(t('Sofort neu starten'))}</option>
        <option value="at">${escapeHtml(t('Neustart zum Zeitpunkt'))}</option>
      </select>
      <input id="maintenance-activate-at" type="datetime-local" aria-label="${escapeHtml(t('Zeitpunkt des Neustarts'))}">
    </div>` : '';
  return `<div class="panel-box">
    <h4>${escapeHtml(t('Firmware'))}</h4>
    ${warnings}
    <div class="detail-grid">
      <div><strong>${escapeHtml(t('Laufende Version:'))}</strong> ${escapeHtml(firmware.running_version || '—')}</div>
      <div><strong>${escapeHtml(t('Boot-Images:'))}</strong> ${escapeHtml(bootImages || '—')}</div>
      <div><strong>${escapeHtml(t('Nächster Start:'))}</strong> ${escapeHtml(firmware.next_boot || '—')}</div>
      <div><strong>${escapeHtml(t('Freier Speicher:'))}</strong> ${escapeHtml(formatByteSize(firmware.free_bytes))}</div>
    </div>
    <table>
      <thead><tr><th>${escapeHtml(t('Image'))}</th><th>${escapeHtml(t('Größe'))}</th><th>SHA-256</th><th>${escapeHtml(t('Aktionen'))}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${activation}
  </div>`;
}

function renderScheduledReloads(jobs, canEdit) {
  const pending = jobs.filter(job => job?.kind === 'reload' && job.status === 'pending');
  if (!pending.length) return `<p class="admin-muted">${escapeHtml(t('Kein Neustart geplant.'))}</p>`;
  return `<table><thead><tr><th>${escapeHtml(t('Zeitpunkt'))}</th><th>${escapeHtml(t('Von'))}</th><th>${escapeHtml(t('Aktionen'))}</th></tr></thead><tbody>
    ${pending.map(job => `<tr><td>${escapeHtml(formatUtcTimestamp(job.run_at))}</td><td>${escapeHtml(job.created_by || '')}</td>
      <td>${canEdit ? `<button type="button" class="danger" data-maintenance-action="cancel-job" data-job-id="${escapeHtml(job.id)}">${escapeHtml(t('Abbrechen'))}</button>` : ''}</td></tr>`).join('')}
  </tbody></table>`;
}

function renderMaintenanceJobs(jobs) {
  if (!jobs.length) return `<p class="admin-muted">${escapeHtml(t('Keine Aufgaben.'))}</p>`;
  return `<table><thead><tr><th>${escapeHtml(t('Aufgabe'))}</th><th>${escapeHtml(t('Zeitpunkt'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Ergebnis'))}</th></tr></thead><tbody>
    ${jobs.map(job => `<tr><td>${escapeHtml(jobKindLabel(job?.kind))}</td><td>${escapeHtml(formatUtcTimestamp(job?.run_at))}</td>
      <td>${escapeHtml(jobStatusLabel(job?.status))}</td><td>${escapeHtml(job?.result?.message || '')}</td></tr>`).join('')}
  </tbody></table>`;
}

// While a job is pending or running, the job list refreshes every 10 s.
function scheduleMaintenanceJobPoll() {
  const state = maintenanceState;
  if (!state || !state.jobs.some(job => job?.status === 'running' || (job?.status === 'pending' && job.kind === 'firmware-stage'))) return;
  const poll = ++maintenanceJobPollSequence;
  setTimeout(() => { void pollMaintenanceJobs(state, poll); }, MAINTENANCE_JOB_POLL_MS);
}

async function pollMaintenanceJobs(state, poll) {
  if (poll !== maintenanceJobPollSequence || state !== maintenanceState) return;
  const container = document.getElementById('maintenance-container');
  if (!maintenanceIsCurrent(state.sequence, container)) return;
  await refreshMaintenanceJobs(state);
}

async function refreshMaintenanceJobs(state) {
  try {
    const jobs = await api(`/api/switches/${state.switchId}/jobs`);
    if (state !== maintenanceState || !maintenanceIsCurrent(state.sequence, document.getElementById('maintenance-container'))) return;
    state.jobs = Array.isArray(jobs) ? jobs : [];
    document.getElementById('maintenance-jobs').innerHTML = renderMaintenanceJobs(state.jobs);
    document.getElementById('maintenance-scheduled').innerHTML = renderScheduledReloads(state.jobs, currentSessionCanEdit());
  } catch (error) {
    if (state === maintenanceState) setMaintenanceMessage(error.message, true);
  }
  scheduleMaintenanceJobPoll();
}

function setMaintenanceMessage(message, error = false) {
  const element = document.getElementById('maintenance-message');
  if (!element) return;
  element.textContent = message;
  if (element.style) element.style.color = error ? 'var(--danger)' : '';
}

async function runMaintenanceChange(kind, params, title) {
  const state = maintenanceState;
  if (!state) return;
  try {
    const result = await runSwitchChange(state.switchId, kind, params, { title });
    if (result && state === maintenanceState) await refreshMaintenanceJobs(state);
  } catch (error) {
    if (state === maintenanceState) setMaintenanceMessage(error.message, true);
  }
}

function activateFirmware(imageId) {
  const reload = document.getElementById('maintenance-activate-reload')?.value || 'none';
  const params = { image_id: imageId, reload: ['none', 'now', 'at'].includes(reload) ? reload : 'none' };
  if (params.reload === 'at') {
    const runAt = localDateTimeToUtcIso(document.getElementById('maintenance-activate-at')?.value);
    if (!runAt) {
      setMaintenanceMessage(t('Bitte einen gültigen Zeitpunkt für den Neustart angeben.'), true);
      return Promise.resolve();
    }
    params.reload_at = runAt;
  }
  return runMaintenanceChange('firmware-activate', params, t('Firmware aktivieren'));
}

function scheduleReload() {
  const runAt = localDateTimeToUtcIso(document.getElementById('maintenance-reload-at')?.value);
  if (!runAt) {
    setMaintenanceMessage(t('Bitte einen gültigen Zeitpunkt für den Neustart angeben.'), true);
    return Promise.resolve();
  }
  return runMaintenanceChange('reload-schedule', { run_at: runAt }, t('Neustart planen'));
}

async function cancelMaintenanceJob(jobId) {
  const state = maintenanceState;
  if (!state || !confirm(t('Geplante Aufgabe abbrechen?'))) return;
  try {
    await api(`/api/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE' });
    if (state !== maintenanceState) return;
    toast(t('Aufgabe abgebrochen.'));
    await refreshMaintenanceJobs(state);
  } catch (error) {
    if (state === maintenanceState) setMaintenanceMessage(error.message, true);
  }
}

function handleMaintenanceClick(event) {
  const target = event.target?.closest?.('[data-maintenance-action]');
  if (!target || !maintenanceState || !currentSessionCanEdit()) return;
  const imageId = Number(target.dataset.imageId);
  switch (target.dataset.maintenanceAction) {
    case 'firmware-stage': void runMaintenanceChange('firmware-stage', { image_id: imageId }, t('Firmware übertragen')); break;
    case 'firmware-activate': void activateFirmware(imageId); break;
    case 'reload-now': void runMaintenanceChange('reload-now', {}, t('Jetzt neu starten')); break;
    case 'reload-schedule': void scheduleReload(); break;
    case 'cancel-job': void cancelMaintenanceJob(target.dataset.jobId); break;
    default: break;
  }
}
