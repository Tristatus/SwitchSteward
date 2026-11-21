// --- Backups-Tab (Konfigurations-Backups, Diff, Wiederherstellung) -------------

// switchId -> Backup-Liste der zuletzt gezeigten Tabelle (neueste zuerst); die Zeilenknöpfe lesen hier nach.
const backupTabData = new Map();

const backupTriggerLabels = {
  'before-save': () => t('Vor dem Speichern'),
  'after-save': () => t('Nach dem Speichern'),
  'before-restore': () => t('Vor der Wiederherstellung'),
  'before-change': () => t('Vor einer Änderung'),
  'after-change': () => t('Nach einer Änderung'),
};

const backupSourceLabels = {
  startup: () => t('Startup-Config'),
  running: () => t('Running-Config'),
};

function backupLabel(labels, value) {
  return labels[value] ? labels[value]() : String(value ?? '—');
}

function backupSizeText(value) {
  const bytes = Number(value);
  if (value == null || !Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

function backupTimeText(backup) {
  return hasValue(backup.created_at) ? `${backup.created_at} UTC` : '—';
}

function backupFromTab(switchId, backupId) {
  return (backupTabData.get(Number(switchId)) || []).find(backup => String(backup.id) === String(backupId)) || null;
}

// Vergleichsziele eines Backups: das nächstältere Backup, Running und (falls vorhanden) Startup des Geräts.
function backupDiffTargets(switchId, backup) {
  const list = backupTabData.get(Number(switchId)) || [];
  const index = list.findIndex(item => String(item.id) === String(backup.id));
  const previous = index >= 0 ? list[index + 1] : null;
  const targets = [];
  if (previous) targets.push([String(previous.id), t('Vorheriges Backup ({time})', { time: backupTimeText(previous) })]);
  targets.push(['running', t('Aktuelle Running-Config')]);
  if (featureState(switchById(switchId), 'config_compare').supported) targets.push(['startup', t('Aktuelle Startup-Config')]);
  return targets;
}

function renderBackupTable(switchId, list, warnings) {
  const sw = switchById(switchId);
  const canEdit = currentSessionCanEdit();
  const restoreState = featureState(sw, 'config_restore');
  if (list.length === 0) {
    return `${renderInventoryWarnings(warnings)}<div class="empty-state">${escapeHtml(t('Noch keine Backups. Backups entstehen automatisch beim Speichern der Konfiguration.'))}</div>`;
  }
  const rows = list.map(backup => {
    const id = escapeHtml(backup.id);
    const diffOptions = backupDiffTargets(switchId, backup)
      .map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join('');
    const actions = canEdit ? `
          <td class="table-actions"><div class="table-actions-inner">
            <button data-backup-id="${id}" class="view-backup-btn">${escapeHtml(t('Anzeigen'))}</button>
            <select data-backup-id="${id}" class="backup-diff-target" aria-label="${escapeHtml(t('Vergleichen mit'))}">${diffOptions}</select>
            <button data-backup-id="${id}" class="diff-backup-btn">${escapeHtml(t('Diff'))}</button>
            <button data-backup-id="${id}" class="download-backup-btn">${escapeHtml(t('Download'))}</button>
            <button data-backup-id="${id}"${vlanActionAttributes(['restore-backup-btn', restoreState.supported ? 'danger' : ''], restoreState)}>${escapeHtml(t('Wiederherstellen'))}${restoreState.supported ? '' : incompatibleBadge()}</button>
          </div></td>
    ` : '';
    return `
        <tr class="backup-row" data-backup-id="${id}">
          <td>${escapeHtml(backupTimeText(backup))}</td>
          <td>${escapeHtml(backupLabel(backupTriggerLabels, backup.trigger))}</td>
          <td>${escapeHtml(backupLabel(backupSourceLabels, backup.source))}</td>
          <td>${escapeHtml(backupSizeText(backup.size))}</td>
          <td>${escapeHtml(backup.encrypted ? t('Ja') : t('Nein'))}</td>
          <td>${escapeHtml(backup.created_by || '—')}</td>
          ${actions}
        </tr>
    `;
  }).join('');
  return `
    ${renderInventoryWarnings(warnings)}
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr><th>${escapeHtml(t('Zeit'))}</th><th>${escapeHtml(t('Auslöser'))}</th><th>${escapeHtml(t('Quelle'))}</th><th>${escapeHtml(t('Größe'))}</th><th>${escapeHtml(t('Verschlüsselt'))}</th><th>${escapeHtml(t('Von'))}</th>${canEdit ? '<th></th>' : ''}</tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

async function loadBackups(switchId) {
  const container = document.getElementById('backups-container');
  if (!container) return;
  const button = document.getElementById('btn-refresh-backups');
  const session = currentSession;
  const sequence = ++backupRequestSequence;
  const isCurrentView = () => sequence === backupRequestSequence && container === document.getElementById('backups-container');
  const isCurrent = () => isCurrentView() && currentSession === session;
  if (button) button.disabled = true;
  try {
    const result = await api(`/api/switches/${switchId}/backups`);
    if (!isCurrent()) return;
    if (!Array.isArray(result?.backups)) throw new Error(t('Der Server lieferte keine gültige Backup-Liste.'));
    const list = result.backups.filter(backup => backup && typeof backup === 'object');
    backupTabData.set(Number(switchId), list);
    container.innerHTML = renderBackupTable(switchId, list, result.warnings);
    const bind = (selector, handler) => container.querySelectorAll(selector).forEach(btn => {
      btn.addEventListener('click', () => {
        const backup = backupFromTab(switchId, btn.dataset.backupId);
        if (backup) handler(backup, btn);
      });
    });
    bind('.view-backup-btn', backup => showBackupText(switchId, backup));
    bind('.diff-backup-btn', backup => {
      const select = [...container.querySelectorAll('.backup-diff-target')]
        .find(item => item.dataset.backupId === String(backup.id));
      showBackupDiff(switchId, backup, select?.value || 'running');
    });
    bind('.download-backup-btn', backup => downloadBackup(switchId, backup));
    bind('.restore-backup-btn', backup => restoreBackup(switchId, backup));
  } catch (e) {
    if (!isCurrent()) return;
    container.innerHTML = `<div class="empty-state" style="color: var(--danger)">${escapeHtml(e.message)}</div>`;
  } finally {
    if (isCurrentView() && button && button === document.getElementById('btn-refresh-backups')) button.disabled = false;
  }
}

function reloadBackupsAfterWrite(switchId, session) {
  if (currentSession !== session || Number(currentSwitchId) !== Number(switchId)) return undefined;
  if (!document.getElementById('backups-container')) return undefined;
  return loadBackups(switchId);
}

async function showBackupText(switchId, backup) {
  if (!requireEditPermission()) return;
  const dialog = showConfigTextDialog(t('Backup vom {time}', { time: backupTimeText(backup) }), configTextLoading(t('Backup wird geladen …')));
  try {
    const result = await api(`/api/switches/${switchId}/backups/${backup.id}`);
    updateConfigTextDialog(dialog, `<pre class="command-preview">${escapeHtml(result?.text ?? '')}</pre>`);
  } catch (error) {
    updateConfigTextDialog(dialog, configTextError(error.message));
  }
}

// against: ID eines anderen Backups, 'running' oder 'startup' (die beiden letzten lesen das Gerät).
async function showBackupDiff(switchId, backup, against) {
  if (!requireEditPermission()) return;
  const target = backupDiffTargets(switchId, backup).find(([value]) => value === String(against));
  if (!target) return;
  const dialog = showConfigTextDialog(t('Backup vom {time} – Vergleich mit {target}', { time: backupTimeText(backup), target: target[1] }),
    configTextLoading(t('Vergleich wird erstellt …')));
  try {
    const result = await api(`/api/switches/${switchId}/backups/${backup.id}/diff?against=${encodeURIComponent(target[0])}`);
    const note = result?.truncated ? `<p class="wlan-modal-help">${escapeHtml(t('Der Vergleich wurde gekürzt.'))}</p>` : '';
    // Backup gegen Backup vergleicht der Server immer älter → neuer, gegen das Gerät Backup → Gerät.
    const legend = ['running', 'startup'].includes(target[0])
      ? t('- nur im Backup, + nur in {target}.', { target: target[1] })
      : t('- nur im älteren Backup, + nur im neueren Backup.');
    updateConfigTextDialog(dialog, `<p class="wlan-modal-help">${escapeHtml(legend)}</p>${note}${renderConfigDiff(result?.lines)}`);
  } catch (error) {
    updateConfigTextDialog(dialog, configTextError(error.message));
  }
}

async function downloadBackup(switchId, backup) {
  if (!requireEditPermission()) return;
  const session = currentSession;
  try {
    await apiDownload(`/api/switches/${switchId}/backups/${backup.id}/download`);
  } catch (error) {
    if (currentSession === session) toast(error.message, true);
  }
}

async function restoreBackup(switchId, backup) {
  if (!requireEditPermission()) return null;
  const key = `${switchId}:config-restore`;
  if (pendingSwitchActions.has(key)) return null;
  const session = currentSession;
  const operation = {};
  pendingSwitchActions.set(key, operation);
  let result = null;
  try {
    result = await runSwitchChange(switchId, 'config-restore', { backup_id: Number(backup.id) }, {
      title: t('Backup vom {time} wiederherstellen', { time: backupTimeText(backup) }),
    });
  } catch (error) {
    if (currentSession === session) toast(error.message, true);
  } finally {
    if (pendingSwitchActions.get(key) === operation) pendingSwitchActions.delete(key);
  }
  if (result) await reloadBackupsAfterWrite(switchId, session);
  return result;
}

registerSessionHooks({
  reset: () => backupTabData.clear(),
});
