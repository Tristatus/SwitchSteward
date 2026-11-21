// Tab "Diagnose": counters, transceivers, environment, log and cable test. Loaded after switches.js.

let diagnosticsRequestSequence = 0;
let diagnosticsState = null;
const CABLE_TEST_POLL_MS = 3000;
const CABLE_TEST_MAX_MS = 60000;

function diagnosticsIsCurrent(state) {
  return state === diagnosticsState && state.sequence === diagnosticsRequestSequence
    && state.container === document.getElementById('diagnostics-container');
}

function diagnosticsValue(value, unit = '') {
  return value == null || value === '' ? '—' : `${value}${unit}`;
}

function diagnosticsWarnings(payload) {
  return (Array.isArray(payload?.warnings) ? payload.warnings : [])
    .map(warning => `<div class="wlan-warning-box">${escapeHtml(warning)}</div>`).join('');
}

function diagnosticsSection(id, title, feature, sw) {
  const state = featureState(sw, feature);
  const body = state.supported
    ? `<div class="empty-state">${escapeHtml(t('Lade {title} …', { title }))}</div>`
    : `<p class="admin-muted">${escapeHtml(incompatibleTitle(state))}</p>`;
  return `<div class="panel-box"><h4>${escapeHtml(title)}</h4><div id="${id}">${body}</div></div>`;
}

async function loadDiagnostics(switchId) {
  const container = document.getElementById('diagnostics-container');
  if (!container) return;
  const sw = switchById(switchId);
  const state = {
    sequence: ++diagnosticsRequestSequence, container, switchId: Number(switchId), counters: [], cableSequence: 0,
  };
  diagnosticsState = state;
  if (!container.dataset.diagnosticsBound) {
    container.dataset.diagnosticsBound = '1';
    container.addEventListener('click', handleDiagnosticsClick);
  }
  const admin = currentSessionCanEdit();
  container.innerHTML = `
    ${diagnosticsSection('diagnostics-counters', t('Zähler'), 'diag_counters', sw)}
    ${diagnosticsSection('diagnostics-transceivers', t('Transceiver'), 'diag_transceivers', sw)}
    ${diagnosticsSection('diagnostics-environment', t('Umgebung'), 'environment', sw)}
    ${renderCableTestSection(sw)}
    ${admin ? diagnosticsSection('diagnostics-log', t('Log'), 'device_log', sw) : ''}
  `;
  const loads = [];
  if (featureState(sw, 'diag_counters').supported) loads.push(loadDiagnosticsCounters(state));
  if (featureState(sw, 'diag_transceivers').supported) loads.push(loadDiagnosticsPart(state, 'transceivers', 'diagnostics-transceivers', renderTransceivers));
  if (featureState(sw, 'environment').supported) loads.push(loadDiagnosticsPart(state, 'environment', 'diagnostics-environment', renderEnvironment));
  if (admin && featureState(sw, 'device_log').supported) loads.push(loadDiagnosticsPart(state, 'log', 'diagnostics-log', renderDeviceLog));
  await Promise.all(loads);
}

async function loadDiagnosticsPart(state, kind, elementId, render) {
  try {
    const payload = await api(`/api/switches/${state.switchId}/diagnostics/${kind}`);
    if (!diagnosticsIsCurrent(state)) return;
    document.getElementById(elementId).innerHTML = diagnosticsWarnings(payload) + render(payload || {});
  } catch (error) {
    if (!diagnosticsIsCurrent(state)) return;
    document.getElementById(elementId).innerHTML = `<div class="wlan-error-box">${escapeHtml(error.message)}</div>`;
  }
}

async function loadDiagnosticsCounters(state) {
  await loadDiagnosticsPart(state, 'counters', 'diagnostics-counters', payload => {
    state.counters = Array.isArray(payload.counters) ? payload.counters : [];
    updateCableTestPorts(state);
    return renderCounters(state.counters);
  });
}

function renderCounters(rows) {
  if (!rows.length) return `<p class="admin-muted">${escapeHtml(t('Keine Zähler verfügbar.'))}</p>`;
  const canOperate = currentSessionCanOperate();
  return `<div style="overflow-x: auto;"><table>
    <thead><tr><th>${escapeHtml(t('Port'))}</th><th>${escapeHtml(t('Bytes ein'))}</th><th>${escapeHtml(t('Bytes aus'))}</th>
      <th>${escapeHtml(t('Fehler ein'))}</th><th>${escapeHtml(t('Fehler aus'))}</th><th>CRC</th>
      <th>${escapeHtml(t('Verworfen ein'))}</th><th>${escapeHtml(t('Verworfen aus'))}</th><th>${escapeHtml(t('Kollisionen'))}</th>
      <th>${escapeHtml(t('Aktionen'))}</th></tr></thead>
    <tbody>${rows.map(row => `<tr>
      <td>${escapeHtml(row.interface)}</td><td>${escapeHtml(diagnosticsValue(row.in_octets))}</td><td>${escapeHtml(diagnosticsValue(row.out_octets))}</td>
      <td>${escapeHtml(diagnosticsValue(row.in_errors))}</td><td>${escapeHtml(diagnosticsValue(row.out_errors))}</td><td>${escapeHtml(diagnosticsValue(row.crc))}</td>
      <td>${escapeHtml(diagnosticsValue(row.drops_in))}</td><td>${escapeHtml(diagnosticsValue(row.drops_out))}</td><td>${escapeHtml(diagnosticsValue(row.collisions))}</td>
      <td>${canOperate ? `<button type="button" data-diagnostics-action="counters-clear" data-interface="${escapeHtml(row.interface)}">${escapeHtml(t('Zurücksetzen'))}</button>` : ''}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function renderTransceivers(payload) {
  const rows = Array.isArray(payload.transceivers) ? payload.transceivers : [];
  if (!rows.length) return `<p class="admin-muted">${escapeHtml(t('Keine Transceiver gefunden.'))}</p>`;
  return `<table><thead><tr><th>${escapeHtml(t('Port'))}</th><th>${escapeHtml(t('Typ'))}</th><th>${escapeHtml(t('Temperatur'))}</th>
      <th>${escapeHtml(t('Spannung'))}</th><th>${escapeHtml(t('Sendeleistung'))}</th><th>${escapeHtml(t('Empfangsleistung'))}</th><th>${escapeHtml(t('Alarm'))}</th></tr></thead>
    <tbody>${rows.map(row => `<tr><td>${escapeHtml(row.interface)}</td><td>${escapeHtml(diagnosticsValue(row.type))}</td>
      <td>${escapeHtml(diagnosticsValue(row.temperature_c, ' °C'))}</td><td>${escapeHtml(diagnosticsValue(row.voltage_v, ' V'))}</td>
      <td>${escapeHtml(diagnosticsValue(row.tx_power_dbm, ' dBm'))}</td><td>${escapeHtml(diagnosticsValue(row.rx_power_dbm, ' dBm'))}</td>
      <td>${escapeHtml(diagnosticsValue(row.alarm))}</td></tr>`).join('')}</tbody></table>`;
}

function renderEnvironment(payload) {
  const list = (items, columns) => (Array.isArray(items) && items.length
    ? `<table><tbody>${items.map(item => `<tr>${columns.map(column => `<td>${escapeHtml(diagnosticsValue(item?.[column[0]], column[1] || ''))}</td>`).join('')}</tr>`).join('')}</tbody></table>`
    : `<p class="admin-muted">${escapeHtml(t('Keine Daten.'))}</p>`);
  return `
    <h5>${escapeHtml(t('Temperaturen'))}</h5>${list(payload.temperatures, [['sensor'], ['celsius', ' °C'], ['status']])}
    <h5>${escapeHtml(t('Lüfter'))}</h5>${list(payload.fans, [['name'], ['status']])}
    <h5>${escapeHtml(t('Netzteile'))}</h5>${list(payload.power_supplies, [['name'], ['status'], ['watts', ' W']])}
  `;
}

function renderDeviceLog(payload) {
  const lines = Array.isArray(payload.lines) ? payload.lines : [];
  return `<pre class="command-preview">${escapeHtml(lines.join('\n') || t('Keine Log-Einträge.'))}</pre>`;
}

function renderCableTestSection(sw) {
  const state = featureState(sw, 'cable_test');
  if (!state.supported) {
    return `<div class="panel-box"><h4>${escapeHtml(t('Kabeltest'))}</h4><p class="admin-muted">${escapeHtml(incompatibleTitle(state))}</p></div>`;
  }
  const controls = currentSessionCanOperate() ? `<div class="flex-row">
      <select id="diagnostics-cable-port" aria-label="${escapeHtml(t('Port für den Kabeltest'))}"></select>
      <button type="button" data-diagnostics-action="cable-test">${escapeHtml(t('Kabeltest starten'))}</button>
    </div>` : '';
  return `<div class="panel-box"><h4>${escapeHtml(t('Kabeltest'))}</h4>
    <p class="admin-muted">${escapeHtml(t('Der Kabeltest unterbricht die Verbindung am Port für einige Sekunden.'))}</p>
    ${controls}
    <div id="diagnostics-cable-result"></div>
  </div>`;
}

function updateCableTestPorts(state) {
  const select = document.getElementById('diagnostics-cable-port');
  if (!select) return;
  const previous = select.value;
  select.innerHTML = state.counters.map(row => `<option value="${escapeHtml(row.interface)}">${escapeHtml(row.interface)}</option>`).join('');
  if (previous) select.value = previous;
}

function renderCableTestResult(result) {
  const status = result?.status;
  if (status === 'running') return `<p>${escapeHtml(t('Kabeltest läuft …'))}</p>`;
  if (status === 'unsupported') return `<p class="admin-muted">${escapeHtml(t('Der Port unterstützt keinen Kabeltest.'))}</p>`;
  const pairs = Array.isArray(result?.pairs) ? result.pairs : [];
  if (!pairs.length) return `<p class="admin-muted">${escapeHtml(t('Kein Ergebnis.'))}</p>`;
  return `<table><thead><tr><th>${escapeHtml(t('Adernpaar'))}</th><th>${escapeHtml(t('Status'))}</th><th>${escapeHtml(t('Länge'))}</th></tr></thead>
    <tbody>${pairs.map(pair => `<tr><td>${escapeHtml(pair.pair)}</td><td>${escapeHtml(diagnosticsValue(pair.status))}</td>
      <td>${escapeHtml(diagnosticsValue(pair.length_m, ' m'))}</td></tr>`).join('')}</tbody></table>`;
}

function setCableTestResult(markup) {
  const element = document.getElementById('diagnostics-cable-result');
  if (element) element.innerHTML = markup;
}

async function clearDiagnosticsCounters(state, interfaceName) {
  try {
    const result = await runSwitchChange(state.switchId, 'counters-clear', { interface: interfaceName }, { title: t('Zähler zurücksetzen') });
    if (result?.ok && diagnosticsIsCurrent(state)) await loadDiagnosticsCounters(state);
  } catch (error) {
    if (diagnosticsIsCurrent(state)) toast(error.message, true);
  }
}

async function startCableTest(state) {
  const interfaceName = document.getElementById('diagnostics-cable-port')?.value;
  if (!interfaceName) return;
  let result;
  try {
    result = await runSwitchChange(state.switchId, 'cable-test', { interface: interfaceName }, { title: t('Kabeltest starten') });
  } catch (error) {
    if (diagnosticsIsCurrent(state)) setCableTestResult(`<div class="wlan-error-box">${escapeHtml(error.message)}</div>`);
    return;
  }
  if (!result?.ok || !diagnosticsIsCurrent(state)) return;
  const cableSequence = ++state.cableSequence;
  setCableTestResult(renderCableTestResult({ status: 'running' }));
  await pollCableTest(state, cableSequence, interfaceName, Date.now());
}

// Polls the cable test result every 3 s until it is no longer running, for at most 60 s.
async function pollCableTest(state, cableSequence, interfaceName, startedAt) {
  const stillCurrent = () => diagnosticsIsCurrent(state) && cableSequence === state.cableSequence;
  if (!stillCurrent()) return;
  let result;
  try {
    result = await api(`/api/switches/${state.switchId}/diagnostics/cable-test?interface=${encodeURIComponent(interfaceName)}`);
  } catch (error) {
    if (stillCurrent()) setCableTestResult(`<div class="wlan-error-box">${escapeHtml(error.message)}</div>`);
    return;
  }
  if (!stillCurrent()) return;
  setCableTestResult(diagnosticsWarnings(result) + renderCableTestResult(result));
  if (result?.status !== 'running') return;
  if (Date.now() - startedAt + CABLE_TEST_POLL_MS > CABLE_TEST_MAX_MS) {
    setCableTestResult(`<div class="wlan-error-box">${escapeHtml(t('Der Kabeltest hat nach 60 Sekunden kein Ergebnis geliefert.'))}</div>`);
    return;
  }
  setTimeout(() => { void pollCableTest(state, cableSequence, interfaceName, startedAt); }, CABLE_TEST_POLL_MS);
}

function handleDiagnosticsClick(event) {
  const target = event.target?.closest?.('[data-diagnostics-action]');
  const state = diagnosticsState;
  if (!target || !state || !currentSessionCanOperate()) return;
  if (target.dataset.diagnosticsAction === 'counters-clear') void clearDiagnosticsCounters(state, target.dataset.interface);
  else if (target.dataset.diagnosticsAction === 'cable-test') void startCableTest(state);
}
