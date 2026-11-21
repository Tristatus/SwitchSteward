(() => {
  'use strict';

  const storageKey = 'switchsteward.theme';
  const normalizeTheme = (value) => value === 'light' ? 'light' : 'dark';
  let theme = 'dark';
  try {
    theme = normalizeTheme(localStorage.getItem(storageKey));
  } catch {
    // The switch still works when browser storage is unavailable.
  }

  // i18n.js may be absent (theme-only harness); the German message ID is the fallback.
  const translate = (text) => (typeof t === 'function' ? t(text) : text);

  function applyTheme(value) {
    theme = normalizeTheme(value);
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      button.setAttribute('aria-checked', String(theme === 'light'));
      button.textContent = theme === 'light' ? 'Light Mode' : 'Dark Mode';
      button.title = translate(theme === 'light' ? 'Zum Dark Mode wechseln' : 'Zum Light Mode wechseln');
    });
  }

  applyTheme(theme);
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(theme);
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      button.addEventListener('click', () => {
        applyTheme(theme === 'light' ? 'dark' : 'light');
        try {
          localStorage.setItem(storageKey, theme);
        } catch {
          // Retain the selected theme for this page without persistence.
        }
      });
    });
  }, { once: true });
  window.addEventListener('storage', (event) => {
    if (event.key !== storageKey && event.key !== null) return;
    try { if (event.storageArea !== localStorage) return; } catch { return; }
    applyTheme(event.newValue);
  });
})();

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const get = (id) => document.getElementById(id);
  document.title = t('Ersteinrichtung · SwitchSteward');
  const form = get('setup-form');
  const fields = get('setup-fields');
  const panels = Array.from(document.querySelectorAll('[data-step]'));
  const labels = {
    admin_username: t('Benutzername'), admin_password: t('Passwort'),
    admin_password_confirm: t('Passwort bestätigen'), server_host: t('Bind-Adresse'), server_port: t('Port'),
    tls_mode: t('Verbindung'), public_url: t('Öffentliche HTTPS-Adresse'), tls_cert_file: t('Zertifikatsdatei'), tls_key_file: t('Private Schlüsseldatei'),
    database_path: t('Datenbankdatei'), ssh_known_hosts_file: t('SSH Known-Hosts-Datei'),
    netconf_known_hosts_file: t('NETCONF Known-Hosts-Datei'), ssh_username: t('SSH-Benutzername'),
    ssh_password: t('SSH-Passwort'), ssh_enable_secret: t('Enable-Passwort'),
  };
  const tlsLabels = {
    http: t('HTTP · lokaler Start'), self_signed: t('HTTPS · automatisch erzeugtes Zertifikat'),
    certificate: t('HTTPS · vorhandenes Zertifikat'), reverse_proxy: t('HTTPS über Reverse Proxy'),
  };
  let step = 0;
  let token = null;
  let saving = false;

  const value = (id) => get(id).value.trim();
  const optional = (id) => value(id) || null;
  const tlsMode = () => form.querySelector('input[name="tls_mode"]:checked').value;

  function clearErrors() {
    get('error-summary').hidden = true;
    get('error-list').replaceChildren();
    get('retry-button').hidden = true;
    form.querySelectorAll('[aria-invalid]').forEach((input) => input.removeAttribute('aria-invalid'));
  }

  function showErrors(errors, title = t('Bitte prüfen Sie Ihre Eingaben.'), retry = false) {
    clearErrors();
    get('error-title').textContent = title;
    errors.forEach(({ message, field }) => {
      const item = document.createElement('li');
      const input = field ? get(field) : null;
      if (input) {
        input.setAttribute('aria-invalid', 'true');
        const link = document.createElement('a');
        link.href = `#${field}`;
        link.textContent = message;
        link.addEventListener('click', (event) => {
          event.preventDefault();
          const panel = input.closest('[data-step]');
          if (panel) showStep(Number(panel.dataset.step), false);
          const details = input.closest('details');
          if (details) details.open = true;
          input.focus();
        });
        item.append(link);
      } else {
        item.textContent = message;
      }
      get('error-list').append(item);
    });
    get('retry-button').hidden = !retry;
    get('error-summary').hidden = false;
    get('error-summary').focus();
  }

  function showStep(index, focus = true) {
    step = index;
    panels.forEach((panel, panelIndex) => { panel.hidden = panelIndex !== step; });
    document.querySelectorAll('[data-step-indicator]').forEach((indicator, index) => {
      if (index === step) indicator.setAttribute('aria-current', 'step');
      else indicator.removeAttribute('aria-current');
      indicator.classList.toggle('completed', index < step);
    });
    get('back-button').hidden = step === 0;
    get('next-button').hidden = step === panels.length - 1;
    get('save-button').hidden = step !== panels.length - 1;
    get('step-status').textContent = t('Schritt {step} von {total}', { step: step + 1, total: panels.length });
    if (step === 2) {
      get('review-admin').textContent = value('admin_username');
      const host = value('server_host');
      get('review-server').textContent = tlsMode() === 'reverse_proxy'
        ? value('public_url') : `${host.includes(':') ? `[${host}]` : host}:${value('server_port')}`;
      get('review-tls').textContent = tlsLabels[tlsMode()];
    }
    if (focus) get(`step-title-${step}`).focus();
  }

  function updateTlsFields() {
    const certificate = tlsMode() === 'certificate';
    get('certificate-fields').hidden = !certificate;
    ['tls_cert_file', 'tls_key_file'].forEach((id) => {
      get(id).required = certificate;
      get(id).disabled = !certificate;
    });
    const proxy = tlsMode() === 'reverse_proxy';
    get('proxy-fields').hidden = !proxy;
    get('public_url').required = proxy;
    get('public_url').disabled = !proxy;
  }

  function validate(panel) {
    const errors = [];
    panel.querySelectorAll('input, textarea').forEach((input) => {
      if (input.disabled || input.type === 'radio') return;
      if (input.required && !input.value.trim()) {
        errors.push({ field: input.id, message: t('{field}: Bitte füllen Sie dieses Feld aus.', { field: labels[input.id] }) });
      } else if (input.id === 'server_port') {
        const port = Number(input.value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          errors.push({ field: input.id, message: t('Port: Bitte geben Sie eine ganze Zahl zwischen 1 und 65535 ein.') });
        }
      } else if (input.id === 'public_url' && input.value.trim()) {
        let valid = false;
        try {
          const url = new URL(input.value.trim());
          valid = url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password
            && !url.search && !url.hash && url.pathname === '/';
        } catch { /* Report the same actionable message for all invalid addresses. */ }
        if (!valid) errors.push({ field: input.id, message: t('Öffentliche HTTPS-Adresse: Verwenden Sie https://host[:port]/ ohne Pfadpräfix, Zugangsdaten oder weitere URL-Parameter.') });
      } else if (input.id === 'admin_username' && !/^[A-Za-z0-9._@-]{1,64}$/.test(input.value.trim())) {
        errors.push({ field: input.id, message: t('Benutzername: Verwenden Sie 1–64 Zeichen aus Buchstaben, Ziffern sowie . _ @ -') });
      } else if (input.id === 'admin_password') {
        // Same rules as the server: 12-1024 characters without control characters.
        if (input.value.length < 12 || input.value.length > 1024) {
          errors.push({ field: input.id, message: t('Passwort: Verwenden Sie 12 bis 1024 Zeichen.') });
        } else if (/[\u0000-\u001f\u007f]/.test(input.value)) {
          errors.push({ field: input.id, message: t('Passwort: Steuerzeichen sind nicht erlaubt.') });
        }
      } else if (input.id === 'admin_password_confirm' && input.value !== get('admin_password').value) {
        errors.push({ field: input.id, message: t('Die Passwörter stimmen nicht überein.') });
      }
    });
    if (panel.contains(get('ssh_username'))) {
      const username = Boolean(value('ssh_username'));
      const password = Boolean(get('ssh_password').value);
      if (username !== password) errors.push({ field: username ? 'ssh_password' : 'ssh_username', message: t('Geben Sie SSH-Benutzername und SSH-Passwort gemeinsam an oder lassen Sie beide Felder leer.') });
      if (get('ssh_enable_secret').value && !username) errors.push({ field: 'ssh_username', message: t('Ein Enable-Passwort benötigt SSH-Benutzername und SSH-Passwort.') });
    }
    return errors;
  }

  function buildPayload() {
    const mode = tlsMode();
    return {
      admin_username: value('admin_username'), admin_password: get('admin_password').value,
      server_host: value('server_host'), server_port: Number(value('server_port')), tls_mode: mode,
      public_url: mode === 'reverse_proxy' ? optional('public_url') : null,
      tls_cert_file: mode === 'certificate' ? optional('tls_cert_file') : null,
      tls_key_file: mode === 'certificate' ? optional('tls_key_file') : null,
      database_path: value('database_path'), ssh_known_hosts_file: optional('ssh_known_hosts_file'),
      netconf_known_hosts_file: optional('netconf_known_hosts_file'), ssh_username: optional('ssh_username'),
      ssh_password: get('ssh_password').value || null, ssh_enable_secret: get('ssh_enable_secret').value || null,
    };
  }

  async function responseData(response) {
    try { return await response.json(); } catch { return null; }
  }

  function serverErrors(response, data) {
    if (response.status === 403) return [{ message: typeof data?.detail === 'string' ? data.detail : t('Die Einrichtungssitzung ist abgelaufen oder ungültig. Laden Sie die Seite neu und versuchen Sie es erneut.') }];
    if (response.status === 409) return [{ message: t('Die Einrichtung wurde bereits abgeschlossen. Öffnen Sie die Anwendung nach dem Neustart des Servers.') }];
    if (Array.isArray(data?.detail)) {
      return data.detail.map((error) => {
        const field = Array.isArray(error.loc) ? error.loc.find((part) => typeof part === 'string' && labels[part]) : null;
        if (typeof error.msg === 'string' && error.msg.startsWith('Value error, ')) {
          return { field, message: field ? t('{field}: {message}', { field: labels[field], message: error.msg.slice(13) }) : error.msg.slice(13) };
        }
        return { field, message: field ? t('{field}: Bitte prüfen Sie diesen Wert.', { field: labels[field] }) : t('Die Konfiguration enthält einen ungültigen Wert. Bitte prüfen Sie Ihre Eingaben.') };
      });
    }
    if (typeof data?.detail === 'string') return [{ message: data.detail }];
    return [{ message: t('Die Konfiguration konnte nicht verarbeitet werden. Prüfen Sie die Serverprotokolle und versuchen Sie es erneut.') }];
  }

  function showSuccess(data) {
    get('admin_password').value = '';
    get('admin_password_confirm').value = '';
    get('ssh_password').value = '';
    get('ssh_enable_secret').value = '';
    token = null;
    get('setup-content').hidden = true;
    clearErrors();
    let next;
    try {
      next = new URL(data.next_url || '/', window.location.href);
      if (!['http:', 'https:'].includes(next.protocol) || next.username || next.password) throw new Error('invalid URL');
    } catch { next = new URL('/', window.location.href); }
    get('next-url').href = next.href;
    get('next-address').textContent = next.href;
    get('restart-message').textContent = data.restart_required === false
      ? t('Die Konfiguration ist gespeichert. Ihre Installation ist bereit.')
      : data.automatic_restart
        ? t('Der Server startet automatisch neu. Warten Sie einen Moment, bevor Sie die Anwendung öffnen.')
        : t('Starten Sie den SwitchSteward-Prozess jetzt neu, damit die Konfiguration übernommen wird.');
    get('success-panel').hidden = false;
    get('success-title').focus();
  }

  async function loadSetup() {
    clearErrors();
    get('loading-status').hidden = false;
    get('setup-content').hidden = true;
    get('retry-button').disabled = true;
    try {
      const response = await fetch('/api/setup', { credentials: 'same-origin', cache: 'no-store', headers: { 'X-UI-Language': uiLanguage } });
      const data = await responseData(response);
      if (!response.ok) {
        showErrors(serverErrors(response, data), t('Die Ersteinrichtung konnte nicht geladen werden.'), true);
        return;
      }
      if (data?.required === false) {
        get('success-title').textContent = t('Die Einrichtung ist bereits abgeschlossen');
        showSuccess({ next_url: '/', restart_required: false });
        return;
      }
      if (data?.required !== true || typeof data.token !== 'string' || !data.token) {
        showErrors([{ message: t('Der Server hat keine gültigen Einrichtungsdaten geliefert. Starten Sie den Server bei Bedarf neu und laden Sie diese Seite erneut.') }], t('Die Ersteinrichtung konnte nicht geladen werden.'), true);
        return;
      }
      token = data.token;
      for (const id of ['server_host', 'server_port', 'database_path']) {
        if (data.defaults?.[id] !== undefined && data.defaults[id] !== null) get(id).value = data.defaults[id];
      }
      get('setup-content').hidden = false;
      showStep(0, false);
    } catch {
      showErrors([{ message: t('Der Server ist nicht erreichbar. Prüfen Sie, ob SwitchSteward läuft, und laden Sie die Einrichtungsdaten erneut.') }], t('Verbindung fehlgeschlagen'), true);
    } finally {
      get('loading-status').hidden = true;
      get('retry-button').disabled = false;
    }
  }

  get('back-button').addEventListener('click', () => { clearErrors(); showStep(step - 1); });
  get('next-button').addEventListener('click', () => {
    const errors = validate(panels[step]);
    if (errors.length) showErrors(errors);
    else { clearErrors(); showStep(step + 1); }
  });
  form.querySelectorAll('input[name="tls_mode"]').forEach((radio) => radio.addEventListener('change', updateTlsFields));
  get('retry-button').addEventListener('click', loadSetup);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (saving || !token) return;
    if (step < panels.length - 1) { get('next-button').click(); return; }
    const errors = panels.flatMap(validate);
    if (errors.length) { showErrors(errors); return; }
    clearErrors();
    saving = true;
    const payload = buildPayload();
    fields.disabled = true;
    form.setAttribute('aria-busy', 'true');
    get('save-status').hidden = false;
    try {
      const response = await fetch('/api/setup', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-Setup-Token': token, 'X-UI-Language': uiLanguage },
        body: JSON.stringify(payload),
      });
      const data = await responseData(response);
      if (!response.ok) {
        showErrors(serverErrors(response, data), t('Die Einrichtung konnte nicht gespeichert werden.'));
      } else if (data?.saved !== true) {
        showErrors([{ message: t('Der Server hat das Speichern nicht bestätigt. Prüfen Sie die Serverprotokolle, bevor Sie es erneut versuchen.') }], t('Speichern nicht bestätigt'));
      } else {
        showSuccess(data);
      }
    } catch {
      showErrors([{ message: t('Die Verbindung zum Server wurde unterbrochen. Falls der Server bereits neu startet, laden Sie die Seite danach erneut. Andernfalls können Sie das Speichern erneut versuchen.') }], t('Keine Bestätigung vom Server'));
    } finally {
      payload.admin_password = null;
      payload.ssh_password = null;
      payload.ssh_enable_secret = null;
      saving = false;
      fields.disabled = false;
      form.removeAttribute('aria-busy');
      get('save-status').hidden = true;
    }
  });

  updateTlsFields();
  loadSetup();
}, { once: true });
