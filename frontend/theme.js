(() => {
  'use strict';
  const storageKey = 'switchsteward.theme';
  let theme = 'dark';
  try {
    if (localStorage.getItem(storageKey) === 'light') theme = 'light';
  } catch { /* Browser storage may be unavailable. */ }

  // theme.js loads before i18n.js; t() exists once the toggles are updated after DOMContentLoaded.
  const translate = text => (typeof t === 'function' ? t(text) : text);

  function applyTheme(value) {
    theme = value === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.setAttribute('aria-checked', String(theme === 'light'));
      button.textContent = theme === 'light' ? 'Light Mode' : 'Dark Mode';
      button.title = translate(theme === 'light' ? 'Zum Dark Mode wechseln' : 'Zum Light Mode wechseln');
    });
  }

  // Apply the saved preference before rendering the page.
  applyTheme(theme);
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(theme);
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.addEventListener('click', () => {
        applyTheme(theme === 'dark' ? 'light' : 'dark');
        try { localStorage.setItem(storageKey, theme); } catch { /* Keep the in-memory choice. */ }
      });
    });
  }, { once: true });
  window.addEventListener('storage', event => {
    if (event.key !== storageKey && event.key !== null) return;
    try { if (event.storageArea !== localStorage) return; } catch { return; }
    applyTheme(event.newValue);
  });
})();
