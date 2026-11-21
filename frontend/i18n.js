'use strict';

// German texts are the message IDs; window.I18N_EN (i18n.en.js) maps them to English.
const SUPPORTED_LANGUAGES = ['de', 'en'];
const LANGUAGE_STORAGE_KEY = 'switchsteward.language';

function detectUiLanguage() {
  let stored = null;
  try {
    stored = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  } catch {
    stored = null;
  }
  if (SUPPORTED_LANGUAGES.includes(stored)) return stored;
  const browserLanguage = String(globalThis.navigator?.language || '').toLowerCase();
  return browserLanguage.startsWith('de') ? 'de' : 'en';
}

const uiLanguage = detectUiLanguage();
if (globalThis.document?.documentElement) document.documentElement.lang = uiLanguage;

function t(msgid, params = {}) {
  const catalog = uiLanguage === 'en' ? globalThis.window?.I18N_EN : null;
  const template = catalog && Object.prototype.hasOwnProperty.call(catalog, msgid) ? catalog[msgid] : msgid;
  return String(template).replace(/\{(\w+)\}/g, (match, name) => (
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match
  ));
}

function uiLocale() {
  return uiLanguage === 'de' ? 'de-DE' : 'en-US';
}

function applyStaticTranslations(root = document) {
  const bindings = [
    ['data-i18n', (element, text) => { element.textContent = text; }],
    ['data-i18n-placeholder', (element, text) => element.setAttribute('placeholder', text)],
    ['data-i18n-title', (element, text) => element.setAttribute('title', text)],
    ['data-i18n-aria-label', (element, text) => element.setAttribute('aria-label', text)],
  ];
  for (const [attribute, apply] of bindings) {
    root.querySelectorAll(`[${attribute}]`).forEach(element => apply(element, t(element.getAttribute(attribute))));
  }
}

function setUiLanguage(lang) {
  if (!SUPPORTED_LANGUAGES.includes(lang)) return;
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, lang);
  } catch {
    // Without storage the choice cannot persist; the reload falls back to browser detection.
  }
  location.reload();
}

function initLanguageToggles(root = document) {
  const target = uiLanguage === 'de' ? 'en' : 'de';
  root.querySelectorAll('[data-language-toggle]').forEach(button => {
    button.textContent = target.toUpperCase();
    button.setAttribute('lang', target);
    button.setAttribute('aria-label', t('Sprache wechseln'));
    button.setAttribute('title', t('Sprache wechseln'));
    button.addEventListener('click', () => setUiLanguage(target));
  });
}

if (globalThis.document?.querySelectorAll) {
  const initialize = () => {
    applyStaticTranslations();
    initLanguageToggles();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize);
  else initialize();
}
