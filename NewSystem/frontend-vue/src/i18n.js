import Vue from 'vue'
import VueI18n from 'vue-i18n'

import en from './store/lang/en'
import th from './store/lang/th'

Vue.use(VueI18n)
//
const messages = {
  en: en,
  th: th
}

const SUPPORTED_LOCALES = ['en', 'th']
const LANG_STORAGE_KEY = 'app-lang'

export default new VueI18n({
  locale: getPreferredLocale(),
  fallbackLocale: 'th',
  messages,
})

function normalizeLocale(locale) {
  const normalized = String(locale || '').trim().toLowerCase().split(/-|_/)[0]
  return SUPPORTED_LOCALES.includes(normalized) ? normalized : 'th'
}

function getStoredLocale() {
  if (typeof window === 'undefined' || !window.localStorage) return ''
  return window.localStorage.getItem(LANG_STORAGE_KEY) || ''
}

function getBrowserLocale() {
  const navigatorLocale =
    navigator.languages !== undefined ?
    navigator.languages[0] :
    navigator.language

  if (!navigatorLocale) {
    return 'th'
  }

  return navigatorLocale.trim().split(/-|_/)[0]
}

function getPreferredLocale() {
  const stored = getStoredLocale()
  if (stored) return normalizeLocale(stored)
  return normalizeLocale(getBrowserLocale())
}
