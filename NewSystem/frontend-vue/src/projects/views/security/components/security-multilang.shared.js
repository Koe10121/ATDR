export function normalizeItems (items) {
  if (!Array.isArray(items)) return []
  return items
    .map(item => ({
      key: item && item.key ? String(item.key).trim().toLowerCase() : '',
      value: item && item.value ? String(item.value) : ''
    }))
    .filter(item => item.key)
}

export function defaultLanguageItems () {
  return [
    { key: 'th', value: '' },
    { key: 'en', value: '' }
  ]
}

export function normalizeOrDefault (items) {
  const normalized = normalizeItems(items)
  return normalized.length ? normalized : defaultLanguageItems()
}

export function langLabel (lang) {
  const mapping = { th: 'ไทย (th)', en: 'English (en)' }
  return mapping[lang] || lang
}

export function getLanguages (...collections) {
  const keys = collections
    .filter(Array.isArray)
    .flat()
    .map(item => item && item.key ? item.key : '')
    .filter(Boolean)
  const merged = [...new Set(keys)]
  return merged.length ? merged : ['th', 'en']
}

export function getValueByLang (items, lang) {
  const found = (Array.isArray(items) ? items : []).find(item => item.key === lang)
  return found ? found.value : ''
}

export function setValueByLang (items, lang, value) {
  const list = Array.isArray(items) ? items : []
  const index = list.findIndex(item => item.key === lang)
  if (index >= 0) {
    list[index].value = value
  } else {
    list.push({ key: lang, value })
  }
}
