export function toValidDate(value) {
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatDateTime24(value, locale) {
  const date = toValidDate(value)
  if (!date) return '-'

  const dateText = date.toLocaleDateString(locale)
  const timeText = date.toLocaleTimeString(locale, {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })

  return `${dateText} ${timeText}`
}
