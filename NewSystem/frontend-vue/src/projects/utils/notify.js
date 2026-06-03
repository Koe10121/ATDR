export function notifyInfo(store, message) {
  return store.dispatch('dialog/info', message)
}

export function notifySuccess(store, message) {
  return store.dispatch('dialog/success', message)
}

export function notifyWarning(store, message) {
  return store.dispatch('dialog/warning', message)
}

export function notifyError(store, message) {
  return store.dispatch('dialog/error', message)
}
