const DEFAULT_BUTTONS = [
  {
    label: 'OK',
    icon: 'cil-check',
    color: 'danger',
    code: 'ok'
  }
]

function buildDialogPayload (data) {
  const payload = Object.assign({}, data || {})
  return {
    title: payload.title || 'Error',
    message: payload.message || 'Unknown error',
    code: payload.code || 'ERROR',
    number: payload.number || '1',
    status: payload.status !== false,
    color: payload.color || 'danger',
    button: Array.isArray(payload.button) && payload.button.length ? payload.button : DEFAULT_BUTTONS
  }
}

const DialogModule = {
  namespaced: true,
  state: {
    dialog: {
      title: 'Error',
      message: 'Unknown error',
      code: '20000',
      number: '1',
      status: false,
      color: 'danger',
      button: DEFAULT_BUTTONS
    },
    loading: false,
    message: 0,
    toasts: [],
    confirm: {
      show: false,
      title: '',
      message: '',
      confirmText: '',
      cancelText: '',
      confirmIcon: 'cil-trash'
    },
    confirmResolver: null,

    isDisaters: false
  },

  mutations: {

    loading(state, data) {
      state.loading = data
    },

    message(state, data) {
      state.message = data
    },
    toasts (state, data) {
      state.toasts = Array.isArray(data) ? data : []
    },
    pushToast (state, data) {
      const next = Array.isArray(state.toasts) ? state.toasts.slice() : []
      next.push(data)
      state.toasts = next
    },

    dialog(state, data) {
      state.dialog = buildDialogPayload(data)
    },

    showError (state, data) {
      state.dialog = buildDialogPayload(Object.assign({}, data || {}, { status: true }))
    },

    hideDialog (state) {
      state.dialog = buildDialogPayload({ status: false, code: '0', number: '1', message: '', title: 'Error' })
    },
    openConfirm (state, payload) {
      state.confirm = {
        show: true,
        title: payload && payload.title ? payload.title : 'Confirm',
        message: payload && payload.message ? payload.message : '',
        confirmText: payload && payload.confirmText ? payload.confirmText : 'Confirm',
        cancelText: payload && payload.cancelText ? payload.cancelText : 'Cancel',
        confirmIcon: payload && payload.confirmIcon ? payload.confirmIcon : 'cil-trash'
      }
    },
    closeConfirm (state) {
      state.confirm = {
        show: false,
        title: '',
        message: '',
        confirmText: '',
        cancelText: '',
        confirmIcon: 'cil-trash'
      }
      state.confirmResolver = null
    },
    confirmResolver (state, resolver) {
      state.confirmResolver = resolver
    },

    isDisaters(state, data) {
      state.isDisaters = data
    }
  },

  actions: {
    showToast ({ commit }, payload) {
      if (Array.isArray(payload)) {
        payload.forEach(item => {
          commit('pushToast', item)
        })
        return
      }
      commit('pushToast', payload || {})
    },
    info ({ dispatch }, message) {
      return dispatch('showToast', { message, color: 'info' })
    },
    success ({ dispatch }, message) {
      return dispatch('showToast', { message, color: 'success' })
    },
    warning ({ dispatch }, message) {
      return dispatch('showToast', { message, color: 'warning' })
    },
    error ({ dispatch }, message) {
      return dispatch('showToast', { message, color: 'danger' })
    },
    clearToasts ({ commit }) {
      commit('toasts', [])
    },
    showError ({ commit }, payload) {
      commit('showError', payload)
    },
    hideDialog ({ commit }) {
      commit('hideDialog')
    },
    openConfirm ({ commit }, payload) {
      return new Promise((resolve) => {
        commit('confirmResolver', resolve)
        commit('openConfirm', payload || {})
      })
    },
    confirm ({ state, commit }) {
      if (typeof state.confirmResolver === 'function') {
        state.confirmResolver(true)
      }
      commit('closeConfirm')
    },
    cancelConfirm ({ state, commit }) {
      if (typeof state.confirmResolver === 'function') {
        state.confirmResolver(false)
      }
      commit('closeConfirm')
    }
  },

  getters: {

    loading(state) {
      return state.loading
    },

    message(state) {
      return state.message
    },
    toasts (state) {
      return state.toasts
    },
    confirm (state) {
      return state.confirm
    },

    dialog(state) {
      return state.dialog
    },

    isDisaters(state) {
      return state.isDisaters
    }
  },
};

export default DialogModule;
