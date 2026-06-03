import Service from '@/service/api'

function mapAuditItem (item) {
  return {
    _id: item && item._id ? String(item._id) : '',
    module: item && item.module ? String(item.module) : '',
    action: item && item.action ? String(item.action) : '',
    actorId: item && item.actorId ? String(item.actorId) : '',
    resourceId: item && item.resourceId ? String(item.resourceId) : '',
    targetId: item && item.targetId ? String(item.targetId) : '',
    ip: item && item.ip ? String(item.ip) : '-',
    createdAt: item && item.createdAt ? String(item.createdAt) : '',
    detail: item && item.detail ? item.detail : null
  }
}

export default {
  namespaced: true,
  state: {
    items: []
  },
  mutations: {
    items (state, value) {
      state.items = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }, filters = {}) {
      const response = await Service.security('audit-events', filters)
      const rows = response && response.data && response.data.data
        ? response.data.data
        : []
      commit('items', rows.map(mapAuditItem))
      return true
    }
  },
  getters: {
    items: state => state.items
  }
}
