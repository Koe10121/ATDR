import Service from '@/service/api'
import {
  fetchSecurityBootstrap,
  getPayload,
  mapPermission
} from './shared'

const moduleState = {
  groups: [],
  types: [],
  menus: [],
  permissions: []
}

export default {
  namespaced: true,
  state: moduleState,
  mutations: {
    groups (state, value) {
      state.groups = Array.isArray(value) ? value : []
    },
    types (state, value) {
      state.types = Array.isArray(value) ? value : []
    },
    menus (state, value) {
      state.menus = Array.isArray(value) ? value : []
    },
    permissions (state, value) {
      state.permissions = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const data = await fetchSecurityBootstrap()
      commit('groups', data.groups)
      commit('types', data.types)
      commit('menus', data.menus)
      commit('permissions', data.permissions)
      return true
    },
    async save ({ dispatch }, row) {
      const payload = {
        _id: row && row._id ? row._id : null,
        group: row && row.groupId ? row.groupId : '',
        menu: row && row.menuId ? row.menuId : '',
        all: !!(row && row.all),
        view: !!(row && row.view),
        edit: !!(row && row.edit),
        delete: !!(row && row.delete),
        action: !!(row && row.action),
        logs: !!(row && row.logs)
      }

      let response
      if (payload._id) {
        response = await Service.security('update-permission', payload)
      } else {
        delete payload._id
        response = await Service.security('create-permission', payload)
      }

      const item = mapPermission(getPayload(response))
      await dispatch('explorer')
      return item
    }
  },
  getters: {
    groups: (state) => state.groups,
    types: (state) => state.types,
    menus: (state) => state.menus,
    permissions: (state) => state.permissions
  }
}
