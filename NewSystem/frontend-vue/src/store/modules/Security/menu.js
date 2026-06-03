import Service from '@/service/api'
import {
  fetchSecurityBootstrap,
  getPayload,
  mapMenu,
  mapType,
  normalizeMultiLanguage,
  toMultiLanguage
} from './shared'

const moduleState = {
  types: [],
  menus: []
}

export default {
  namespaced: true,
  state: moduleState,
  mutations: {
    types (state, value) {
      state.types = Array.isArray(value) ? value : []
    },
    menus (state, value) {
      state.menus = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const data = await fetchSecurityBootstrap()
      commit('types', data.types)
      commit('menus', data.menus)
      return true
    },
    async createType ({ dispatch }, name) {
      const title = Array.isArray(name && name.title) ? normalizeMultiLanguage(name.title) : toMultiLanguage(name && name.name ? name.name : name)
      const response = await Service.security('create-type', { title })
      const itemPayload = getPayload(response)
      if (itemPayload && typeof (name && name.state) === 'boolean') itemPayload.state = name.state
      const item = mapType(itemPayload)
      await dispatch('explorer')
      return item
    },
    async updateType ({ dispatch }, payload) {
      const title = Array.isArray(payload && payload.title) ? normalizeMultiLanguage(payload.title) : toMultiLanguage(payload && payload.name ? payload.name : '')
      const response = await Service.security('update-type', {
        _id: payload && payload._id ? payload._id : '',
        title,
        state: payload && typeof payload.state === 'boolean' ? payload.state : true
      })
      const item = mapType(getPayload(response))
      await dispatch('explorer')
      return item
    },
    async removeType ({ dispatch }, item) {
      await Service.security('delete-type', { id: item && item._id ? item._id : '' })
      await dispatch('explorer')
      return true
    },
    async createMenu ({ dispatch }, payload) {
      const title = Array.isArray(payload && payload.title) ? normalizeMultiLanguage(payload.title) : toMultiLanguage(payload && payload.name ? payload.name : '')
      const description = Array.isArray(payload && payload.description) ? normalizeMultiLanguage(payload.description) : toMultiLanguage(payload && payload.description ? payload.description : '')
      const response = await Service.security('create-menu', {
        title,
        description,
        path: payload && payload.path ? payload.path : '',
        type: payload && payload.typeId ? payload.typeId : '',
        state: payload && typeof payload.state === 'boolean' ? payload.state : true
      })
      const item = mapMenu(getPayload(response))
      await dispatch('explorer')
      return item
    },
    async updateMenu ({ dispatch }, payload) {
      const title = Array.isArray(payload && payload.title) ? normalizeMultiLanguage(payload.title) : toMultiLanguage(payload && payload.name ? payload.name : '')
      const description = Array.isArray(payload && payload.description) ? normalizeMultiLanguage(payload.description) : toMultiLanguage(payload && payload.description ? payload.description : '')
      const response = await Service.security('update-menu', {
        _id: payload && payload._id ? payload._id : '',
        title,
        description,
        path: payload && payload.path ? payload.path : '',
        type: payload && payload.typeId ? payload.typeId : '',
        state: payload && typeof payload.state === 'boolean' ? payload.state : true
      })
      const item = mapMenu(getPayload(response))
      await dispatch('explorer')
      return item
    },
    async removeMenu ({ dispatch }, item) {
      await Service.security('delete-menu', { id: item && item._id ? item._id : '' })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    types: (state) => state.types,
    menus: (state) => state.menus
  }
}
