import Service from '@/service/api'
import {
  fetchSecurityBootstrap,
  getPayload,
  mapGroup,
  normalizeMultiLanguage,
  toMultiLanguage
} from './shared'

const moduleState = {
  groups: [],
  types: []
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
    }
  },
  actions: {
    async explorer ({ commit }) {
      const data = await fetchSecurityBootstrap()
      commit('groups', data.groups)
      commit('types', data.types)
      return true
    },
    async create ({ dispatch }, payload) {
      const title = Array.isArray(payload && payload.title) ? normalizeMultiLanguage(payload.title) : toMultiLanguage(payload && payload.name ? payload.name : '')
      const description = Array.isArray(payload && payload.description) ? normalizeMultiLanguage(payload.description) : toMultiLanguage(payload && payload.description ? payload.description : '')
      const response = await Service.security('create-group', {
        title,
        description,
        visibleType: payload && payload.visibleTypeId ? payload.visibleTypeId : '',
        state: payload && typeof payload.state === 'boolean' ? payload.state : true
      })
      const item = mapGroup(getPayload(response))
      await dispatch('explorer')
      return item
    },
    async update ({ dispatch }, payload) {
      const title = Array.isArray(payload && payload.title) ? normalizeMultiLanguage(payload.title) : toMultiLanguage(payload && payload.name ? payload.name : '')
      const description = Array.isArray(payload && payload.description) ? normalizeMultiLanguage(payload.description) : toMultiLanguage(payload && payload.description ? payload.description : '')
      const response = await Service.security('update-group', {
        _id: payload && payload._id ? payload._id : '',
        title,
        description,
        visibleType: payload && payload.visibleTypeId ? payload.visibleTypeId : '',
        state: payload && typeof payload.state === 'boolean' ? payload.state : true
      })
      const item = mapGroup(getPayload(response))
      await dispatch('explorer')
      return item
    },
    async remove ({ dispatch }, item) {
      await Service.security('delete-group', { id: item && item._id ? item._id : '' })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    groups: (state) => state.groups,
    types: (state) => state.types
  }
}
