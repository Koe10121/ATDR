import Service from '@/service/api'
import { fetchSecurityBootstrap, getPayload, getTextByLanguage } from './shared'

function pickLangValue (items) {
  if (!Array.isArray(items)) return ''
  const found = items.find(item => item && item.value)
  return found ? String(found.value) : ''
}

function getAccountLabel (item) {
  if (!item || typeof item !== 'object') return '-'
  const firstName = item.userinfo && Array.isArray(item.userinfo.firstName) ? pickLangValue(item.userinfo.firstName) : ''
  const lastName = item.userinfo && Array.isArray(item.userinfo.lastName) ? pickLangValue(item.userinfo.lastName) : ''
  const fullName = `${firstName} ${lastName}`.trim()
  return fullName || item.email || item.code || '-'
}

function mapAssignment (item) {
  const account = item && item.account && typeof item.account === 'object' ? item.account : null
  const group = item && item.group && typeof item.group === 'object' ? item.group : null
  return {
    _id: item && item._id ? String(item._id) : '',
    accountId: account && account._id ? String(account._id) : (item && item.account ? String(item.account) : ''),
    accountLabel: getAccountLabel(account),
    groupId: group && group._id ? String(group._id) : (item && item.group ? String(item.group) : ''),
    groupLabel: group ? (getTextByLanguage(group.title) || '-') : '-',
    dataScope: item && item.dataScope ? String(item.dataScope) : 'self',
    scopeUnits: Array.isArray(item && item.scopeUnits) ? item.scopeUnits.map(String) : [],
    active: !(item && item.active === false)
  }
}

export default {
  namespaced: true,
  state: {
    assignments: [],
    groups: [],
    accounts: []
  },
  mutations: {
    assignments (state, value) {
      state.assignments = Array.isArray(value) ? value : []
    },
    groups (state, value) {
      state.groups = Array.isArray(value) ? value : []
    },
    accounts (state, value) {
      state.accounts = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const [securityData, assignmentRes, accountRes] = await Promise.all([
        fetchSecurityBootstrap(),
        Service.security('assignments'),
        Service.accounts('list')
      ])
      const assignments = getPayload(assignmentRes) || []
      const accounts = getPayload(accountRes) || []
      commit('groups', securityData.groups)
      commit('assignments', assignments.map(mapAssignment))
      commit('accounts', accounts.map(item => ({
        _id: item && item._id ? String(item._id) : '',
        label: getAccountLabel(item)
      })))
      return true
    },
    async create ({ dispatch }, payload) {
      await Service.security('create-assignment', {
        account: payload && payload.accountId ? payload.accountId : '',
        group: payload && payload.groupId ? payload.groupId : '',
        dataScope: payload && payload.dataScope ? payload.dataScope : 'self',
        scopeUnits: Array.isArray(payload && payload.scopeUnits) ? payload.scopeUnits : [],
        active: !(payload && payload.active === false)
      })
      await dispatch('explorer')
      return true
    },
    async update ({ dispatch }, payload) {
      await Service.security('update-assignment', {
        _id: payload && payload._id ? payload._id : '',
        account: payload && payload.accountId ? payload.accountId : '',
        group: payload && payload.groupId ? payload.groupId : '',
        dataScope: payload && payload.dataScope ? payload.dataScope : 'self',
        scopeUnits: Array.isArray(payload && payload.scopeUnits) ? payload.scopeUnits : [],
        active: !(payload && payload.active === false)
      })
      await dispatch('explorer')
      return true
    },
    async remove ({ dispatch }, payload) {
      await Service.security('delete-assignment', { id: payload && payload._id ? payload._id : '' })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    assignments: state => state.assignments,
    groups: state => state.groups,
    accounts: state => state.accounts
  }
}
