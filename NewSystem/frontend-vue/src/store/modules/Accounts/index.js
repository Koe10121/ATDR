import Service from '@/service/api'
import { formatDateTime24 } from '@/projects/utils/date-time'

function pickLangValue(items) {
  if (!Array.isArray(items)) return ''
  const found = items.find(item => item && item.value)
  return found ? String(found.value) : ''
}

function getStatusLabel(status) {
  if (!status || typeof status !== 'object') return '-'
  return pickLangValue(status.title) || status.key || '-'
}

function getGroupLabel(group) {
  if (!group) return '-'
  if (typeof group === 'string') return String(group || '-') || '-'
  if (typeof group !== 'object') return '-'
  if (Array.isArray(group.title)) return pickLangValue(group.title) || group.key || '-'
  return group.title || group.name || group.key || '-'
}

function getLifecycleRefLabel(item) {
  if (!item) return ''
  if (typeof item === 'string') return String(item)
  if (Array.isArray(item.title)) return pickLangValue(item.title) || item.key || ''
  return item.key || item.label || ''
}

function mapAccount(item) {
  const status = item && item.status && typeof item.status === 'object' ? item.status : null
  const securityGroups = item && Array.isArray(item.securityGroups) ? item.securityGroups : []
  const prefix = item && item.userinfo && Array.isArray(item.userinfo.prefix) ? pickLangValue(item.userinfo.prefix) : ''
  const firstName = item && item.userinfo && Array.isArray(item.userinfo.firstName) ? pickLangValue(item.userinfo.firstName) : ''
  const lastName = item && item.userinfo && Array.isArray(item.userinfo.lastName) ? pickLangValue(item.userinfo.lastName) : ''
  const birthdayRaw = item && item.userinfo && item.userinfo.birthday ? new Date(item.userinfo.birthday) : null
  const deviceLogs = item && item.control && Array.isArray(item.control.device) ? item.control.device : []
  const lastLoginRaw = deviceLogs
    .map(device => device && device.dateTime ? new Date(device.dateTime) : null)
    .filter(value => value instanceof Date && !Number.isNaN(value.getTime()))
    .sort((left, right) => right.getTime() - left.getTime())[0] || null
  const lifecycle = item && item.lifecycle && typeof item.lifecycle === 'object' ? item.lifecycle : {}
  const affiliations = Array.isArray(lifecycle.affiliations) ? lifecycle.affiliations : []
  const primaryAffiliationRef = lifecycle.primaryAffiliation || (affiliations.find(entry => entry && entry.isPrimary) || {}).type || ''
  const primaryAffiliation = getLifecycleRefLabel(primaryAffiliationRef)
  const provisioningState = lifecycle.provisioning && lifecycle.provisioning.state ? String(lifecycle.provisioning.state) : 'UNPROVISIONED'

  return {
    _id: item && item._id ? String(item._id) : '',
    code: item && item.code ? String(item.code) : '-',
    email: item && item.email ? String(item.email) : '-',
    prefix,
    firstName,
    lastName,
    fullName: `${prefix} ${firstName} ${lastName}`.trim() || '-',
    msisdn: item && item.userinfo && item.userinfo.msisdn ? String(item.userinfo.msisdn) : '-',
    lineId: item && item.userinfo && item.userinfo.lineId ? String(item.userinfo.lineId) : '-',
    cardId: item && item.userinfo && item.userinfo.cardId ? String(item.userinfo.cardId) : '-',
    religion: item && item.userinfo && item.userinfo.religion ? String(item.userinfo.religion) : '-',
    birthday: birthdayRaw && !Number.isNaN(birthdayRaw.getTime()) ? birthdayRaw.toISOString().slice(0, 10) : '',
    birthdayLabel: birthdayRaw && !Number.isNaN(birthdayRaw.getTime()) ? birthdayRaw.toLocaleDateString() : '-',
    image: item && item.userinfo && item.userinfo.image ? String(item.userinfo.image) : '',
    groupLabel: securityGroups.length ? securityGroups.map(getGroupLabel).join(', ') : '-',
    groupIds: securityGroups
      .map(group => group && group._id ? String(group._id) : '')
      .filter(Boolean),
    lastLoginLabel: formatDateTime24(lastLoginRaw),
    lastLoginDateLabel: lastLoginRaw ? lastLoginRaw.toLocaleDateString() : '-',
    lastLoginTimeLabel: lastLoginRaw ? lastLoginRaw.toLocaleTimeString() : '-',
    statusKey: status && status.key ? String(status.key) : '',
    statusLabel: getStatusLabel(status),
    primaryAffiliation: primaryAffiliation || '-',
    lifecycleAffiliationCount: affiliations.length,
    provisioningState,
    lifecycle,
    raw: item
  }
}

const state = {
  items: [],
  statusOptions: [],
  groupOptions: [],
  lastUpdatedAt: null,
  accessGroups: [],
  accessPermissions: [],
  selectedLifecycle: null,
  accountSessions: [],
  trustedDevices: []
}

export default {
  namespaced: true,
  state,
  mutations: {
    items(state, value) {
      state.items = Array.isArray(value) ? value : []
    },
    statusOptions(state, value) {
      state.statusOptions = Array.isArray(value) ? value : []
    },
    groupOptions(state, value) {
      state.groupOptions = Array.isArray(value) ? value : []
    },
    lastUpdatedAt(state, value) {
      state.lastUpdatedAt = value instanceof Date ? value : null
    },
    accessReview(state, value) {
      state.accessGroups = Array.isArray(value && value.groups) ? value.groups : []
      state.accessPermissions = Array.isArray(value && value.permissions) ? value.permissions : []
    },
    clearAccessReview(state) {
      state.accessGroups = []
      state.accessPermissions = []
    },
    selectedLifecycle(state, value) {
      state.selectedLifecycle = value || null
    },
    accountSessions(state, value) {
      state.accountSessions = Array.isArray(value) ? value : []
    },
    trustedDevices(state, value) {
      state.trustedDevices = Array.isArray(value) ? value : []
    },
    clearSecurityWorkspace(state) {
      state.accessGroups = []
      state.accessPermissions = []
      state.accountSessions = []
      state.trustedDevices = []
    }
  },
  actions: {
    async explorer({ commit }) {
      const [accountsRes, statusRes, groupRes] = await Promise.all([
        Service.accounts('list'),
        Service.accounts('status-options'),
        Service.accounts('group-options')
      ])

      const items = Array.isArray(accountsRes && accountsRes.data && accountsRes.data.data)
        ? accountsRes.data.data.map(mapAccount)
        : []
      const rawStatuses = statusRes && statusRes.data && statusRes.data.data && Array.isArray(statusRes.data.data.statuses)
        ? statusRes.data.data.statuses
        : []
      const statusOptions = rawStatuses.map(item => ({
        key: item && item.key ? String(item.key) : '',
        label: getStatusLabel(item)
      })).filter(item => item.key)
      const rawGroups = groupRes && groupRes.data && groupRes.data.data && Array.isArray(groupRes.data.data.groups)
        ? groupRes.data.data.groups
        : []
      const groupOptions = rawGroups.map(item => ({
        _id: item && item._id ? String(item._id) : '',
        label: item && item.label ? String(item.label) : '-'
      })).filter(item => item._id)

      commit('items', items)
      commit('statusOptions', statusOptions)
      commit('groupOptions', groupOptions)
      commit('lastUpdatedAt', new Date())
      return items
    },
    async fetchAccessReview({ commit }, id) {
      const response = await Service.accounts('effective-permissions', { id })
      const data = response && response.data ? response.data.data : {}
      commit('accessReview', {
        groups: Array.isArray(data && data.groups) ? data.groups : [],
        permissions: Array.isArray(data && data.effectivePermissions) ? data.effectivePermissions : []
      })
      return data
    },
    async fetchSessions({ commit }, id) {
      const response = await Service.accounts('sessions', { id })
      const data = response && response.data && response.data.data ? response.data.data : {}
      commit('accountSessions', Array.isArray(data.sessions) ? data.sessions : [])
      return data
    },
    async revokeSession({ dispatch }, payload) {
      await Service.accounts('revoke-session', payload)
      await dispatch('fetchSessions', payload && (payload.id || payload._id))
      return true
    },
    async fetchTrustedDevices({ commit }, id) {
      const response = await Service.accounts('trusted-devices', { id })
      const data = response && response.data && response.data.data ? response.data.data : {}
      commit('trustedDevices', Array.isArray(data.trustedDevices) ? data.trustedDevices : [])
      return data
    },
    async revokeTrustedDevice({ dispatch }, payload) {
      await Service.accounts('revoke-trusted-device', payload)
      await dispatch('fetchTrustedDevices', payload && (payload.id || payload._id))
      return true
    },
    async archive({ dispatch }, id) {
      await Service.accounts('change-status', {
        id,
        toStatusKey: 'ARCHIVED',
        action: 'archive'
      })
      await dispatch('explorer')
      return true
    },
    async update({ dispatch }, payload) {
      await Service.accounts('update', payload)
      if (payload && payload.statusKey) {
        await Service.accounts('change-status', {
          id: payload._id,
          toStatusKey: payload.statusKey,
          action: String(payload.statusKey).toLowerCase()
        })
      }
      await dispatch('explorer')
      return true
    },
    async invite({ dispatch }, payload) {
      await Service.accounts('invite', payload)
      await dispatch('explorer')
      return true
    },
    async removeNewSystemAccess({ dispatch }, payload) {
      await Service.accounts('remove-newSystem-access', payload)
      await dispatch('explorer')
      return true
    },
    async fetchLifecycle({ commit }, id) {
      const response = await Service.accounts('lifecycle', { id })
      const data = response && response.data ? response.data.data : null
      commit('selectedLifecycle', data)
      return data
    },
    async updateLifecycle({ dispatch, commit }, payload) {
      const response = await Service.accounts('update-lifecycle', payload)
      const data = response && response.data ? response.data.data : null
      commit('selectedLifecycle', data)
      await dispatch('explorer')
      return data
    },
    async provision({ dispatch, commit }, payload) {
      const response = await Service.accounts('provision', payload)
      const data = response && response.data ? response.data.data : null
      commit('selectedLifecycle', data)
      await dispatch('explorer')
      return data
    },
    async deprovision({ dispatch, commit }, payload) {
      const response = await Service.accounts('deprovision', payload)
      const data = response && response.data ? response.data.data : null
      commit('selectedLifecycle', data)
      await dispatch('explorer')
      return data
    }
  },
  getters: {
    items: state => state.items,
    statusOptions: state => state.statusOptions,
    groupOptions: state => state.groupOptions,
    lastUpdatedAt: state => state.lastUpdatedAt,
    accessGroups: state => state.accessGroups,
    accessPermissions: state => state.accessPermissions,
    selectedLifecycle: state => state.selectedLifecycle,
    accountSessions: state => state.accountSessions,
    trustedDevices: state => state.trustedDevices,
    lastUpdatedLabel: state => formatDateTime24(state.lastUpdatedAt)
  }
}
