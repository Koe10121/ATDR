import Service from '@/service/api'
import { formatDateTime24 } from '@/projects/utils/date-time'

function pickLangValue(items, preferred = 'en') {
  if (!Array.isArray(items)) return ''
  const normalized = items
    .map(item => ({
      key: item && item.key ? String(item.key).toLowerCase() : '',
      value: item && item.value ? String(item.value) : ''
    }))
    .filter(item => item.value)
  if (!normalized.length) return ''
  const direct = normalized.find(item => item.key === preferred)
  if (direct) return direct.value
  const fallback = normalized.find(item => item.key === 'en') || normalized[0]
  return fallback ? fallback.value : ''
}

function accountLabel(account) {
  if (!account) return '-'
  if (typeof account === 'string') return String(account)
  const prefix = pickLangValue(account.userinfo && account.userinfo.prefix, 'th')
  const firstName = pickLangValue(account.userinfo && account.userinfo.firstName, 'th')
  const lastName = pickLangValue(account.userinfo && account.userinfo.lastName, 'th')
  const fullName = [prefix, firstName, lastName].filter(Boolean).join(' ').trim()
  if (fullName) return fullName
  if (account.code) return String(account.code)
  if (account.email) return String(account.email)
  return '-'
}

function mapCourse(item) {
  return {
    _id: item && item._id ? String(item._id) : '',
    code: item && item.code ? String(item.code) : '',
    titleText: pickLangValue(item && item.title, 'en') || pickLangValue(item && item.title, 'th') || (item && item.code ? String(item.code) : 'Untitled course'),
    provider: item && item.provider ? String(item.provider) : '-',
    state: !(item && item.state === false)
  }
}

function statusFromRequest(item) {
  if (!item) return ''
  if (typeof item.status === 'string') return String(item.status).toLowerCase()
  if (item.status && item.status.key) return String(item.status.key).toLowerCase()
  if (item.state) return String(item.state).toLowerCase()
  return ''
}

function mapRequest(item) {
  const statusKey = statusFromRequest(item) || 'draft'
  const trainingStart = item && item.trainingStart ? String(item.trainingStart).slice(0, 10) : ''
  const trainingEnd = item && item.trainingEnd ? String(item.trainingEnd).slice(0, 10) : ''
  const courseObj = item && item.course && typeof item.course === 'object' ? item.course : null
  const requesterObj = item && item.requester && typeof item.requester === 'object' ? item.requester : null
  const approverObj = item && item.approver && typeof item.approver === 'object' ? item.approver : null
  const updatedAt = item && item.update && item.update.datetime ? item.update.datetime : (item && item.updatedAt ? item.updatedAt : null)

  return {
    _id: item && item._id ? String(item._id) : '',
    requestNo: item && item.requestNo ? String(item.requestNo) : '',
    titleText: pickLangValue(item && item.title, 'en') || pickLangValue(item && item.title, 'th') || '-',
    reasonText: pickLangValue(item && item.reason, 'en') || pickLangValue(item && item.reason, 'th') || '-',
    requesterId: requesterObj && requesterObj._id ? String(requesterObj._id) : (item && item.requester ? String(item.requester) : ''),
    requesterLabel: accountLabel(requesterObj || (item && item.requester)),
    courseId: courseObj && courseObj._id ? String(courseObj._id) : (item && item.course ? String(item.course) : ''),
    courseLabel: courseObj ? (pickLangValue(courseObj.title, 'en') || courseObj.code || '-') : '-',
    approverId: approverObj && approverObj._id ? String(approverObj._id) : (item && item.approver ? String(item.approver) : ''),
    approverLabel: approverObj ? accountLabel(approverObj) : '-',
    trainingStart,
    trainingEnd,
    periodLabel: [trainingStart, trainingEnd].filter(Boolean).join(' - ') || '-',
    statusKey,
    statusLabel: String(statusKey || '-').toUpperCase(),
    updatedAt: updatedAt ? String(updatedAt) : '',
    updatedAtLabel: formatDateTime24(updatedAt)
  }
}

function mapAction(item) {
  const actorObj = item && item.actor && typeof item.actor === 'object' ? item.actor : null
  const createdAt = item && item.create && item.create.datetime ? item.create.datetime : (item && item.createdAt ? item.createdAt : null)
  return {
    _id: item && item._id ? String(item._id) : '',
    requestId: item && item.request ? String(item.request && item.request._id ? item.request._id : item.request) : '',
    action: item && item.action ? String(item.action) : '-',
    actorLabel: accountLabel(actorObj || (item && item.actor)),
    note: item && item.note ? String(item.note) : '-',
    createdAtLabel: formatDateTime24(createdAt)
  }
}

function mapRecord(item) {
  const requestObj = item && item.request && typeof item.request === 'object' ? item.request : null
  const courseObj = requestObj && requestObj.course && typeof requestObj.course === 'object' ? requestObj.course : null
  const createdAt = item && item.create && item.create.datetime ? item.create.datetime : (item && item.createdAt ? item.createdAt : null)
  return {
    _id: item && item._id ? String(item._id) : '',
    requestId: requestObj && requestObj._id ? String(requestObj._id) : (item && item.request ? String(item.request) : ''),
    status: item && item.status ? String(item.status) : '-',
    score: item && item.score != null ? Number(item.score) : null,
    resultNote: item && item.resultNote ? String(item.resultNote) : '-',
    requestTitle: requestObj ? (pickLangValue(requestObj.title, 'en') || pickLangValue(requestObj.title, 'th') || '-') : '-',
    courseLabel: courseObj ? (pickLangValue(courseObj.title, 'en') || courseObj.code || '-') : '-',
    createdAtLabel: formatDateTime24(createdAt)
  }
}

const state = {
  requests: [],
  actions: [],
  records: [],
  courses: [],
  selectedRequestId: '',
  lastUpdatedAt: null
}

export default {
  namespaced: true,
  state,
  mutations: {
    requests(state, value) {
      state.requests = Array.isArray(value) ? value : []
    },
    actions(state, value) {
      state.actions = Array.isArray(value) ? value : []
    },
    records(state, value) {
      state.records = Array.isArray(value) ? value : []
    },
    courses(state, value) {
      state.courses = Array.isArray(value) ? value : []
    },
    selectedRequestId(state, value) {
      state.selectedRequestId = value ? String(value) : ''
    },
    lastUpdatedAt(state, value) {
      state.lastUpdatedAt = value instanceof Date ? value : null
    }
  },
  actions: {
    async explorer({ commit }, params = {}) {
      const [requestsRes, recordsRes] = await Promise.all([
        Service.training('requests', params),
        Service.training('records', params)
      ])

      let courseItems = []
      try {
        const courseRes = await Service.settings('training-courses', { state: true })
        courseItems = (courseRes && courseRes.data && courseRes.data.data) || []
      } catch (error) {
        courseItems = []
      }

      const requestItems = (requestsRes && requestsRes.data && requestsRes.data.data) || []
      const recordItems = (recordsRes && recordsRes.data && recordsRes.data.data) || []
      commit('requests', requestItems.map(mapRequest))
      commit('records', recordItems.map(mapRecord))
      commit('courses', courseItems.map(mapCourse))
      commit('lastUpdatedAt', new Date())
      return true
    },
    async fetchActions({ commit }, requestId) {
      const query = requestId ? { requestId: String(requestId) } : {}
      const response = await Service.training('actions', query)
      const items = (response && response.data && response.data.data) || []
      commit('actions', items.map(mapAction))
      commit('selectedRequestId', requestId || '')
      return true
    },
    async createRequest({ dispatch, rootGetters }, payload) {
      const profile = rootGetters['auth/profile'] || null
      const requesterId = payload && payload.requesterId ? String(payload.requesterId) : (profile && profile._id ? String(profile._id) : '')
      if (!requesterId) throw new Error('missing_requester')
      if (!(payload && payload.courseId && payload.title && payload.trainingStart && payload.trainingEnd)) {
        throw new Error('invalid_payload')
      }
      await Service.training('create-request', {
        requester: requesterId,
        course: String(payload.courseId),
        title: [{ key: 'en', value: String(payload.title) }],
        reason: [{ key: 'en', value: String(payload.reason || payload.title) }],
        trainingStart: payload.trainingStart,
        trainingEnd: payload.trainingEnd,
        steps: payload && payload.approverId ? [{ order: 1, approver: String(payload.approverId) }] : []
      })
      await dispatch('explorer')
      return true
    },
    async submitRequest({ dispatch, rootGetters }, payload) {
      const profile = rootGetters['auth/profile'] || null
      const requesterId = payload && payload.requesterId ? String(payload.requesterId) : (profile && profile._id ? String(profile._id) : '')
      await Service.training('submit-request', {
        _id: payload && payload._id ? String(payload._id) : '',
        requesterId,
        note: payload && payload.note ? String(payload.note) : 'submit from frontend'
      })
      await dispatch('explorer')
      if (payload && payload._id) await dispatch('fetchActions', payload._id)
      return true
    },
    async approveRequest({ dispatch, rootGetters }, payload) {
      const profile = rootGetters['auth/profile'] || null
      const approverId = payload && payload.approverId ? String(payload.approverId) : (profile && profile._id ? String(profile._id) : '')
      await Service.training('approve-request', {
        _id: payload && payload._id ? String(payload._id) : '',
        approverId,
        note: payload && payload.note ? String(payload.note) : 'approve from frontend'
      })
      await dispatch('explorer')
      if (payload && payload._id) await dispatch('fetchActions', payload._id)
      return true
    },
    async rejectRequest({ dispatch, rootGetters }, payload) {
      const profile = rootGetters['auth/profile'] || null
      const approverId = payload && payload.approverId ? String(payload.approverId) : (profile && profile._id ? String(profile._id) : '')
      await Service.training('reject-request', {
        _id: payload && payload._id ? String(payload._id) : '',
        approverId,
        note: payload && payload.note ? String(payload.note) : 'reject from frontend'
      })
      await dispatch('explorer')
      if (payload && payload._id) await dispatch('fetchActions', payload._id)
      return true
    },
    async completeRequest({ dispatch, rootGetters }, payload) {
      const profile = rootGetters['auth/profile'] || null
      const actorId = payload && payload.actorId ? String(payload.actorId) : (profile && profile._id ? String(profile._id) : '')
      await Service.training('complete-request', {
        _id: payload && payload._id ? String(payload._id) : '',
        actorId,
        recordStatus: payload && payload.recordStatus ? String(payload.recordStatus) : 'completed',
        score: payload && payload.score != null ? Number(payload.score) : 100,
        resultNote: payload && payload.resultNote ? String(payload.resultNote) : 'completed from frontend'
      })
      await dispatch('explorer')
      if (payload && payload._id) await dispatch('fetchActions', payload._id)
      return true
    }
  },
  getters: {
    requests: state => state.requests,
    actions: state => state.actions,
    records: state => state.records,
    courses: state => state.courses,
    selectedRequestId: state => state.selectedRequestId,
    lastUpdatedLabel: state => formatDateTime24(state.lastUpdatedAt),
    summary: state => {
      const summary = { total: 0, submitted: 0, approved: 0, completed: 0 }
      summary.total = state.requests.length
      state.requests.forEach(item => {
        const key = String(item && item.statusKey ? item.statusKey : '').toLowerCase()
        if (key.includes('submit') || key.includes('pending')) summary.submitted += 1
        if (key.includes('approve')) summary.approved += 1
        if (key.includes('complete')) summary.completed += 1
      })
      return summary
    }
  }
}

