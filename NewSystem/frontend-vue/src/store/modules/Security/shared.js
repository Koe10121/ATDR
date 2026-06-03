import Service from '@/service/api'
import { normalizeNewSystemData } from './bootstrap-filter'

export function getPayload (response) {
  return (response && response.data && response.data.data) || null
}

export function normalizeMultiLanguage (value) {
  if (Array.isArray(value)) return value
  if (!value) return []
  return [{ key: 'th', value: String(value) }]
}

export function getTextByLanguage (multiLanguage, language = 'th') {
  const items = normalizeMultiLanguage(multiLanguage)
  const byLanguage = items.find(item => item && item.key === language && item.value)
  if (byLanguage) return byLanguage.value
  const byEnglish = items.find(item => item && item.key === 'en' && item.value)
  if (byEnglish) return byEnglish.value
  const first = items.find(item => item && item.value)
  return first ? first.value : ''
}

export function toMultiLanguage (value, language = 'th') {
  const text = String(value || '').trim()
  if (!text) return []
  return [{ key: language, value: text }]
}

export function mapType (item) {
  return {
    _id: item && item._id ? String(item._id) : '',
    appId: item && item.appId ? String(item.appId) : '',
    source: item && item.source ? String(item.source) : '',
    title: normalizeMultiLanguage(item && item.title),
    description: normalizeMultiLanguage(item && item.description),
    name: getTextByLanguage(item && item.title),
    state: item && typeof item.state === 'boolean' ? item.state : true,
    stateLabel: item && item.state === false ? 'Inactive' : 'Active'
  }
}

export function mapMenu (item) {
  const typeObj = item && item.type && typeof item.type === 'object' ? item.type : null
  return {
    _id: item && item._id ? String(item._id) : '',
    appId: item && item.appId ? String(item.appId) : '',
    title: normalizeMultiLanguage(item && item.title),
    description: normalizeMultiLanguage(item && item.description),
    name: getTextByLanguage(item && item.title),
    descriptionText: getTextByLanguage(item && item.description),
    path: item && item.path ? item.path : '',
    typeId: typeObj ? String(typeObj._id) : (item && item.type ? String(item.type) : ''),
    typeName: typeObj ? getTextByLanguage(typeObj.title) : '',
    source: item && item.source ? item.source : '-',
    state: item && typeof item.state === 'boolean' ? item.state : true,
    stateLabel: item && item.state === false ? 'Inactive' : 'Active'
  }
}

export function mapGroup (item) {
  const typeObj = item && item.visibleType && typeof item.visibleType === 'object' ? item.visibleType : null
  return {
    _id: item && item._id ? String(item._id) : '',
    title: normalizeMultiLanguage(item && item.title),
    description: normalizeMultiLanguage(item && item.description),
    name: getTextByLanguage(item && item.title),
    descriptionText: getTextByLanguage(item && item.description),
    visibleTypeId: typeObj ? String(typeObj._id) : (item && item.visibleType ? String(item.visibleType) : ''),
    visibleTypeName: typeObj ? getTextByLanguage(typeObj.title) : '',
    state: item && typeof item.state === 'boolean' ? item.state : true,
    stateLabel: item && item.state === false ? 'Inactive' : 'Active'
  }
}

export function mapPermission (item) {
  const groupObj = item && item.group && typeof item.group === 'object' ? item.group : null
  const menuObj = item && item.menu && typeof item.menu === 'object' ? item.menu : null
  return {
    _id: item && item._id ? String(item._id) : '',
    groupId: groupObj ? String(groupObj._id) : (item && item.group ? String(item.group) : ''),
    menuId: menuObj ? String(menuObj._id) : (item && item.menu ? String(item.menu) : ''),
    all: !!(item && item.all),
    view: !!(item && item.view),
    edit: !!(item && item.edit),
    delete: !!(item && item.delete),
    action: !!(item && item.action),
    logs: !!(item && item.logs)
  }
}

export async function fetchSecurityBootstrap () {
  const [typesRes, menusRes, groupsRes, permissionsRes] = await Promise.all([
    Service.security('types'),
    Service.security('menus'),
    Service.security('groups'),
    Service.security('permissions')
  ])

  return normalizeNewSystemData({
    types: (getPayload(typesRes) || []).map(mapType),
    menus: (getPayload(menusRes) || []).map(mapMenu),
    groups: (getPayload(groupsRes) || []).map(mapGroup),
    permissions: (getPayload(permissionsRes) || []).map(mapPermission)
  })
}
