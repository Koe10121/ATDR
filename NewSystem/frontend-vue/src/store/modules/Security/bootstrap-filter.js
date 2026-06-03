const PROJECT_PERMISSION_TYPE_TITLE = process.env.VUE_APP_PROJECT_PERMISSION_TYPE_TITLE || 'New System Administration'
const PROJECT_PERMISSION_ROOT_PATH = process.env.VUE_APP_PROJECT_PERMISSION_ROOT_PATH || '/new-system/security/permission'
const PROJECT_APP_ID = process.env.VUE_APP_PROJECT_APP_ID || 'newSystem'

function buildDefaultPermissionPaths (rootPath = PROJECT_PERMISSION_ROOT_PATH) {
  return [
    rootPath,
    '/dashboard',
    '/operations/business',
    '/config/message-authen',
    '/config/email-notifications',
    '/config/workflow-actions',
    '/config/runtime-access',
    '/config/database-backup',
    '/config/setting-message',
    '/config/verification',
    '/setting/group',
    '/setting/message-status',
    '/security/permissions/menu',
    '/security/permissions/group',
    '/security/permissions/matrix',
    '/security/audit',
    '/accounts/directory',
  '/accounts/lifecycle'
  ]
}

const PROJECT_PERMISSION_PATHS = Array.from(new Set(
  buildDefaultPermissionPaths().concat(
    String(process.env.VUE_APP_PROJECT_PERMISSION_PATHS || '')
      .split(',')
      .map(item => String(item || '').trim())
      .filter(Boolean)
  )
))

function normalizeScopeValue (value) {
  return String(value || '').trim().toLowerCase()
}

function normalizePathValue (value) {
  let normalized = String(value || '').trim()
  const queryIndex = normalized.indexOf('?')
  if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex)
  const hashIndex = normalized.indexOf('#')
  if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex)
  normalized = normalized.replace(/\/{2,}/g, '/')
  if (normalized && !normalized.startsWith('/')) normalized = `/${normalized}`
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1)
  }
  return normalized
}

function isProjectScoped (item) {
  if (!item) return false
  const projectAppId = normalizeScopeValue(PROJECT_APP_ID)
  return normalizeScopeValue(item.appId) === projectAppId || normalizeScopeValue(item.source) === projectAppId
}

export function normalizeNewSystemData (data) {
  const allowedPathSet = new Set(PROJECT_PERMISSION_PATHS.map(normalizePathValue).filter(Boolean))
  const projectTypesById = new Map()
  ;(data.types || []).forEach(type => {
    if (type.name === PROJECT_PERMISSION_TYPE_TITLE || isProjectScoped(type)) {
      projectTypesById.set(type._id, type)
    }
  })
  const scopedTypeIds = new Set(projectTypesById.keys())
  ;(data.menus || []).forEach(menu => {
    if (isProjectScoped(menu) && menu.typeId) scopedTypeIds.add(menu.typeId)
  })
  ;(data.types || []).forEach(type => {
    if (scopedTypeIds.has(type._id)) projectTypesById.set(type._id, type)
  })
  const projectTypes = Array.from(projectTypesById.values())
  const projectTypeIds = new Set(projectTypes.map(type => type._id))
  const primaryProjectType = projectTypes[0] || null
  const projectMenus = (data.menus || [])
    .filter(menu => (
      allowedPathSet.has(normalizePathValue(menu.path)) || isProjectScoped(menu) || projectTypeIds.has(menu.typeId)
    ))
    .map(menu => {
      if (!primaryProjectType || !allowedPathSet.has(normalizePathValue(menu.path))) {
        return menu
      }
      return {
        ...menu,
        typeId: primaryProjectType._id,
        typeName: primaryProjectType.name,
        source: menu.source || PROJECT_APP_ID
      }
    })
  const projectMenuIds = new Set(projectMenus.map(menu => menu._id))
  const projectGroups = (data.groups || []).filter(group => projectTypeIds.has(group.visibleTypeId))
  const projectGroupIds = new Set(projectGroups.map(group => group._id))
  const projectPermissions = (data.permissions || []).filter(permission =>
    projectMenuIds.has(permission.menuId) && projectGroupIds.has(permission.groupId)
  )

  return {
    types: projectTypes,
    menus: projectMenus,
    groups: projectGroups,
    permissions: projectPermissions
  }
}
