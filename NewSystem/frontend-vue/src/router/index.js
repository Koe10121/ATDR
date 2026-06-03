import Vue from 'vue'
import Router from 'vue-router'
import store from '@/store/store'

const TheContainer = () => import('@/containers/TheContainer')
const Dashboard = () => import('@/views/Dashboard')
const Page404 = () => import('@/views/pages/Page404')
const Page500 = () => import('@/views/pages/Page500')
const Login = () => import('@/views/pages/Login')
const NewSystemRegistry = () => import('@/projects/views/newSystem/NewSystemRegistry')
const AccountDirectory = () => import('@/projects/views/accounts/Management')
const BusinessOperations = () => import('@/projects/views/operations/BusinessOperations')
const CreateMenu = () => import('@/projects/views/security/CreateMenu')
const CreateGroup = () => import('@/projects/views/security/CreateGroup')
const PermissionMatrix = () => import('@/projects/views/security/PermissionMatrix')
const AuditExplorer = () => import('@/projects/views/security/AuditExplorer')
const SettingMessageAuthen = () => import('@/projects/views/setting/MessageAuthen')
const EmailNotifications = () => import('@/projects/views/setting/EmailNotifications')
const WorkflowActions = () => import('@/projects/views/setting/WorkflowActions')
const RuntimeAccess = () => import('@/projects/views/setting/RuntimeAccess')
const DatabaseBackup = () => import('@/projects/views/setting/DatabaseBackup')
const SettingMessage = () => import('@/projects/views/setting/Message')
const SettingVerification = () => import('@/projects/views/setting/Verification')
const SettingGroup = () => import('@/projects/views/setting/Group')
const SettingMessageStatus = () => import('@/projects/views/setting/Status')

Vue.use(Router)

const router = new Router({
  hash: false,
  mode: 'history',
  linkActiveClass: 'open active',
  scrollBehavior: () => ({ y: 0 }),
  routes: [
    {
      path: '/',
      redirect: '/dashboard',
      name: 'Home',
      component: TheContainer,
      children: [
        {
          path: 'dashboard',
          name: 'Dashboard',
          meta: { permission: { path: '/dashboard', action: 'view' } },
          component: Dashboard
        },
        {
          path: 'newSystem/registry',
          name: 'New System Registry',
          meta: { permission: { path: '/newsystem/registry', action: 'view' } },
          component: NewSystemRegistry
        },
        {
          path: 'operations/business',
          name: 'Business Operations',
          meta: { permission: { path: '/operations/business', action: 'view' } },
          component: BusinessOperations
        },
        {
          path: 'accounts/directory',
          name: 'Account Directory',
          meta: { permission: { path: '/accounts/directory', action: 'view' } },
          component: AccountDirectory
        },
        {
          path: 'security/permissions',
          redirect: '/security/permissions/menu',
          name: 'Permission'
        },
        {
          path: 'security/permissions/menu',
          name: 'Create Menu',
          meta: { permission: { path: '/security/permissions/menu', action: 'view' } },
          component: CreateMenu
        },
        {
          path: 'security/permissions/group',
          name: 'Create Group',
          meta: { permission: { path: '/security/permissions/group', action: 'view' } },
          component: CreateGroup
        },
        {
          path: 'security/permissions/matrix',
          name: 'Permission Matrix',
          meta: { permission: { path: '/security/permissions/matrix', action: 'view' } },
          component: PermissionMatrix
        },
        {
          path: 'security/audit',
          name: 'Audit Explorer',
          meta: { permission: { path: '/security/audit', action: 'view' } },
          component: AuditExplorer
        },
        {
          path: 'config/message-authen',
          name: 'Message Authen',
          meta: { permission: { path: '/config/message-authen', action: 'view' } },
          component: SettingMessageAuthen
        },
        {
          path: 'config/email-notifications',
          name: 'Email Notifications',
          meta: { permission: { path: '/config/email-notifications', action: 'view' } },
          component: EmailNotifications
        },
        {
          path: 'config/workflow-actions',
          name: 'Workflow Actions',
          meta: { permission: { path: '/config/workflow-actions', action: 'view' } },
          component: WorkflowActions
        },
        {
          path: 'config/runtime-access',
          name: 'Runtime Access',
          component: RuntimeAccess,
          meta: { permission: { path: '/config/runtime-access', action: 'view' } }
        },
        {
          path: 'config/database-backup',
          name: 'Database Backup',
          component: DatabaseBackup,
          meta: { permission: { path: '/config/database-backup', action: 'view' } }
        },
        {
          path: 'config/setting-message',
          name: 'Setting Message',
          meta: { permission: { path: '/config/setting-message', action: 'view' } },
          component: SettingMessage
        },
        {
          path: 'config/verification',
          name: 'Setting Verification',
          meta: { permission: { path: '/config/verification', action: 'view' } },
          component: SettingVerification
        },
        {
          path: 'setting/group',
          name: 'Setting Group',
          meta: { permission: { path: '/setting/group', action: 'view' } },
          component: SettingGroup
        },
        {
          path: 'setting/message-status',
          name: 'Message Status',
          meta: { permission: { path: '/setting/message-status', action: 'view' } },
          component: SettingMessageStatus
        }
      ]
    },
    {
      path: '/pages',
      redirect: '/pages/404',
      name: 'Pages',
      component: {
        render (c) { return c('router-view') }
      },
      children: [
        {
          path: '404',
          name: 'Page404',
          component: Page404
        },
        {
          path: '500',
          name: 'Page500',
          component: Page500
        },
        {
          path: 'login',
          name: 'Login',
          component: Login
        }
      ]
    },
    {
      path: '*',
      redirect: '/pages/404'
    }
  ]
})

function normalizePermissionPath(path) {
  if (!path) return ''
  let normalized = String(path).trim()
  const queryIndex = normalized.indexOf('?')
  if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex)
  const hashIndex = normalized.indexOf('#')
  if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex)
  normalized = normalized.replace(/\/{2,}/g, '/')
  if (!normalized.startsWith('/')) normalized = `/${normalized}`
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1)
  }
  return normalized
}

function swapPermissionPlurality(path) {
  const normalized = normalizePermissionPath(path)
  if (!normalized) return ''
  if (normalized.includes('/permissions')) {
    return normalized.replace('/permissions', '/permission')
  }
  if (normalized.includes('/permission')) {
    return normalized.replace('/permission', '/permissions')
  }
  return ''
}

function buildPermissionCandidates(to, permissionMeta) {
  const candidates = new Set()
  const rawMetaPath = permissionMeta && permissionMeta.path ? permissionMeta.path : ''
  const rawRoutePath = to && to.path ? to.path : ''

  const normalizedMetaPath = normalizePermissionPath(rawMetaPath)
  const normalizedRoutePath = normalizePermissionPath(rawRoutePath)

  ;[
    normalizedMetaPath,
    normalizedRoutePath,
    swapPermissionPlurality(normalizedMetaPath),
    swapPermissionPlurality(normalizedRoutePath)
  ].filter(Boolean).forEach(item => candidates.add(item))

  return Array.from(candidates)
}

router.beforeEach(async (to, from, next) => {
  try {
    await store.dispatch('auth/bootstrapSession')
  } catch (err) {
    // ignore bootstrap error
  }

  const isPublicPage = to.path.startsWith('/pages')
  const hasToken = !!store.state.XAccessToken
  const authState = store.getters['auth/authenticated'] || {}
  const isAuthenticated = !!authState.isAuthen

  if (!isPublicPage && (!hasToken || !isAuthenticated)) {
    return next({ path: '/pages/login' })
  }

  if (to.path === '/pages/login' && hasToken && isAuthenticated) {
    return next({ path: '/dashboard' })
  }

  const permissionMeta = to.meta && to.meta.permission
  if (permissionMeta && hasToken && isAuthenticated) {
    if (!store.getters['security/loaded']) {
      try {
        await store.dispatch('security/fetchMyPermissions')
      } catch (err) {
        // permission fetch failed, fallback to denied
      }
    }
    const action = permissionMeta.action || 'view'
    const pathCandidates = buildPermissionCandidates(to, permissionMeta)
    const canAccess = pathCandidates.some(path => (
      store.getters['security/canAccess'](path, action)
    ))
    if (!canAccess) {
      return next({ path: '/pages/404' })
    }
  }

  return next()
})

export default router
