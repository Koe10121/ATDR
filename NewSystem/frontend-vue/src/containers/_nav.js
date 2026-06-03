export default function buildNav (t) {
  return [
    {
      _name: 'CSidebarNav',
      _children: [
        {
          _name: 'CSidebarNavItem',
          name: t('nav.dashboard'),
          to: '/dashboard',
          icon: 'cil-speedometer',
          permission: { path: '/dashboard', action: 'view' }
        },
        {
          _name: 'CSidebarNavItem',
          name: t('nav.newSystemRegistry'),
          to: '/newsystem/registry',
          icon: 'cil-description',
          permission: { path: '/newsystem/registry', action: 'view' }
        },
        {
          _name: 'CSidebarNavItem',
          name: t('nav.businessOperations'),
          to: '/operations/business',
          icon: 'cil-layers',
          permission: { path: '/operations/business', action: 'view' }
        },
        {
          _name: 'CSidebarNavTitle',
          _children: [t('nav.accessControl')]
        },
        {
          _name: 'CSidebarNavDropdown',
          name: t('nav.config'),
          route: '/config',
          icon: 'cil-settings',
          items: [
            {
              name: t('nav.messageAuthen'),
              to: '/config/message-authen',
              permission: { path: '/config/message-authen', action: 'view' }
            },
            {
              name: t('nav.emailNotifications'),
              to: '/config/email-notifications',
              permission: { path: '/config/email-notifications', action: 'view' }
            },
            {
              name: t('nav.workflowActions'),
              to: '/config/workflow-actions',
              permission: { path: '/config/workflow-actions', action: 'view' }
            },
            {
              name: t('nav.runtimeAccess'),
              to: '/config/runtime-access',
              permission: { path: '/config/runtime-access', action: 'view' }
            },
            {
              name: t('nav.databaseBackup'),
              to: '/config/database-backup',
              permission: { path: '/config/database-backup', action: 'view' }
            },
            {
              name: t('nav.settingMessage'),
              to: '/config/setting-message',
              permission: { path: '/config/setting-message', action: 'view' }
            },
            {
              name: t('nav.settingVerification'),
              to: '/config/verification',
              permission: { path: '/config/verification', action: 'view' }
            }
          ]
        },
        {
          _name: 'CSidebarNavDropdown',
          name: t('nav.setting'),
          route: '/setting',
          icon: 'cil-list',
          items: [
            {
              name: t('nav.settingGroup'),
              to: '/setting/group',
              permission: { path: '/setting/group', action: 'view' }
            },
            {
              name: t('nav.messageStatus'),
              to: '/setting/message-status',
              permission: { path: '/setting/message-status', action: 'view' }
            }
          ]
        },
        {
          _name: 'CSidebarNavDropdown',
          name: t('nav.permission'),
          route: '/security/permissions/menu',
          icon: 'cil-lock-locked',
          items: [
            {
              name: t('security.createMenu.title'),
              to: '/security/permissions/menu',
              permission: { path: '/security/permissions/menu', action: 'view' }
            },
            {
              name: t('security.createGroup.title'),
              to: '/security/permissions/group',
              permission: { path: '/security/permissions/group', action: 'view' }
            },
            {
              name: t('security.permissionMatrix.title'),
              to: '/security/permissions/matrix',
              permission: { path: '/security/permissions/matrix', action: 'view' }
            },
            {
              name: t('security.auditExplorer.title'),
              to: '/security/audit',
              permission: { path: '/security/audit', action: 'view' }
            }
          ]
        },
        {
          _name: 'CSidebarNavItem',
          name: t('nav.accountDirectory'),
          to: '/accounts/directory',
          icon: 'cil-user',
          permission: { path: '/accounts/directory', action: 'view' }
        }
      ]
    }
  ]
}
