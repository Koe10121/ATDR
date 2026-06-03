export default {
  computed: {
    permissionMatrix () {
      return this.$store.getters['security/matrix'] || {}
    },
    permissionLoaded () {
      return !!this.$store.getters['security/loaded']
    },
    defaultPermissionPath () {
      const metaPath = this.$route && this.$route.meta && this.$route.meta.permission
        ? this.$route.meta.permission.path
        : ''
      return this.normalizePermissionPath(metaPath || (this.$route && this.$route.path) || '')
    }
  },
  methods: {
    normalizePermissionPath (path) {
      if (!path) return ''
      let normalized = String(path).trim()
      const queryIndex = normalized.indexOf('?')
      if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex)
      const hashIndex = normalized.indexOf('#')
      if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex)
      normalized = normalized.replace(/\/{2,}/g, '/')
      if (!normalized.startsWith('/')) normalized = `/${normalized}`
      if (normalized.length > 1 && normalized.endsWith('/')) normalized = normalized.slice(0, -1)
      return normalized
    },
    swapPermissionPlurality (path) {
      const normalized = this.normalizePermissionPath(path)
      if (!normalized) return ''
      if (normalized.includes('/permissions')) return normalized.replace('/permissions', '/permission')
      if (normalized.includes('/permission')) return normalized.replace('/permission', '/permissions')
      return ''
    },
    resolvePermissionRule (path) {
      const normalizedPath = this.normalizePermissionPath(path || this.defaultPermissionPath)
      if (!normalizedPath) return null
      return this.permissionMatrix[normalizedPath] || this.permissionMatrix[this.swapPermissionPlurality(normalizedPath)] || null
    },
    canAccessAction (action = 'view', path = '') {
      const normalizedPath = this.normalizePermissionPath(path || this.defaultPermissionPath)
      if (!normalizedPath) return true
      if (!this.permissionLoaded) return false
      const rule = this.resolvePermissionRule(normalizedPath)
      if (!rule) return false
      return !!(rule.all || rule[action])
    },
    canViewPath (path = '') {
      return this.canAccessAction('view', path)
    },
    canAddPath (path = '') {
      return this.canAccessAction('add', path)
    },
    canEditPath (path = '') {
      return this.canAccessAction('edit', path)
    },
    canDeletePath (path = '') {
      return this.canAccessAction('delete', path)
    },
    canActionPath (path = '') {
      return this.canAccessAction('action', path)
    },
    canOwnerPath (path = '') {
      return this.canAccessAction('owner', path)
    },
    canLogsPath (path = '') {
      return this.canAccessAction('logs', path)
    }
  }
}
