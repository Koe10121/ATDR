<template>
  <CSidebar
      class="bg-style1"
      :minimize="minimize"
      unfoldable
      :show="show"
      @update:show="(value) => $store.commit('set', ['sidebarShow', value])"
  >
    <CSidebarBrand class="d-md-down-none" >
<!--      <CIcon-->
<!--          class="c-sidebar-brand-full"-->
<!--          name="logo"-->
<!--          size="custom-size"-->
<!--          :height="35"-->
<!--          viewBox="0 0 556 134"-->
<!--      />-->
      <div class="c-sidebar-brand-full" >
        <a href="/">
          <CRow >
            <img class="pt-2 pb-2" src="@/assets/logo.svg" height="60px">
            <CCol class="text-white">
              <p class="font-weight-bold mb-0 mt-2 h5">MFU</p>
              <p class="font-weight-bold">{{ $t('common.app.dashboardSystem') }}</p>
            </CCol>
          </CRow>
        </a>

      </div>


      <!--      <img src="@/assets/logo.svg" height="48"/>-->
      <CIcon
          class="c-sidebar-brand-minimized"
          name="logo"
          size="custom-size"
          :height="35"
          viewBox="0 0 110 134"
      />
    </CSidebarBrand>
    <CRenderFunction flat :contentToRender="navs"/>
    <CSidebarMinimizer
        class="c-d-md-down-none"
        @click.native="$store.commit('toggle', 'sidebarMinimize')"
    />
  </CSidebar>
</template>

<script>
import buildNav from './_nav'

export default {
  name: 'TheSidebar',
  computed: {
    permissionLoaded() {
      return this.$store.getters['security/loaded']
    },
    navs() {
      this.$i18n.locale
      const navConfig = buildNav(this.$t.bind(this))
      return this.filterNavTree(navConfig)
    },
    show() {
      return this.$store.state.sidebarShow
    },
    minimize() {
      return this.$store.state.sidebarMinimize
    }
  },
  watch: {
    '$store.state.XAccessToken': {
      async handler(value) {
        if (!value) return
        if (this.permissionLoaded) return
        try {
          await this.$store.dispatch('security/fetchMyPermissions')
        } catch (error) {
          // Keep sidebar visible if permission bootstrap fails.
        }
      },
      immediate: true
    }
  },
  methods: {
    normalizePermissionPath(path) {
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
    },
    swapPermissionPlurality(path) {
      const normalized = this.normalizePermissionPath(path)
      if (!normalized) return ''
      if (normalized.includes('/permissions')) return normalized.replace('/permissions', '/permission')
      if (normalized.includes('/permission')) return normalized.replace('/permission', '/permissions')
      return ''
    },
    hasViewPermission(item) {
      if (!item) return true
      const requiresExplicitPermission = !!(item.permission && item.permission.path)
      if (!this.permissionLoaded) {
        return requiresExplicitPermission ? !this.$store.state.XAccessToken : true
      }
      const matrix = this.$store.getters['security/matrix'] || {}
      const permissionPath = item.permission && item.permission.path
        ? item.permission.path
        : (item.to || item.route || '')
      const normalizedRoute = this.normalizePermissionPath(permissionPath)
      const rule = matrix[normalizedRoute] || matrix[this.swapPermissionPlurality(normalizedRoute)]

      if (!rule) return !requiresExplicitPermission
      const action = item.permission && item.permission.action ? item.permission.action : 'view'
      return !!(rule.all || rule[action] || rule.view)
    },
    filterNavTree(items) {
      if (!Array.isArray(items)) return []

      const filtered = items.reduce((result, item) => {
        if (!item || typeof item !== 'object') return result

        if (item._name === 'CSidebarNavTitle') {
          result.push({ ...item })
          return result
        }

        const nextItem = { ...item }
        const children = Array.isArray(item._children) ? this.filterNavTree(item._children) : null
        const dropdownItems = Array.isArray(item.items) ? this.filterNavTree(item.items) : null

        if (children) nextItem._children = children
        if (dropdownItems) nextItem.items = dropdownItems

        const hasVisibleChildren = !!((children && children.length) || (dropdownItems && dropdownItems.length))

        if (hasVisibleChildren || this.hasViewPermission(item)) {
          result.push(nextItem)
        }

        return result
      }, [])

      return filtered.filter((item, index) => {
        if (item._name !== 'CSidebarNavTitle') return true
        const nextItem = filtered[index + 1]
        return !!nextItem && nextItem._name !== 'CSidebarNavTitle'
      })
    }
  }
}
</script>

<style>
.bg-style1{
  background: linear-gradient(30deg,#FEC260 0%,#8c1515 60%);
}
</style>
