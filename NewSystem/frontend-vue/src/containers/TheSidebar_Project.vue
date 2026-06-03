<template>
  <CSidebar
      class="bg-style1"
      :minimize="minimize"
      unfoldable
      :show="show"
      @update:show="(value) => $store.commit('set', ['sidebarShow', value])"
  >
    <CSidebarBrand class="d-md-down-none">
      <!--      <CIcon-->
      <!--          class="c-sidebar-brand-full"-->
      <!--          name="logo"-->
      <!--          size="custom-size"-->
      <!--          :height="35"-->
      <!--          viewBox="0 0 556 134"-->
      <!--      />-->
      <div class="c-sidebar-brand-full">
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
    <CRenderFunction flat :contentToRender="nav"/>
    <!--    <CSidebarMinimizer-->
    <!--        class="c-d-md-down-none"-->
    <!--        @click.native="$store.commit('toggle', 'sidebarMinimize')"-->
    <!--    />-->
  </CSidebar>
</template>

<script>
export default {
  name: 'TheSidebar_Project',
  components: {},

  computed: {
    nav() {
      this.$i18n.locale
      return [{
        _name: 'CSidebarNav',
        _children: [
          {
            _name: 'CSidebarNavTitle',
            _children: [this.$t('nav.projectShortcuts')]
          },
          {
            _name: 'CSidebarNavDropdown',
            name: this.$t('nav.projectSettings'),
            route: '/project/settings',
            icon: 'cil-settings',
            items: [
              {
                name: this.$t('nav.general'),
                to: `/project/${this.$route.params.application}/settings/general`
              },
              {
                name: this.$t('nav.permission'),
                to: `/project/${this.$route.params.application}/settings/permission`
              }
            ]
          }
        ]
      }]
    },
    show() {
      return this.$store.state.sidebarShow
    },
    minimize() {
      return this.$store.state.sidebarMinimize
    }
  },
  data: function () {
    return {}
  }
}
</script>

<style>
.bg-style1 {
  background: linear-gradient(30deg, #FEC260 0%, #8c1515 60%);
}
</style>
