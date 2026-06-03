<template>
  <CHeader with-subheader>
    <CToggler
      in-header
      class="ml-3 d-lg-none"
      @click="$store.commit('toggleSidebarMobile')"
    />
    <CToggler
      in-header
      class="ml-3 d-md-down-none"
      @click="$store.commit('toggleSidebarDesktop')"
    />
    <CHeaderBrand class="mx-auto d-lg-none" to="/">
<!--      <img src="@/assets/logo.svg" height="48"/>-->
    </CHeaderBrand>
    <CHeaderNav class="d-md-down-none mr-auto">
<!--      <CHeaderNavItem class="px-3">-->
<!--        <CHeaderNavLink to="/dashboard">-->
<!--          Dashboard-->
<!--        </CHeaderNavLink>-->
<!--      </CHeaderNavItem>-->
<!--      <CHeaderNavItem class="px-3">-->
<!--        <CHeaderNavLink to="/users" exact>-->
<!--          Users-->
<!--        </CHeaderNavLink>-->
<!--      </CHeaderNavItem>-->
<!--      <CHeaderNavItem class="px-3">-->
<!--        <CHeaderNavLink>-->
<!--          settings-->
<!--        </CHeaderNavLink>-->
<!--      </CHeaderNavItem>-->
    </CHeaderNav>
    <CHeaderNav>
<!--      <CHeaderNavItem class="px-3">-->
<!--        <button-->
<!--          @click="() => $store.commit('toggle', 'darkMode')"-->
<!--          class="c-header-nav-btn"-->
<!--        >-->
<!--          <CIcon v-if="$store.state.darkMode" name="cil-sun"/>-->
<!--          <CIcon v-else name="cil-moon"/>-->
<!--        </button>-->
<!--      </CHeaderNavItem>-->
      <TheHeaderDropdownNotif/>
<!--      <TheHeaderDropdownTasks/>-->
<!--      <TheHeaderDropdownMssgs/>-->
<!--      <TheHeaderDropdownAccnt/>-->
<!--      <CHeaderNavItem class="px-3">-->
<!--        <button-->
<!--          in-header-->
<!--          class="c-header-nav-btn"-->
<!--          @click="$store.commit('toggle', 'asideShow')"-->
<!--        >-->
<!--          <CIcon size="lg" name="cil-applications-settings" class="mr-2"/>-->
<!--        </button>-->
<!--      </CHeaderNavItem>-->
      <CHeaderNavItem >
        <CButton size="sm" color="info" shape="pill" variant="outline" style="width: 35px; height:35px;" @click="onSwitchLang" >
          {{lang.toUpperCase()}}
        </CButton>
      </CHeaderNavItem>

      <TheHeaderDropdownAccnt class="pr-3"/>
    </CHeaderNav>

<!--    <CSubheader class="px-3">-->
<!--      <CBreadcrumbRouter class="border-0 mb-0"/>-->
<!--    </CSubheader>-->
  </CHeader>
</template>

<script>
import TheHeaderDropdownAccnt from './TheHeaderDropdownAccnt'
import TheHeaderDropdownNotif from './TheHeaderDropdownNotif'
import {mapGetters} from "vuex";

export default {
  name: 'TheHeader',
  components: {
    TheHeaderDropdownAccnt,
    TheHeaderDropdownNotif
  },

  methods: {
    onSwitchLang(){
      switch (this.lang) {
        case "th":
          this.$store.commit("setting/lang", "en")
          break;
        case "en":
          this.$store.commit("setting/lang", "th")
          break;
      }
    }
  },

  computed: {
    ...mapGetters({
      lang: "setting/lang",
    })
  },
}
</script>
