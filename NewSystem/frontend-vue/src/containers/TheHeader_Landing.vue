<template>
  <CHeader with-subheader>

    <CHeaderBrand class="mx-auto d-lg-none" to="/">
      <img src="@/assets/logo.svg" height="48"/>
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
<!--      <TheHeaderDropdownNotif/>-->
<!--      <TheHeaderDropdownTasks/>-->
<!--      <TheHeaderDropdownMssgs/>-->
<!--      <TheHeaderDropdownAccnt class="px-3"/>-->
<!--      <CHeaderNavItem class="px-3">-->
<!--        <button-->
<!--          in-header-->
<!--          class="c-header-nav-btn"-->
<!--          @click="$store.commit('toggle', 'asideShow')"-->
<!--        >-->
<!--          <CIcon size="lg" name="cil-applications-settings" class="mr-2"/>-->
<!--        </button>-->
<!--      </CHeaderNavItem>-->
    </CHeaderNav>

  </CHeader>
</template>

<script>
export default {
  name: 'TheHeader_Landing'
}
</script>
