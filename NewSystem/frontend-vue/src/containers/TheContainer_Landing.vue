<template>
  <div class="c-app" :class="{ 'c-dark-theme': $store.state.darkMode }">
    <TheSidebar/>
    <TheAside/>
    <CWrapper>
<!--      <TheHeader_Landing/>-->
      <div class="c-body">
        <main class="c-main">
          <CContainer fluid  >
            <transition name="fade">
              <router-view></router-view>
            </transition>
          </CContainer>
        </main>
<!--        <TheFooter/>-->
      </div>
    </CWrapper>
    <CenterLoading/>
    <DialogMessage/>
  </div>
</template>

<script>
import TheSidebar from './TheSidebar'
import TheAside from './TheAside'
import CenterLoading from "@/projects/components/dialog/CenterLoading.vue";
import DialogMessage from "@/projects/components/dialog/DialogMessage.vue";

export default {
  name: 'TheContainer_Landing',
  components: {
    DialogMessage,
    CenterLoading,
    TheSidebar,
    TheAside
  }
}
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}
.fade-enter,
.fade-leave-to {
  opacity: 0;
}
</style>
