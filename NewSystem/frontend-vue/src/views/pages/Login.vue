<template>
  <div class="c-app flex-row align-items-center">
    <CContainer>
      <CRow class="justify-content-center">
        <CCol md="6">
          <CCard class="p-4">
            <CCardBody class="text-center">
              <img src="@/assets/logo.svg" height="130px"/>
              <h3 class="mt-3">Sign in</h3>
              <p class="text-muted mb-4">Sign in with MFU Google account</p>
              <img
                class="google-btn"
                @click="onAuthenGoogle"
                src="@/assets/icons/logo-google.png"
                width="52px"
                alt="Google Sign-In"
              />
            </CCardBody>
          </CCard>
        </CCol>
      </CRow>
    </CContainer>
    <TwoFA/>
    <CenterLoading/>
    <DialogMessage/>
  </div>
</template>

<script>
import TwoFA from '@/projects/components/dialog/TwoFA.vue'
import CenterLoading from '@/projects/components/dialog/CenterLoading.vue'
import DialogMessage from '@/projects/components/dialog/DialogMessage.vue'

export default {
  name: 'Login',
  components: {
    TwoFA,
    CenterLoading,
    DialogMessage
  },
  methods: {
    async onAuthenGoogle() {
      try {
        const googleUser = await this.$gAuth.signIn();
        const id_token = googleUser.getAuthResponse().id_token;
        const body = {
          token: id_token,
          authType: "689c06d5255db4e56aea8902"
        };
        await this.$store.dispatch("auth/signIn", body)
      } catch (err) {
        this.$store.commit("dialog/dialog", {
          title: "Authentication Error",
          message: "Google Sign-In failed. Please try again.",
          code: "AUTH_GOOGLE_FAILED",
          number: "1",
          status: true
        })
      }
    }
  }
}
</script>

<style scoped>
.google-btn {
  cursor: pointer;
  transition: transform 0.15s ease;
}
.google-btn:hover {
  transform: scale(1.08);
}
</style>
