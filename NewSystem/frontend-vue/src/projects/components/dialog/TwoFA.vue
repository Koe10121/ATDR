<template>
  <div>
    <CModal
        add-content-classes="bg-login"
        :show="is2FA"
        centered
    >
      <template #header-wrapper>
        <div class="mb-4"></div>
      </template>

      <template #body-wrapper>
        <CRow class="justify-content-center text-white">
          <CCol col="8">
            <CForm @submit.prevent="onSubmitCode">
              <div class="text-center mb-3">
                <img src="@/assets/logo.svg" height="100px" />
              </div>

              <div class="text-center">
                <p class="h4 font-weight-bold mb-2">{{ $t('auth.twoFa.title') }}</p>
                <p>{{ $t('auth.twoFa.subtitle') }}</p>
                <p>{{ $t('auth.twoFa.instruction') }}</p>
                <p v-if="userEmail"><strong>{{ $t('auth.twoFa.email') }}:</strong> {{ userEmail }}</p>
              </div>

              <!-- OTP Input -->
              <div class="otp-wrapper mt-4">
                <div
                    v-for="(digit, index) in otpInputs"
                    :key="index"
                    class="otp-input"
                >
                  <input
                      v-model="otpInputs[index]"
                      type="text"
                      maxlength="1"
                      @input="onInput(index)"
                      @keydown.backspace="onBackspace(index)"
                      ref="otpRefs"
                  />
                </div>
              </div>

              <CRow class="mt-4 text-center">
                <CCol>
                  <p class="p-0 m-0">{{ $t('auth.twoFa.receiveHint') }}</p>
                  <p class="p-0 m-0">{{ $t('auth.twoFa.resendPrompt') }} <span class="text-info"  style="cursor: pointer" @click="onRequestTwoFa()">{{ $t('auth.twoFa.resendAction') }}</span></p>
                </CCol>
<!--                <CCol col="5" class="text-right">-->
<!--                  <CButton class=""   shape="pill" variant="outline"  color="danger">-->
<!--                    <span class="font-weight-bold mr-1 pl-1 pr-1">-->
<!--                      <CIcon name="cil-save" size="lg"/> SUBMIT-->
<!--                    </span>-->
<!--                  </CButton>-->
<!--                </CCol>-->
              </CRow>
            </CForm>
          </CCol>
        </CRow>
      </template>

      <template #footer-wrapper>
        <div class="mb-4"></div>
      </template>
    </CModal>
    <TrustDeviceDialog :show="showTrustDeviceDialog" @close="onCloseTrustDialog"/>
  </div>
</template>

<script>
import {mapGetters} from "vuex";
import TrustDeviceDialog from '@/projects/components/dialog/TrustDeviceDialog.vue'

export default {
  name: 'TwoFA',
  components: {
    TrustDeviceDialog
  },
  data() {
    return {
      otpLength: 6,
      otpInputs: [],
      lastSubmittedCode: '',
      submittingCode: false,
      showTrustDeviceDialog: false
    }
  },
  mounted() {
    this.otpInputs = Array(this.otpLength).fill('')
  },
  methods: {
    async onRequestTwoFa(){
      try {
        await this.$store.dispatch("auth/twofa",{})
      } catch (err) {
        this.$store.commit('dialog/showError', {
          title: this.$t('auth.errors.title'),
          message: this.$t('auth.twoFa.errors.resend'),
          code: "AUTH_2FA_REQUEST_FAILED",
          number: "1",
          status: true
        })
      }
    },
    onInput(index) {
      const input = this.otpInputs[index]
      // ✅ รับเฉพาะ a-z, A-Z, 0-9
      if (!/^[a-zA-Z0-9]$/.test(input)) {
        this.$set(this.otpInputs, index, '')
        return
      }
      // 🔁 move focus ถัดไป
      if (index < this.otpLength - 1) {
        this.$refs.otpRefs[index + 1].focus()
      }
    },
    onBackspace(index) {
      if (this.otpInputs[index] === '' && index > 0) {
        this.$refs.otpRefs[index - 1].focus()
      }
    },
    onSubmitCode() {
      const code = this.otpInputs.join('')
      if (code.length === this.otpLength) {
        this.dispatchOtpCode(code)
      }
    },
    async dispatchOtpCode(code) {
      if (this.submittingCode || code.length !== this.otpLength || code === this.lastSubmittedCode) {
        return
      }
      this.submittingCode = true
      try {
        await this.$store.dispatch("auth/twofaSend", { code })
        this.lastSubmittedCode = code
        this.showTrustDeviceDialog = true
      } catch (err) {
        this.$store.commit('dialog/showError', {
          title: this.$t('auth.errors.title'),
          message: this.$t('auth.twoFa.errors.verify'),
          code: "AUTH_2FA_VERIFY_FAILED",
          number: "1",
          status: true
        })
      } finally {
        this.submittingCode = false
      }
    },
    resetOtpInputs() {
      this.otpInputs = Array(this.otpLength).fill('')
      this.lastSubmittedCode = ''
      this.submittingCode = false
      this.showTrustDeviceDialog = false
    },
    onCloseTrustDialog() {
      this.showTrustDeviceDialog = false
    }
  },

  computed: {
    ...mapGetters({
      is2FA: 'auth/is2FA',
      profile : "auth/profile"
    }),

    userEmail() {
      try {
        if (this.profile && this.profile.email) {
          return String(this.profile.email)
        }
        if (this.profile && Array.isArray(this.profile.authen)) {
          const authenEmail = this.profile.authen.find(item => item && item.email)
          if (authenEmail && authenEmail.email) {
            return String(authenEmail.email)
          }
        }
        return ''
      } catch (err) {
        return ''
      }
    }
  },

  watch: {
    otpInputs(value) {
      const isCompleted = value.every(v => v !== "" && v != null)
      if (!isCompleted) {
        return
      }
      this.dispatchOtpCode(value.join(""))
    },
    is2FA(value) {
      if (value) {
        this.resetOtpInputs()
      }
    }
  }
}
</script>

<style scoped>
.otp-wrapper {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 12px;
}

.otp-input input {
  width: 50px;
  height: 50px;
  text-align: center;
  font-size: 1.2rem;
  font-weight: bold;
  border: 2px solid #ccc;
  border-radius: 8px;
  transition: all 0.2s ease;
  /* text-transform: uppercase; */
}

.otp-input input:focus {
  border-color: #007bff;
  box-shadow: 0 0 5px rgba(0, 123, 255, 0.4);
  outline: none;
}
</style>
