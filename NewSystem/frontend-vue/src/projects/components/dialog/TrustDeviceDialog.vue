<template>
  <CModal :show="show" centered add-content-classes="trust-device-modal">
    <template #header-wrapper>
      <div class="trust-header">
        <div class="trust-icon">🔐</div>
        <h4 class="trust-title">{{ $t('auth.trustDevice.title') }}</h4>
        <p class="trust-subtitle">{{ $t('auth.trustDevice.subtitle') }}</p>
      </div>
    </template>
    <template #body-wrapper>
      <div class="trust-body">
        <div class="trust-card">
          <p class="trust-line"><strong>{{ $t('auth.trustDevice.ifTrusted') }}:</strong> {{ $t('auth.trustDevice.ifTrustedText') }}</p>
          <p class="trust-line"><strong>{{ $t('auth.trustDevice.condition') }}:</strong> {{ $t('auth.trustDevice.conditionText') }}</p>
          <p class="trust-line text-muted mb-0"><strong>{{ $t('auth.trustDevice.tip') }}:</strong> {{ $t('auth.trustDevice.tipText') }}</p>
        </div>
      </div>
    </template>
    <template #footer-wrapper>
      <div class="trust-actions">
        <CButton
          color="secondary"
          variant="outline"
          class="trust-btn trust-btn-secondary"
          :disabled="submitting"
          @click="onChoose(false)"
        >
          {{ $t('common.actions.notNow') }}
        </CButton>
        <CButton
          color="primary"
          class="trust-btn trust-btn-primary"
          :disabled="submitting"
          @click="onChoose(true)"
        >
          {{ $t('auth.trustDevice.confirm') }}
        </CButton>
      </div>
    </template>
  </CModal>
</template>

<script>
export default {
  name: 'TrustDeviceDialog',
  props: {
    show: {
      type: Boolean,
      default: false
    }
  },
  data() {
    return {
      submitting: false
    }
  },
  watch: {
    show(value) {
      if (!value) {
        this.submitting = false
      }
    }
  },
  methods: {
    async onChoose(trustDevice) {
      if (this.submitting) {
        return
      }
      this.submitting = true
      try {
        await this.$store.dispatch('auth/completeSignInFlow', { trustDevice: !!trustDevice })
      } finally {
        this.submitting = false
        this.$emit('close')
      }
    }
  }
}
</script>

<style scoped>
.trust-header {
  text-align: center;
  padding: 20px 24px 8px;
}

.trust-icon {
  width: 52px;
  height: 52px;
  border-radius: 50%;
  margin: 0 auto 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  background: linear-gradient(135deg, #e9f4ff 0%, #f5fbff 100%);
}

.trust-title {
  font-weight: 700;
  margin: 0;
}

.trust-subtitle {
  margin: 8px 0 0;
  color: #6c757d;
  font-size: 0.95rem;
}

.trust-body {
  padding: 0 24px 12px;
}

.trust-card {
  border: 1px solid #e7edf3;
  border-radius: 12px;
  padding: 14px 14px 10px;
  background: #fafcfe;
}

.trust-line {
  margin-bottom: 8px;
  font-size: 0.94rem;
  line-height: 1.4;
}

.trust-actions {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 10px;
  padding: 0 24px 20px;
}

.trust-btn {
  min-width: 140px;
}

@media (max-width: 576px) {
  .trust-actions {
    flex-direction: column-reverse;
  }

  .trust-btn {
    width: 100%;
  }
}
</style>
