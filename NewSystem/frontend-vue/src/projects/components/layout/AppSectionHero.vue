<template>
  <div>
    <CCard class="app-section-hero mb-4 bg-style2">
      <CCardBody class="app-section-hero__body">
        <div class="app-section-hero__copy">
          <h3 class="mb-2">{{ title }}</h3>
          <div v-if="subtitle" class="app-section-hero__text">{{ subtitle }}</div>
        </div>

        <div v-if="showMeta || showRefresh" class="app-section-hero__actions">
          <div v-if="showMeta" class="app-section-hero__meta">
            <div class="app-section-hero__meta-label">{{ metaLabel }}</div>
            <div class="app-section-hero__meta-value">{{ metaValue }}</div>
          </div>

          <CButton v-if="showRefresh" color="light" class="app-section-hero__refresh" @click="$emit('refresh')">
            <CIcon name="cil-reload" class="mr-2" />
            {{ refreshLabel }}
          </CButton>
        </div>
      </CCardBody>
    </CCard>

    <CRow v-if="statItems.length" class="mb-4">
      <CCol v-for="stat in statItems" :key="stat.label" md="4" sm="6" col="12">
        <CCard class="app-section-stat bg-style2">
          <CCardBody>
            <div class="app-section-stat__header">
              <div>
                <div class="app-section-stat__label">{{ stat.label }}</div>
                <div class="app-section-stat__value">{{ stat.value }}</div>
                <div v-if="stat.hint" class="app-section-stat__hint">{{ stat.hint }}</div>
              </div>
              <div class="app-section-stat__icon" :class="stat.iconClass">
                <CIcon :name="stat.icon" />
              </div>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  </div>
</template>

<script>
export default {
  name: 'AppSectionHero',
  emits: ['refresh'],
  props: {
    title: { type: String, required: true },
    subtitle: { type: String, default: '' },
    stats: { type: Array, default: () => [] },
    showRefresh: { type: Boolean, default: true },
    refreshLabel: { type: String, default: 'Refresh' },
    metaLabel: { type: String, default: '' },
    metaValue: { type: String, default: '' }
  },
  computed: {
    statItems () {
      return Array.isArray(this.stats) ? this.stats : []
    },
    showMeta () {
      return !!(this.metaLabel || this.metaValue)
    }
  }
}
</script>

<style scoped lang="scss">
.app-section-hero {
  overflow: hidden;
  border: 0;
  border-radius: 1.5rem;
  box-shadow: 0 20px 40px rgba(44, 52, 71, 0.1);
  background:
    radial-gradient(circle at top right, rgba(254, 194, 96, 0.28), transparent 28%),
    radial-gradient(circle at left center, rgba(255, 255, 255, 0.12), transparent 26%),
    linear-gradient(135deg, #5d0f12 0%, #8c1515 46%, #c77f28 100%);
}

.app-section-hero__body {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1.5rem;
  padding: 1.55rem 1.7rem;
}

.app-section-hero__copy {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.app-section-hero h3 {
  color: #fff8f1;
  font-size: 1.5rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.app-section-hero__text {
  max-width: 48rem;
  color: rgba(255, 246, 237, 0.86);
  font-size: 0.84rem;
  line-height: 1.55;
}

.app-section-hero__actions {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.app-section-hero__meta {
  text-align: right;
}

.app-section-hero__meta-label {
  font-size: 0.64rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: rgba(255, 248, 240, 0.62);
  font-weight: 700;
  margin-bottom: 0.2rem;
}

.app-section-hero__meta-value {
  color: #fff8f1;
  font-size: 0.8rem;
  font-weight: 600;
}

.app-section-hero__refresh {
  border-radius: 999px;
  min-width: 108px;
  border: 0;
  background: linear-gradient(135deg, rgba(255, 248, 240, 0.2), rgba(255, 248, 240, 0.12));
  color: #fff9f4;
  backdrop-filter: blur(12px);
  box-shadow: inset 0 0 0 1px rgba(255, 248, 240, 0.24);
  font-size: 0.78rem;
}

.app-section-hero__refresh:hover,
.app-section-hero__refresh:focus {
  background: linear-gradient(135deg, rgba(255, 248, 240, 0.3), rgba(255, 248, 240, 0.18));
  color: #fff;
  box-shadow: inset 0 0 0 1px rgba(255, 248, 240, 0.32), 0 0 0 0.2rem rgba(255, 250, 245, 0.12);
}

.app-section-stat {
  overflow: hidden;
  border: 1px solid rgba(223, 230, 238, 0.78);
  border-radius: 1.35rem;
  box-shadow: 0 14px 30px rgba(44, 52, 71, 0.06);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(247, 249, 252, 0.98));
}

.app-section-stat__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.15rem 0;
}

.app-section-stat__label {
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #7d8696;
  font-weight: 700;
  margin-bottom: 0.55rem;
}

.app-section-stat__value {
  font-size: 1.72rem;
  line-height: 1;
  font-weight: 700;
  letter-spacing: -0.03em;
  color: #233247;
}

.app-section-stat__hint {
  margin-top: 0.45rem;
  color: #74839a;
  font-size: 0.72rem;
  line-height: 1.4;
}

.app-section-stat__icon {
  width: 3rem;
  height: 3rem;
  border-radius: 1.1rem;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 1.08rem;
  flex: 0 0 3rem;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5);
}

.app-section-stat__icon--total,
.security-stat__icon--primary {
  background: linear-gradient(135deg, rgba(140, 21, 21, 0.12), rgba(254, 194, 96, 0.2));
  color: #8c1515;
}

.app-section-stat__icon--active,
.security-stat__icon--success {
  background: linear-gradient(135deg, rgba(46, 184, 92, 0.12), rgba(46, 184, 92, 0.2));
  color: #2eb85c;
}

.app-section-stat__icon--attention,
.security-stat__icon--warning {
  background: linear-gradient(135deg, rgba(254, 194, 96, 0.18), rgba(140, 21, 21, 0.1));
  color: #9a5d00;
}

@media (max-width: 767.98px) {
  .app-section-hero__body {
    align-items: flex-start;
    flex-direction: column;
  }

  .app-section-hero__actions {
    width: 100%;
    align-items: stretch;
    flex-direction: column;
  }

  .app-section-hero__meta {
    text-align: left;
  }
}
</style>
