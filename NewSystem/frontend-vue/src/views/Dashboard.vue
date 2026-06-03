<template>
  <div class="dashboard-page">
    <CRow>
      <CCol lg="8" class="mb-4">
        <CCard class="h-100 dashboard-card">
          <CCardBody>
            <div class="dashboard-kicker">{{ $t('newSystemDashboard.kicker') }}</div>
            <h2 class="dashboard-title">{{ $t('newSystemDashboard.title') }}</h2>
            <p class="dashboard-text">{{ $t('newSystemDashboard.subtitle') }}</p>

            <div class="dashboard-actions">
              <router-link class="btn btn-primary" to="/newsystem/registry">
                {{ $t('newSystemDashboard.actions.openRegistry') }}
              </router-link>
            </div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol lg="4" class="mb-4">
        <CCard class="h-100 dashboard-card">
          <CCardBody>
            <div class="dashboard-kicker">{{ $t('newSystemDashboard.scopeTitle') }}</div>
            <h4 class="dashboard-subtitle">{{ $t('newSystemDashboard.scopeHeading') }}</h4>
            <ul class="dashboard-list">
              <li>{{ $t('newSystemDashboard.scopeItems.signIn') }}</li>
              <li>{{ $t('newSystemDashboard.scopeItems.delegatedPermission') }}</li>
              <li>{{ $t('newSystemDashboard.scopeItems.accountDirectory') }}</li>
              <li>{{ $t('newSystemDashboard.scopeItems.newSystemRegistry') }}</li>
            </ul>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

    <CRow>
      <CCol md="4" class="mb-4">
        <CCard class="dashboard-card h-100">
          <CCardBody>
            <div class="dashboard-stat__label">{{ $t('newSystemDashboard.cards.identity.label') }}</div>
            <div class="dashboard-stat__value">{{ $t('newSystemDashboard.cards.identity.value') }}</div>
            <div class="dashboard-stat__hint">{{ $t('newSystemDashboard.cards.identity.hint') }}</div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol md="4" class="mb-4">
        <CCard class="dashboard-card h-100">
          <CCardBody>
            <div class="dashboard-stat__label">{{ $t('newSystemDashboard.cards.apiFlow.label') }}</div>
            <div class="dashboard-stat__value">{{ $t('newSystemDashboard.cards.apiFlow.value') }}</div>
            <div class="dashboard-stat__hint">{{ $t('newSystemDashboard.cards.apiFlow.hint') }}</div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol md="4" class="mb-4">
        <CCard class="dashboard-card h-100">
          <CCardBody>
            <div class="dashboard-stat__label">{{ $t('newSystemDashboard.cards.owner.label') }}</div>
            <div class="dashboard-stat__value">{{ $t('newSystemDashboard.cards.owner.value') }}</div>
            <div class="dashboard-stat__hint">{{ $t('newSystemDashboard.cards.owner.hint') }}</div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  </div>
</template>

<script>
export default {
  name: 'Dashboard'
}
</script>

<style scoped>
.dashboard-page {
  padding: 0.25rem;
}

.dashboard-card {
  border: 0;
  box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08);
}

.dashboard-kicker {
  margin-bottom: 0.75rem;
  color: #64748b;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.dashboard-title {
  margin-bottom: 0.75rem;
  color: #0f172a;
  font-size: 2rem;
  font-weight: 700;
}

.dashboard-subtitle {
  margin-bottom: 0.75rem;
  color: #0f172a;
  font-weight: 700;
}

.dashboard-text,
.dashboard-stat__hint {
  color: #475569;
  line-height: 1.6;
}

.dashboard-actions {
  margin-top: 1.5rem;
}

.dashboard-list {
  margin: 0;
  padding-left: 1.25rem;
  color: #334155;
  line-height: 1.8;
}

.dashboard-stat__label {
  color: #64748b;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.dashboard-stat__value {
  margin: 0.5rem 0;
  color: #0f172a;
  font-size: 1.5rem;
  font-weight: 700;
}
</style>
