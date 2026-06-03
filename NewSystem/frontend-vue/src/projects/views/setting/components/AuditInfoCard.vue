<template>
  <div class="floating-group mb-3">
    <div class="border rounded mt-3 p-3">
      <CRow>
        <CCol col="2" class="font-weight-bold">{{ $t('common.audit.by') }} : </CCol>
        <CCol><div class="text-dark">{{ by || '-' }}</div></CCol>
      </CRow>
      <CRow>
        <CCol col="2" class="font-weight-bold">{{ $t('common.audit.at') }} : </CCol>
        <CCol><div class="text-dark">{{ at || '-' }}</div></CCol>
      </CRow>
    </div>
    <label class="active">
      <CIcon :name="icon" class="mr-1" />
      {{ title }}
    </label>
  </div>
</template>

<script>
export default {
  name: 'AuditInfoCard',
  props: {
    title: { type: String, default: '' },
    icon: { type: String, default: 'cil-user-follow' },
    by: { type: String, default: '-' },
    at: { type: String, default: '-' }
  }
}
</script>

<style scoped>
.floating-group {
  position: relative;
}

.floating-group > label {
  position: absolute;
  top: 0;
  left: 0.85rem;
  transform: translateY(-50%);
  background: #fff;
  padding: 0 0.45rem;
  color: #5f6f86;
  font-size: 0.78rem;
  font-weight: 600;
}
</style>
