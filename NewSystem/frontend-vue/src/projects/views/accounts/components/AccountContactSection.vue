<template>
  <CCard v-bind="$attrs">
    <CCardBody class="account-section-body account-section-body--compact pb-0">
      <label class="floating-section__label">
        <CIcon name="cil-address-book" class="mr-1" />
        Contact
      </label>
      <CRow>
        <CCol md="6" col="12"><CPInput v-model="value.msisdn" label="Phone" placeholder="" /></CCol>
        <CCol md="6" col="12"><CPInput v-model="value.lineId" label="Line ID" placeholder="" /></CCol>
      </CRow>
      <CRow>
        <CCol md="6" col="12"><CPInput v-model="value.religion" label="Religion" placeholder="" /></CCol>
      </CRow>
    </CCardBody>
  </CCard>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'

export default {
  name: 'AccountContactSection',
  components: { CPInput },
  inheritAttrs: false,
  props: {
    value: { type: Object, required: true }
  }
}
</script>
