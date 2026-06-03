<template>
  <CCard v-bind="$attrs">
    <CCardBody class="account-section-body account-section-body--compact pb-0">
      <label class="floating-section__label">
        <CIcon name="cil-user" class="mr-1" />
        Identity
      </label>
      <CRow>
        <CCol md="4" col="12"><CPInput v-model="value.prefix" label="Prefix" placeholder="" /></CCol>
        <CCol md="4" col="12"><CPInput v-model="value.firstName" label="First Name" placeholder="" /></CCol>
        <CCol md="4" col="12"><CPInput v-model="value.lastName" label="Last Name" placeholder="" /></CCol>
      </CRow>
      <CRow>
        <CCol md="6" col="12"><CPInput v-model="value.cardId" label="Card ID" placeholder="" /></CCol>
        <CCol md="6" col="12"><CPDateInput v-model="value.birthday" label="Birthday" /></CCol>
      </CRow>
    </CCardBody>
  </CCard>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'
import CPDateInput from '@/projects/components/custom/CPDateInput'

export default {
  name: 'AccountIdentitySection',
  components: { CPInput, CPDateInput },
  inheritAttrs: false,
  props: {
    value: { type: Object, required: true }
  }
}
</script>
