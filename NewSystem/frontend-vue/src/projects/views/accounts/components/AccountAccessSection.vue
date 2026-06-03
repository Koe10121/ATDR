<template>
  <CCard v-bind="$attrs">
    <CCardBody class="account-section-body account-section-body--compact">
      <label class="floating-section__label">
        <CIcon name="cil-shield-alt" class="mr-1" />
        Access
      </label>
      <CRow>
        <CCol md="6" col="12" class="mb-0"><CPInput v-model="form.code" label="Code" placeholder="" /></CCol>
        <CCol md="6" col="12" class="mb-0"><CPInput v-model="form.email" label="Email" placeholder="" /></CCol>
      </CRow>
      <CRow>
        <CCol md="6" col="12" class="mb-0">
          <CPSelect
            v-model="selectedStatus"
            :options="statusSelectOptions"
            label="Status"
            label-key="label"
            track-by="value"
            :multiple="false"
            :close-on-select="true"
            :show-labels="false"
            :allow-empty="false"
            :select-label="''"
            :deselect-label="''"
          />
        </CCol>
        <CCol md="6" col="12" class="mb-0">
          <CPSelect
            v-model="selectedGroups"
            :options="securityGroupSelectOptions"
            label="Group"
            label-key="label"
            track-by="value"
            :multiple="true"
            :close-on-select="false"
            :show-labels="false"
            :allow-empty="true"
            :select-label="''"
            :deselect-label="''"
          />
        </CCol>
      </CRow>
    </CCardBody>
  </CCard>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'
import CPSelect from '@/projects/components/custom/CPSelect'

export default {
  name: 'AccountAccessSection',
  components: { CPInput, CPSelect },
  inheritAttrs: false,
  props: {
    value: { type: Object, required: true },
    statusOptions: { type: Array, default: () => [] },
    groupOptions: { type: Array, default: () => [] }
  },
  computed: {
    form () {
      return this.value
    },
    statusSelectOptions () {
      return (this.statusOptions || []).map(item => ({
        value: item && item.key ? String(item.key) : '',
        label: item && item.label ? String(item.label) : (item && item.key ? String(item.key) : '')
      })).filter(item => item.value)
    },
    securityGroupSelectOptions () {
      return (this.groupOptions || []).map(item => ({
        value: item && item._id ? String(item._id) : '',
        label: item && item.label ? String(item.label) : '-'
      })).filter(item => item.value)
    },
    selectedStatus: {
      get () {
        return this.statusSelectOptions.find(item => item.value === this.form.statusKey) || null
      },
      set (option) {
        this.form.statusKey = option && option.value ? String(option.value) : ''
      }
    },
    selectedGroups: {
      get () {
        const groupIds = Array.isArray(this.form.groupIds) ? this.form.groupIds.map(item => String(item)) : []
        return this.securityGroupSelectOptions.filter(item => groupIds.includes(String(item.value)))
      },
      set (options) {
        this.form.groupIds = Array.isArray(options)
          ? options.map(item => item && item.value ? String(item.value) : '').filter(Boolean)
          : []
      }
    }
  }
}
</script>
