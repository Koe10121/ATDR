<template>
  <CModal :show="show" @update:show="onShowChange" size="lg" class="login-message-modal" add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">{{ subtitle }}</div>
      </div>
    </div>

    <CRow>
      <CCol md="7" col="12">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title">Content</h5>
            <CPInput v-model.trim="local.key" label="Key" :required="true" />
            <CPInput v-if="showCodeField" v-model.trim="local.code" label="Code" />
            <CPInput v-model.trim="titleTh" label="Title (TH)" :required="true" />
            <CPInput v-model.trim="titleEn" label="Title (EN)" />
            <CPQuillEditor v-model="descriptionTh" label="Description (TH)" />
            <CPQuillEditor v-model="descriptionEn" label="Description (EN)" />
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="5" col="12">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title">Structure</h5>
            <div v-if="showOrgGroupField" class="setting-field mb-3">
              <CPSelect
                v-model="orgGroupSelected"
                :options="orgGroupOptions"
                label="Org Group"
                label-key="label"
                track-by="value"
                :multiple="false"
                :close-on-select="true"
                :show-labels="false"
                :allow-empty="false"
              />
            </div>
            <div v-if="showOrgUnitField" class="setting-field mb-3">
              <CPSelect
                v-model="orgUnitSelected"
                :options="orgUnitOptions"
                label="Org Unit"
                label-key="label"
                track-by="value"
                :multiple="false"
                :close-on-select="true"
                :show-labels="false"
                :allow-empty="false"
              />
            </div>
            <div class="setting-field mb-0">
              <CInputCheckbox custom :checked="local.isActive" @change="local.isActive = !local.isActive" />
              <span class="small text-muted ml-2">Active</span>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

    <div class="modal-footer-wrap d-flex w-100 justify-content-end mt-3">
      <CButton class="mr-2 footer-btn-cancel footer-action-btn" color="danger" variant="outline" shape="pill" @click="onCancel">
        <CIcon name="cil-ban" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1"> Cancel </span>
      </CButton>
      <CButton color="success" shape="pill" class="footer-btn-save footer-action-btn" :disabled="!canSubmit" @click="submit">
        <CIcon :name="local._id ? 'cil-pencil' : 'cil-save'" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1"> {{ local._id ? 'Update' : 'Save' }} </span>
      </CButton>
    </div>
    <template #footer-wrapper><div></div></template>
  </CModal>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'
import CPSelect from '@/projects/components/custom/CPSelect'
import CPQuillEditor from '@/projects/components/custom/CPQuillEditor'

function normalizeLangArray (value) {
  if (!Array.isArray(value)) return []
  return value.map(item => ({
    key: item && item.key ? String(item.key).trim().toLowerCase() : '',
    value: item && item.value ? String(item.value) : ''
  })).filter(item => item.key)
}

function emptyDraft () {
  return {
    _id: null,
    key: '',
    code: '',
    titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    isActive: true,
    orgGroupId: '',
    orgUnitId: ''
  }
}

export default {
  name: 'HrMasterModal',
  components: { CPInput, CPSelect, CPQuillEditor },
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: '' },
    subtitle: { type: String, default: '' },
    entity: { type: String, default: 'orgGroups' },
    value: { type: Object, default: () => emptyDraft() },
    orgGroups: { type: Array, default: () => [] },
    orgUnits: { type: Array, default: () => [] }
  },
  data () {
    return { local: emptyDraft() }
  },
  computed: {
    showCodeField () {
      return ['orgUnits', 'degreeLevels', 'employmentStatuses', 'workLines', 'personnelTypes'].includes(this.entity)
    },
    showOrgGroupField () {
      return ['orgUnits', 'subUnits'].includes(this.entity)
    },
    showOrgUnitField () {
      return this.entity === 'subUnits'
    },
    orgGroupOptions () {
      return (this.orgGroups || []).map(item => ({ value: item._id, label: item.titleText || item.key }))
    },
    orgUnitOptions () {
      const groupId = this.local.orgGroupId
      return (this.orgUnits || [])
        .filter(item => !groupId || item.orgGroupId === groupId)
        .map(item => ({ value: item._id, label: item.titleText || item.key }))
    },
    orgGroupSelected: {
      get () {
        return this.orgGroupOptions.find(item => item.value === this.local.orgGroupId) || null
      },
      set (value) {
        this.local.orgGroupId = value && value.value ? value.value : ''
        if (!this.showOrgUnitField) return
        const exists = this.orgUnitOptions.some(item => item.value === this.local.orgUnitId)
        if (!exists) this.local.orgUnitId = ''
      }
    },
    orgUnitSelected: {
      get () {
        return this.orgUnitOptions.find(item => item.value === this.local.orgUnitId) || null
      },
      set (value) {
        this.local.orgUnitId = value && value.value ? value.value : ''
      }
    },
    titleTh: {
      get () {
        return this.readLang('titleItems', 'th')
      },
      set (value) {
        this.writeLang('titleItems', 'th', value)
      }
    },
    titleEn: {
      get () {
        return this.readLang('titleItems', 'en')
      },
      set (value) {
        this.writeLang('titleItems', 'en', value)
      }
    },
    descriptionTh: {
      get () {
        return this.readLang('descriptionItems', 'th')
      },
      set (value) {
        this.writeLang('descriptionItems', 'th', value)
      }
    },
    descriptionEn: {
      get () {
        return this.readLang('descriptionItems', 'en')
      },
      set (value) {
        this.writeLang('descriptionItems', 'en', value)
      }
    },
    canSubmit () {
      const hasTitle = normalizeLangArray(this.local.titleItems).some(item => item.value && String(item.value).trim())
      if (!this.local.key || !hasTitle) return false
      if (this.showOrgGroupField && !this.local.orgGroupId) return false
      if (this.showOrgUnitField && !this.local.orgUnitId) return false
      return true
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (!value) return
        this.local = Object.assign(emptyDraft(), this.value || {})
        this.local.titleItems = normalizeLangArray(this.value && this.value.titleItems).length ? normalizeLangArray(this.value.titleItems) : [{ key: 'th', value: '' }, { key: 'en', value: '' }]
        this.local.descriptionItems = normalizeLangArray(this.value && this.value.descriptionItems).length ? normalizeLangArray(this.value.descriptionItems) : [{ key: 'th', value: '' }, { key: 'en', value: '' }]
      }
    }
  },
  methods: {
    readLang (field, lang) {
      const found = (this.local[field] || []).find(item => item.key === lang)
      return found ? found.value : ''
    },
    writeLang (field, lang, value) {
      const index = (this.local[field] || []).findIndex(item => item.key === lang)
      if (index >= 0) {
        this.local[field][index].value = value
      } else {
        this.local[field].push({ key: lang, value })
      }
    },
    submit () {
      this.$emit('submit', Object.assign({}, this.local))
    },
    onCancel () {
      this.$emit('cancel')
      this.onShowChange(false)
    },
    onShowChange (value) {
      this.$emit('update:show', value)
    }
  }
}
</script>

<style scoped lang="scss">
@import "../../../styles/settings/setting-modal.shared.scss";
</style>
