<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal " add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">{{ isEditMode ? 'Update verification setting with multilingual content.' : 'Configure verification setting with multilingual content.' }}</div>
      </div>
    </div>

    <ModalLanguageToolbar :languages="languages" :active-tab="activeLanguageTab" :active-lang="activeLang" :label-resolver="langLabel" @update:activeTab="activeLanguageTab = $event" />

    <CRow>
      <CCol md="7" col="12">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title">Content</h5>
            <CPInput v-model.trim="activeTitle" :label="'Title'" :required="true" placeholder="" />
            <CPQuillEditor v-model="activeDescription" :label="'Description'" placeholder="" />
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="5" col="12">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title">Settings</h5>
            <div class="setting-field mb-3">
              <CPSelect
                v-model="groupSelected"
                :options="groupOptions"
                label="Group"
                :required="true"
                label-key="label"
                track-by="value"
                :multiple="false"
                :close-on-select="true"
                :show-labels="false"
                :allow-empty="false"
                :select-label="''"
                :deselect-label="''"
              />
            </div>
            <div class="setting-field mb-0">
              <CPSelect
                v-model="statusSelected"
                :options="statusOptions"
                label="Status"
                :required="true"
                label-key="label"
                track-by="value"
                :multiple="false"
                :close-on-select="true"
                :show-labels="false"
                :allow-empty="false"
                :select-label="''"
                :deselect-label="''"
              />
            </div>
            <AuditInfoCard
              v-if="isEditMode"
              title="Created"
              icon="cil-user-follow"
              :by="createdByLabel"
              :at="createdAtLabel"
            />
            <AuditInfoCard
              v-if="isEditMode"
              title="Updated"
              icon="cil-history"
              :by="updatedByLabel"
              :at="updatedAtLabel"
            />
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
        <CIcon :name="submitIcon" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1"> {{ submitLabel }} </span>
      </CButton>
    </div>
    <template #footer-wrapper><div></div></template>
  </CModal>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'
import CPSelect from '@/projects/components/custom/CPSelect'
import CPQuillEditor from '@/projects/components/custom/CPQuillEditor'
import ModalLanguageToolbar from '@/projects/components/layout/ModalLanguageToolbar'
import RequiredValidation from '@/projects/mixins/requiredValidation'
import AuditInfoCard from './AuditInfoCard'

function normalizeItems (items) {
  if (!Array.isArray(items)) return []
  return items
    .map(item => ({
      key: item && item.key ? String(item.key).trim().toLowerCase() : '',
      value: item && item.value ? String(item.value) : ''
    }))
    .filter(item => item.key)
}

function emptyDraft () {
  return { _id: null, titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }], descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }], groupId: '', statusId: '' }
}

export default {
  name: 'VerificationFormModal',
  components: { CPInput, CPSelect, CPQuillEditor, ModalLanguageToolbar, AuditInfoCard },
  mixins: [RequiredValidation],
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: 'Create Verification' },
    value: { type: Object, default: () => emptyDraft() },
    groups: { type: Array, default: () => [] },
    statuses: { type: Array, default: () => [] }
  },
  data () {
    return {
      local: emptyDraft(),
      activeLang: 'th'
    }
  },
  computed: {
    isEditMode () {
      return !!(this.local && this.local._id)
    },
    submitLabel () {
      return this.isEditMode ? 'Update' : 'Save'
    },
    submitIcon () {
      return this.isEditMode ? 'cil-pencil' : 'cil-save'
    },
    createdByLabel () {
      return this.value && this.value.createdByName ? this.value.createdByName : '-'
    },
    createdAtLabel () {
      if (!(this.value && this.value.createdAt)) return '-'
      const date = new Date(this.value.createdAt)
      if (Number.isNaN(date.getTime())) return this.value.createdAt
      return date.toLocaleString()
    },
    updatedByLabel () {
      return this.value && this.value.updatedByName ? this.value.updatedByName : '-'
    },
    updatedAtLabel () {
      if (!(this.value && this.value.updatedAt)) return '-'
      const date = new Date(this.value.updatedAt)
      if (Number.isNaN(date.getTime())) return this.value.updatedAt
      return date.toLocaleString()
    },
    languages () {
      const t = this.local.titleItems.map(i => i.key)
      const d = this.local.descriptionItems.map(i => i.key)
      const merged = [...new Set([...t, ...d].filter(Boolean))]
      return merged.length ? merged : ['th', 'en']
    },
    activeLanguageTab: {
      get () {
        const idx = this.languages.indexOf(this.activeLang)
        return idx >= 0 ? idx : 0
      },
      set (tabIndex) {
        this.activeLang = this.languages[tabIndex] || this.languages[0] || 'th'
      }
    },
    activeTitle: {
      get () {
        const found = this.local.titleItems.find(i => i.key === this.activeLang)
        return found ? found.value : ''
      },
      set (value) {
        const idx = this.local.titleItems.findIndex(i => i.key === this.activeLang)
        if (idx >= 0) this.local.titleItems[idx].value = value
        else this.local.titleItems.push({ key: this.activeLang, value })
      }
    },
    activeDescription: {
      get () {
        const found = this.local.descriptionItems.find(i => i.key === this.activeLang)
        return found ? found.value : ''
      },
      set (value) {
        const idx = this.local.descriptionItems.findIndex(i => i.key === this.activeLang)
        if (idx >= 0) this.local.descriptionItems[idx].value = value
        else this.local.descriptionItems.push({ key: this.activeLang, value })
      }
    },
    groupOptions () {
      return (this.groups || []).map(i => ({ value: i._id, label: i.name || i.key })).filter(i => i.value)
    },
    statusOptions () {
      return (this.statuses || []).map(i => ({ value: i._id, label: i.titleTh || i.titleEn || i.key })).filter(i => i.value)
    },
    groupSelected: {
      get () { return this.groupOptions.find(i => i.value === this.local.groupId) || null },
      set (v) { this.local.groupId = v && v.value ? v.value : '' }
    },
    statusSelected: {
      get () { return this.statusOptions.find(i => i.value === this.local.statusId) || null },
      set (v) { this.local.statusId = v && v.value ? v.value : '' }
    },
    canSubmit () {
      const titleItems = normalizeItems(this.local.titleItems).filter(i => i.value && String(i.value).trim())
      return !!titleItems.length && !!this.local.groupId && !!this.local.statusId
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (v) {
        if (v) {
          this.local = {
            _id: this.value && this.value._id ? this.value._id : null,
            titleItems: normalizeItems(this.value && this.value.titleItems),
            descriptionItems: normalizeItems(this.value && this.value.descriptionItems),
            groupId: this.value && this.value.groupId ? this.value.groupId : '',
            statusId: this.value && this.value.statusId ? this.value.statusId : ''
          }
          if (!this.local.titleItems.length) this.local.titleItems = [{ key: 'th', value: '' }, { key: 'en', value: '' }]
          if (!this.local.descriptionItems.length) this.local.descriptionItems = [{ key: 'th', value: '' }, { key: 'en', value: '' }]
          if (!this.local.groupId && this.groupOptions[0]) this.local.groupId = this.groupOptions[0].value
          if (!this.local.statusId && this.statusOptions[0]) this.local.statusId = this.statusOptions[0].value
          this.activeLang = this.languages[0] || 'th'
        }
      }
    }
  },
  methods: {
    langLabel (lang) {
      const mapping = { th: 'ไทย (th)', en: 'English (en)' }
      return mapping[lang] || lang
    },
    onShowChange (value) {
      this.$emit('update:show', value)
      if (!value) this.$emit('cancel')
    },
    onCancel () {
      this.$emit('update:show', false)
      this.$emit('cancel')
    },
    submit () {
      if (!this.validateRequired()) {
        this.$emit('invalid', 'Please fill all required fields.')
        return
      }
      const titleItems = normalizeItems(this.local.titleItems).filter(i => i.value && String(i.value).trim())
      if (!titleItems.length || !this.local.groupId || !this.local.statusId) {
        this.$emit('invalid', 'Please complete required fields.')
        return
      }
      this.$emit('submit', this.local)
    }
  }
}
</script>
