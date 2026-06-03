<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal " add-content-classes="border-radius-1">
    <template #header-wrapper>
      <div></div>
    </template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">
          {{ isEditMode ? 'Update login announcement that supports multiple languages.' : 'Configure login announcement that supports multiple languages.' }}
        </div>
      </div>
    </div>

    <ModalLanguageToolbar :languages="languages" :active-tab="activeLanguageTab" :active-lang="activeLang" :label-resolver="langLabel" @update:activeTab="activeLanguageTab = $event" />

    <CRow>
      <CCol md="7" col="12">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title">Content</h5>

            <div class="content-block mb-4">
              <CPInput
                v-model.trim="activeTitle"
                :label="'Title'"
                :required="true"
                placeholder=""
              />
              <div class="d-flex justify-content-between align-items-center content-meta-row">
                <small class="text-muted">Recommended 80 characters max</small>
                <small :class="titleCounterClass">{{ titleLength }}/80</small>
              </div>
            </div>

            <div class="content-block mb-0">
              <label class="content-label">Description</label>
              <QEditor :content="activeDescriptionItem" />
            </div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol md="5" col="12">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title">Settings</h5>

            <div class="status-pill mb-3 ">
              <span class="status-dot" :class="{ inactive: statusOption !== 'active' }"></span>
              <span class="status-text">{{ statusSelected.label }}</span>
            </div>

            <CRow class="mt-2">
              <CCol md="6" col="12">
                <CPDateInput v-model="localForm.startDate" type="date" label="Start date"
                             :required="true"/>
              </CCol>
              <CCol md="6" col="12">
                <CPDateInput v-model="localForm.endDate" type="date" label="End date"
                             :required="true"/>
              </CCol>
            </CRow>
            <small v-if="!isDateRangeValid" class="text-danger d-block mb-3">
              End date must be the same or later than start date.
            </small>

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
              placeholder=""
            />


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
      <CButton class="mr-2 footer-btn-secondary footer-action-btn" color="secondary" variant="outline" shape="pill" @click="onSubmit(true)">
        <CIcon name="cil-notes" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1"> {{ draftLabel }} </span>

      </CButton>
      <CButton color="success" shape="pill" class="footer-btn-save footer-action-btn" :disabled="!canSubmit" @click="onSubmit(false)">
        <CIcon :name="submitIcon" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1"> {{ submitLabel }} </span>

      </CButton>
    </div>

    <template #footer-wrapper>
      <div></div>
    </template>
  </CModal>
</template>

<script>
import QEditor from '@/projects/components/Util/QEditor'
import CPInput from '@/projects/components/custom/CPInput'
import CPDateInput from '@/projects/components/custom/CPDateInput'
import CPSelect from '@/projects/components/custom/CPSelect'
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

export default {
  name: 'MessageAuthenFormModal',
  mixins: [RequiredValidation],
  components: { QEditor, CPInput, CPDateInput, CPSelect, ModalLanguageToolbar, AuditInfoCard },
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: 'Create Setting Message Authen' },
    value: {
      type: Object,
      default: () => ({
        _id: null,
        titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
        descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
        startDate: '',
        endDate: '',
        statusOption: 'active',
        createdByName: '',
        createdAt: ''
      })
    }
  },
  data () {
    return {
      localForm: this.createEmptyForm(),
      activeLang: 'th',
      statusOption: 'active',
      statusOptions: [
        { value: 'active', label: 'Active' },
        { value: 'inactive', label: 'Inactive' },
        { value: 'draft', label: 'Draft' }
      ]
    }
  },
  computed: {
    submitLabel () {
      return this.isEditMode ? 'Update' : 'Save'
    },
    submitIcon () {
      return this.isEditMode ? 'cil-pencil' : 'cil-save'
    },
    draftLabel () {
      return this.isEditMode ? 'Update as Draft' : 'Save as Draft'
    },
    languages () {
      const titleKeys = this.localForm.titleItems.map(item => item.key)
      const descKeys = this.localForm.descriptionItems.map(item => item.key)
      const merged = [...new Set([...titleKeys, ...descKeys].filter(Boolean))]
      if (!merged.length) return ['th', 'en']
      return merged
    },
    activeLanguageTab: {
      get () {
        const idx = this.languages.indexOf(this.activeLang)
        return idx >= 0 ? idx : 0
      },
      set (tabIndex) {
        const nextLang = this.languages[tabIndex] || this.languages[0] || 'th'
        this.activeLang = nextLang
        this.ensureLangExists(nextLang)
      }
    },
    activeTitle: {
      get () {
        const found = this.localForm.titleItems.find(item => item.key === this.activeLang)
        return found ? found.value : ''
      },
      set (value) {
        this.upsertLangValue('titleItems', this.activeLang, value)
      }
    },
    activeDescriptionItem () {
      const found = this.localForm.descriptionItems.find(item => item.key === this.activeLang)
      return found || { key: this.activeLang, value: '' }
    },
    titleLength () {
      return (this.activeTitle || '').length
    },
    titleCounterClass () {
      return this.titleLength > 80 ? 'text-danger' : 'text-muted'
    },
    hasAtLeastOneTitle () {
      return normalizeItems(this.localForm.titleItems).some(item => item.value && String(item.value).trim())
    },
    isDateRangeValid () {
      if (!this.localForm.startDate || !this.localForm.endDate) return true
      return new Date(this.localForm.endDate) >= new Date(this.localForm.startDate)
    },
    canSubmit () {
      return this.hasAtLeastOneTitle && this.isDateRangeValid
    },
    statusSelected: {
      get () {
        return this.statusOptions.find(item => item.value === this.statusOption) || this.statusOptions[0]
      },
      set (option) {
        this.statusOption = option && option.value ? option.value : 'active'
      }
    },
    isEditMode () {
      return !!(this.localForm && this.localForm._id)
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
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (value) this.resetForm()
      }
    },
    value: {
      deep: true,
      handler () {
        if (this.show) this.resetForm()
      }
    },
    activeLang (value) {
      this.ensureLangExists(value)
    }
  },
  methods: {
    createEmptyForm () {
      return {
        _id: null,
        titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
        descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
        startDate: '',
        endDate: ''
      }
    },
    langLabel (lang) {
      const mapping = { th: 'ไทย (th)', en: 'English (en)' }
      return mapping[lang] || lang
    },
    upsertLangValue (field, lang, value) {
      const list = this.localForm[field]
      const idx = list.findIndex(item => item.key === lang)
      if (idx >= 0) {
        list[idx].value = value
      } else {
        list.push({ key: lang, value })
      }
    },
    ensureLangExists (lang) {
      if (!this.localForm.titleItems.some(item => item.key === lang)) {
        this.localForm.titleItems.push({ key: lang, value: '' })
      }
      if (!this.localForm.descriptionItems.some(item => item.key === lang)) {
        this.localForm.descriptionItems.push({ key: lang, value: '' })
      }
    },
    resetForm () {
      this.localForm = {
        _id: this.value && this.value._id ? this.value._id : null,
        titleItems: normalizeItems(this.value && this.value.titleItems),
        descriptionItems: normalizeItems(this.value && this.value.descriptionItems),
        startDate: this.value && this.value.startDate ? this.value.startDate : '',
        endDate: this.value && this.value.endDate ? this.value.endDate : ''
      }

      if (!this.localForm.titleItems.length && !this.localForm.descriptionItems.length) {
        this.localForm.titleItems = [{ key: 'th', value: '' }, { key: 'en', value: '' }]
        this.localForm.descriptionItems = [{ key: 'th', value: '' }, { key: 'en', value: '' }]
      }

      const firstLang = this.languages[0] || 'th'
      this.activeLang = firstLang
      this.ensureLangExists(firstLang)
      this.statusOption = this.value && this.value.statusOption ? this.value.statusOption : 'active'
    },
    onShowChange (value) {
      this.$emit('update:show', value)
      if (!value) this.$emit('cancel')
    },
    onCancel () {
      this.$emit('update:show', false)
      this.$emit('cancel')
    },
    onSubmit (isDraft) {
      if (!this.validateRequired()) {
        this.$emit('invalid', 'Please fill all required fields.')
        return
      }

      const titleItems = normalizeItems(this.localForm.titleItems).filter(item => item.value && String(item.value).trim())
      const descriptionItems = normalizeItems(this.localForm.descriptionItems)

      if (!titleItems.length) {
        this.$emit('invalid', 'Please provide at least one language title.')
        return
      }
      if (!this.isDateRangeValid) {
        this.$emit('invalid', 'End date must be the same or later than start date.')
        return
      }

      this.$emit('submit', {
        _id: this.localForm._id,
        titleItems,
        descriptionItems,
        startDate: this.localForm.startDate || '',
        endDate: this.localForm.endDate || '',
        statusOption: isDraft ? 'draft' : this.statusOption
      })
    }
  }
}
</script>
