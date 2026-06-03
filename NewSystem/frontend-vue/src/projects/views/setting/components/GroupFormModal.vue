<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal " add-content-classes="border-radius-1">
    <template #header-wrapper>
      <div></div>
    </template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">
          {{ isEditMode ? 'Update group that supports multiple languages.' : 'Configure group that supports multiple languages.' }}
        </div>
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

            <CPInput v-model="keyValue" :label="'Key'" placeholder="" />

            <CPSelect
              v-model="stateSelected"
              :options="stateOptions"
              label="State"
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
      <CButton color="success" shape="pill" class="footer-btn-save footer-action-btn" @click="onSubmit">
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

function createEmptyForm () {
  return {
    _id: null,
    key: '',
    titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    state: true
  }
}

export default {
  name: 'GroupFormModal',
  components: { CPInput, CPSelect, CPQuillEditor, ModalLanguageToolbar, AuditInfoCard },
  mixins: [RequiredValidation],
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: 'Create Group' },
    value: { type: Object, default: () => createEmptyForm() }
  },
  data () {
    return {
      localForm: createEmptyForm(),
      activeLang: 'th',
      stateOptions: [
        { value: 'active', label: 'Active' },
        { value: 'inactive', label: 'Inactive' }
      ]
    }
  },
  computed: {
    isEditMode () {
      return !!(this.localForm && this.localForm._id)
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
      const titleKeys = this.localForm.titleItems.map(item => item.key)
      const descKeys = this.localForm.descriptionItems.map(item => item.key)
      const merged = [...new Set([...titleKeys, ...descKeys].filter(Boolean))]
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
        const found = this.localForm.titleItems.find(item => item.key === this.activeLang)
        return found ? found.value : ''
      },
      set (value) {
        this.upsertTitle(this.activeLang, value)
      }
    },
    activeDescription: {
      get () {
        const found = this.localForm.descriptionItems.find(item => item.key === this.activeLang)
        return found ? found.value : ''
      },
      set (value) {
        this.upsertDescription(this.activeLang, value)
      }
    },
    stateSelected: {
      get () {
        return this.localForm.state ? this.stateOptions[0] : this.stateOptions[1]
      },
      set (option) {
        this.localForm.state = !option || option.value !== 'inactive'
      }
    },
    keyValue: {
      get () {
        return this.localForm.key || ''
      },
      set (value) {
        this.localForm.key = String(value || '')
          .toUpperCase()
          .replace(/\s+/g, '_')
          .replace(/[^A-Z0-9_]/g, '')
      }
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
    }
  },
  methods: {
    langLabel (lang) {
      const mapping = { th: 'ไทย (th)', en: 'English (en)' }
      return mapping[lang] || lang
    },
    upsertTitle (lang, value) {
      const idx = this.localForm.titleItems.findIndex(item => item.key === lang)
      if (idx >= 0) {
        this.localForm.titleItems[idx].value = value
      } else {
        this.localForm.titleItems.push({ key: lang, value })
      }
    },
    upsertDescription (lang, value) {
      const idx = this.localForm.descriptionItems.findIndex(item => item.key === lang)
      if (idx >= 0) {
        this.localForm.descriptionItems[idx].value = value
      } else {
        this.localForm.descriptionItems.push({ key: lang, value })
      }
    },
    resetForm () {
      const titleItems = normalizeItems(this.value && this.value.titleItems)
      const descriptionItems = normalizeItems(this.value && this.value.descriptionItems)
      this.localForm = {
        _id: this.value && this.value._id ? this.value._id : null,
        key: this.value && this.value.key ? String(this.value.key) : '',
        titleItems: titleItems.length ? titleItems : [{ key: 'th', value: '' }, { key: 'en', value: '' }],
        descriptionItems: descriptionItems.length ? descriptionItems : [{ key: 'th', value: '' }, { key: 'en', value: '' }],
        state: typeof (this.value && this.value.state) === 'boolean' ? this.value.state : true
      }
      this.activeLang = this.languages[0] || 'th'
    },
    onShowChange (value) {
      this.$emit('update:show', value)
      if (!value) this.$emit('cancel')
    },
    onCancel () {
      this.$emit('update:show', false)
      this.$emit('cancel')
    },
    onSubmit () {
      if (!this.validateRequired()) {
        this.$emit('invalid', 'Please fill all required fields.')
        return
      }
      const title = normalizeItems(this.localForm.titleItems)
        .filter(item => item.value && String(item.value).trim())
      const description = normalizeItems(this.localForm.descriptionItems)
        .filter(item => item.value && String(item.value).trim())

      if (!title.length) {
        this.$emit('invalid', 'Please provide at least one language title.')
        return
      }
      this.$emit('submit', {
        _id: this.localForm._id,
        key: String(this.localForm.key || '').trim(),
        title,
        description,
        state: !!this.localForm.state
      })
    }
  }
}
</script>
