<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal " add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">{{ isEditMode ? 'Update system message that supports multiple languages.' : 'Configure system message that supports multiple languages.' }}</div>
      </div>
    </div>

    <ModalLanguageToolbar :languages="languages" :active-tab="activeLanguageTab" :active-lang="activeLang" :label-resolver="langLabel" @update:activeTab="activeLanguageTab = $event" />

    <CRow>
      <CCol md="7" col="12">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title">Content</h5>
            <CPInput v-model.trim="activeMessage" :label="'Message'" :required="true" placeholder="" />
            <CPQuillEditor v-model="activeDescription" :label="'Description'" placeholder="" />
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="5" col="12">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title">Settings</h5>
            <CPInput v-model.number="local.number" type="number" :label="'Number'" :required="true" placeholder="" />
            <CPInput v-model.number="local.code" type="number" :label="'Code'" :required="true" placeholder="" />
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

function emptyForm () {
  return {
    _id: null,
    number: 0,
    code: 0,
    messageItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }]
  }
}

export default {
  name: 'MessageFormModal',
  components: { CPInput, CPQuillEditor, ModalLanguageToolbar, AuditInfoCard },
  mixins: [RequiredValidation],
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: 'Create Message' },
    value: { type: Object, default: () => emptyForm() }
  },
  data () {
    return {
      local: emptyForm(),
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
      const messageKeys = this.local.messageItems.map(i => i.key)
      const descriptionKeys = this.local.descriptionItems.map(i => i.key)
      const merged = [...new Set([...messageKeys, ...descriptionKeys].filter(Boolean))]
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
    activeMessage: {
      get () {
        const found = this.local.messageItems.find(i => i.key === this.activeLang)
        return found ? found.value : ''
      },
      set (value) {
        const idx = this.local.messageItems.findIndex(i => i.key === this.activeLang)
        if (idx >= 0) this.local.messageItems[idx].value = value
        else this.local.messageItems.push({ key: this.activeLang, value })
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
    canSubmit () {
      const messageItems = normalizeItems(this.local.messageItems).filter(i => i.value && String(i.value).trim())
      return Number(this.local.number) > 0 && Number(this.local.code) > 0 && messageItems.length > 0
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (value) {
          this.local = {
            _id: this.value && this.value._id ? this.value._id : null,
            number: this.value && this.value.number ? this.value.number : 0,
            code: this.value && this.value.code ? this.value.code : 0,
            messageItems: normalizeItems(this.value && this.value.messageItems),
            descriptionItems: normalizeItems(this.value && this.value.descriptionItems)
          }
          if (!this.local.messageItems.length) {
            this.local.messageItems = [{ key: 'th', value: '' }, { key: 'en', value: '' }]
          }
          if (!this.local.descriptionItems.length) {
            this.local.descriptionItems = [{ key: 'th', value: '' }, { key: 'en', value: '' }]
          }
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
      const messageItems = normalizeItems(this.local.messageItems).filter(i => i.value && String(i.value).trim())
      if (!messageItems.length) {
        this.$emit('invalid', 'Please provide at least one language message.')
        return
      }
      this.$emit('submit', {
        _id: this.local._id,
        number: Number(this.local.number),
        code: Number(this.local.code),
        messageItems,
        descriptionItems: normalizeItems(this.local.descriptionItems).filter(i => i.value && String(i.value).trim())
      })
    }
  }
}
</script>
