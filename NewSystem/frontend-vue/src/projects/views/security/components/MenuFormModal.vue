<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal" add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">{{ isEditMode ? $t('security.formModal.menu.editHint') : $t('security.formModal.menu.createHint') }}</div>
      </div>
    </div>

    <ModalLanguageToolbar :languages="languages" :active-tab="activeLanguageTab" :active-lang="activeLang" :label-resolver="langLabel" @update:activeTab="activeLanguageTab = $event" />

    <CRow>
      <CCol md="7" col="12" class="mb-3">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title">{{ $t('common.sections.content') }}</h5>
            <CPInput v-model.trim="activeTitle" :label="$t('security.createMenu.fields.menuTitle')" :required="true" placeholder="" />
            <CPQuillEditor v-model="activeDescription" :label="$t('common.description')" placeholder="" />
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="5" col="12" class="mb-3">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title">{{ $t('common.sections.settings') }}</h5>
            <CPInput v-model.trim="localForm.path" :label="$t('security.createMenu.fields.path')" :required="true" placeholder="" />
            <CPSelect
                class="mb-3"
              v-model="selectedType"
              :options="typeOptions"
              :label="$t('security.createMenu.fields.type')"
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
            <CPSelect
              v-model="stateSelected"
              :options="stateOptions"
              :label="$t('common.status.label')"
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
              :title="$t('common.audit.created')"
              icon="cil-user-follow"
              :by="createdByLabel"
              :at="createdAtLabel"
            />
            <AuditInfoCard
              v-if="isEditMode"
              :title="$t('common.audit.updated')"
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
        <span class="font-weight-bold pr-1 pl-1">{{ $t('common.actions.cancel') }}</span>
      </CButton>
      <CButton color="success" shape="pill" class="footer-btn-save footer-action-btn" @click="onSubmit">
        <CIcon name="cil-save" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1">{{ isEditMode ? $t('common.actions.update') : $t('common.actions.save') }}</span>
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
import AuditInfoCard from '@/projects/views/setting/components/AuditInfoCard'
import {
  getLanguages,
  getValueByLang,
  langLabel,
  normalizeOrDefault,
  setValueByLang
} from './security-multilang.shared'

export default {
  name: 'MenuFormModal',
  components: { CPInput, CPSelect, CPQuillEditor, ModalLanguageToolbar, AuditInfoCard },
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: '' },
    value: {
      type: Object,
      default: () => ({ _id: null, title: [], description: [], path: '', typeId: '' })
    },
    typeOptions: { type: Array, default: () => [] }
  },
  data () {
    return {
      localForm: {
        _id: null,
        title: normalizeOrDefault([]),
        description: normalizeOrDefault([]),
        path: '',
        typeId: '',
        state: true
      },
      activeLang: 'th',
      stateOptions: [
        { value: 'active', label: this.$t('common.status.active') },
        { value: 'inactive', label: this.$t('common.status.inactive') }
      ]
    }
  },
  computed: {
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
    },
    stateSelected: {
      get () {
        return this.localForm.state ? this.stateOptions[0] : this.stateOptions[1]
      },
      set (option) {
        this.localForm.state = !option || option.value !== 'inactive'
      }
    },
    languages () {
      return getLanguages(this.localForm.title, this.localForm.description)
    },
    activeLanguageTab: {
      get () {
        const index = this.languages.indexOf(this.activeLang)
        return index >= 0 ? index : 0
      },
      set (tabIndex) {
        this.activeLang = this.languages[tabIndex] || this.languages[0] || 'th'
      }
    },
    activeTitle: {
      get () {
        return getValueByLang(this.localForm.title, this.activeLang)
      },
      set (value) {
        setValueByLang(this.localForm.title, this.activeLang, value)
      }
    },
    activeDescription: {
      get () {
        return getValueByLang(this.localForm.description, this.activeLang)
      },
      set (value) {
        setValueByLang(this.localForm.description, this.activeLang, value)
      }
    },
    selectedType: {
      get () {
        return this.typeOptions.find(item => item.value === this.localForm.typeId) || null
      },
      set (option) {
        this.localForm.typeId = option && option.value ? option.value : ''
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
    langLabel,
    resetForm () {
      this.localForm = {
        _id: this.value && this.value._id ? this.value._id : null,
        title: normalizeOrDefault(this.value && this.value.title),
        description: normalizeOrDefault(this.value && this.value.description),
        path: this.value && this.value.path ? this.value.path : '',
        typeId: this.value && this.value.typeId ? this.value.typeId : (this.typeOptions[0] ? this.typeOptions[0].value : '')
        ,
        state: this.value && typeof this.value.state === 'boolean' ? this.value.state : true
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
      const payload = {
        _id: this.localForm._id,
        title: this.localForm.title.filter(item => String(item.value || '').trim()),
        description: this.localForm.description.filter(item => String(item.value || '').trim()),
        path: (this.localForm.path || '').trim(),
        typeId: this.localForm.typeId,
        state: this.localForm.state
      }

      if (!payload.title.length) {
        this.$emit('invalid', this.$t('security.formModal.menu.validationTitle'))
        return
      }
      if (!payload.path || !payload.path.startsWith('/')) {
        this.$emit('invalid', this.$t('security.formModal.menu.validationPath'))
        return
      }
      if (!payload.typeId) {
        this.$emit('invalid', this.$t('security.formModal.menu.validationType'))
        return
      }

      this.$emit('submit', payload)
    }
  }
}
</script>
