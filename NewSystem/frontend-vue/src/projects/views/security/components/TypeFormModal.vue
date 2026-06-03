<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal" add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">
          {{ isEditMode ? $t('security.formModal.type.editHint') : $t('security.formModal.type.createHint') }}
        </div>
      </div>
    </div>

    <ModalLanguageToolbar :languages="languages" :active-tab="activeLanguageTab" :active-lang="activeLang" :label-resolver="langLabel" @update:activeTab="activeLanguageTab = $event" />

    <CRow>
      <CCol md="7" col="12" class="mb-3">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title">{{ $t('common.sections.content') }}</h5>
            <CPInput v-model.trim="activeTitle" :label="$t('security.createMenu.fields.typeTitle')" :required="true" placeholder="" />
            <CPQuillEditor v-model="activeDescription" :label="$t('common.description')" placeholder="" />
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="5" col="12" class="mb-3">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title">{{ $t('common.sections.settings') }}</h5>
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
import AuditInfoCard from '@/projects/views/setting/components/AuditInfoCard'
import {
  getLanguages,
  getValueByLang,
  langLabel,
  normalizeOrDefault,
  setValueByLang
} from './security-multilang.shared'

export default {
  name: 'TypeFormModal',
  components: { CPInput, CPSelect, CPQuillEditor, ModalLanguageToolbar, AuditInfoCard },
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: '' },
    value: {
      type: Object,
      default: () => ({ _id: null, name: '', title: [] })
    }
  },
  data () {
    return {
      localTitleItems: normalizeOrDefault([]),
      localDescriptionItems: normalizeOrDefault([]),
      activeLang: 'th',
      localState: true,
      stateOptions: [
        { value: 'active', label: this.$t('common.status.active') },
        { value: 'inactive', label: this.$t('common.status.inactive') }
      ]
    }
  },
  computed: {
    isEditMode () {
      return !!(this.value && this.value._id)
    },
    submitLabel () {
      return this.isEditMode ? this.$t('common.actions.update') : this.$t('common.actions.save')
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
    stateSelected: {
      get () {
        return this.localState ? this.stateOptions[0] : this.stateOptions[1]
      },
      set (option) {
        this.localState = !option || option.value !== 'inactive'
      }
    },
    languages () {
      return getLanguages(this.localTitleItems)
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
        return getValueByLang(this.localTitleItems, this.activeLang)
      },
      set (value) {
        setValueByLang(this.localTitleItems, this.activeLang, value)
      }
    },
    activeDescription: {
      get () {
        return getValueByLang(this.localDescriptionItems, this.activeLang)
      },
      set (value) {
        setValueByLang(this.localDescriptionItems, this.activeLang, value)
      }
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (value) this.resetForm()
      }
    }
  },
  methods: {
    langLabel,
    resetForm () {
      this.localTitleItems = normalizeOrDefault(this.value && this.value.title ? this.value.title : [])
      this.localDescriptionItems = normalizeOrDefault(this.value && this.value.description ? this.value.description : [])
      this.localState = this.value && typeof this.value.state === 'boolean' ? this.value.state : true
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
      const title = this.localTitleItems.filter(item => String(item.value || '').trim())
      const description = this.localDescriptionItems.filter(item => String(item.value || '').trim())
      if (!title.length) {
        this.$emit('invalid', this.$t('security.formModal.type.validationTitle'))
        return
      }
      this.$emit('submit', { _id: this.value ? this.value._id : null, title, description, state: this.localState })
    }
  }
}
</script>
