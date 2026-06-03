<template>
  <CModal :show="show" @update:show="onShowChange" size="xl" class="login-message-modal" add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="message-modal__header mb-4">
      <div class="message-modal__hero">
        <label class="h4 mb-1">{{ title }}</label>
        <div class="text-muted">{{ $t('setting.emailNotifications.form.editHint') }}</div>
      </div>
    </div>

    <CRow>
      <CCol col="12">
        <CCard class="bg-style2 panel-card mb-3">
          <CCardBody>
            <div class="placeholder-panel__title">
              <CIcon name="cil-list" class="mr-2" />
              {{ $t('setting.emailNotifications.placeholders.title') }}
            </div>
            <div class="placeholder-panel__items">
              <div v-for="item in visiblePlaceholderItems" :key="item.key" class="placeholder-panel__item">
                <code>{{ item.token }}</code>
                <span>{{ item.label }}</span>
              </div>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="7" col="12">
        <CCard class="bg-style2 h-100 panel-card content-panel-card">
          <CCardBody class="content-panel-body">
            <h5 class="mb-3 panel-title"><CIcon name="cil-description" class="mr-2" />{{ $t('common.sections.content') }}</h5>
            <div v-if="allowMetadata" class="email-metadata-fields">
              <CRow>
                <CCol md="6" col="12">
                  <label class="metadata-field-label required">{{ $t('setting.emailNotifications.form.fields.eventKey') }}</label>
                  <CInput v-model.trim="local.key" :readonly="metadataKeyReadonly" placeholder="newSystem.expiring" />
                </CCol>
                <CCol md="6" col="12">
                  <label class="metadata-field-label required">{{ $t('setting.emailNotifications.form.fields.templateName') }}</label>
                  <CInput v-model.trim="local.label" placeholder="NewSystem expiring" />
                </CCol>
                <CCol md="12" col="12">
                  <label class="metadata-field-label">{{ $t('setting.emailNotifications.form.fields.description') }}</label>
                  <CInput v-model.trim="local.description" placeholder="When an NewSystem enters the renewal window" />
                </CCol>
                <CCol md="12" col="12">
                  <label class="metadata-field-label">{{ $t('setting.emailNotifications.form.fields.placeholders') }}</label>
                  <CInput v-model.trim="local.placeholdersText" placeholder="newSystemNo, partnerName, expiryDate" />
                </CCol>
              </CRow>
            </div>
            <CPSelect
              v-model="local.status"
              :options="statusOptions"
              :label="$t('setting.emailNotifications.fields.state')"
              icon="cil-check-circle"
              primitive
              :close-on-select="true"
              :searchable="false"
              :allow-empty="false"
            />
            <CPInput v-model="local.subject" :label="$t('setting.emailNotifications.fields.subject')" :required="true" placeholder="" />
            <label class="metadata-field-label email-editor-label">{{ $t('setting.emailNotifications.form.fields.text') }}</label>
            <CkEditorCustom v-model="local.text" :hide-label="true" />
          </CCardBody>
        </CCard>
      </CCol>
      <CCol md="5" col="12">
        <CCard class="bg-style2 h-100 panel-card">
          <CCardBody>
            <h5 class="mb-3 panel-title"><CIcon name="cil-code" class="mr-2" />{{ $t('setting.emailNotifications.form.htmlPreview') }}</h5>
            <div class="email-preview">
              <iframe class="email-preview__frame email-preview__frame--modal" title="Email HTML preview" sandbox="" :srcdoc="activePreviewHtml"></iframe>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

    <div class="modal-footer-wrap d-flex w-100 justify-content-end mt-3">
      <CButton class="mr-2 footer-btn-cancel footer-action-btn" color="danger" variant="outline" shape="pill" @click="onCancel">
        <CIcon name="cil-ban" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1">{{ $t('common.actions.cancel') }}</span>
      </CButton>
      <CButton color="success" shape="pill" class="footer-btn-save footer-action-btn" :disabled="saving || !canSubmit" @click="onSubmit">
        <CIcon name="cil-save" class="mr-1 action-icon" />
        <span class="font-weight-bold pr-1 pl-1">{{ allowMetadata ? $t('common.actions.save') : $t('common.actions.update') }}</span>
      </CButton>
    </div>
    <template #footer-wrapper><div></div></template>
  </CModal>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'
import CPSelect from '@/projects/components/custom/CPSelect'
import CkEditorCustom from '@/projects/components/custom/CkEditorCustom'

function emptyDraft () {
  return { key: '', label: '', description: '', subject: '', text: '', html: '', status: 'inactive', placeholders: [], placeholdersText: '' }
}

function normalizeEventKey (value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9._:-]+/g, '').replace(/^\.+|\.+$/g, '')
}

function normalizePlaceholderName (value) {
  const cleaned = String(value || '').trim()
  return /^[a-zA-Z0-9_]+$/.test(cleaned) ? cleaned : ''
}

function parsePlaceholders (value) {
  const unique = new Set()
  String(value || '').split(/[\s,]+/).forEach(item => {
    const normalized = normalizePlaceholderName(item)
    if (normalized) unique.add(normalized)
  })
  return Array.from(unique)
}

export default {
  name: 'EmailNotificationTemplateModal',
  components: { CPInput, CPSelect, CkEditorCustom },
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: '' },
    value: { type: Object, default: () => emptyDraft() },
    saving: { type: Boolean, default: false },
    placeholderItems: { type: Array, default: () => [] },
    previewContext: { type: Object, default: () => ({}) },
    previewHtml: { type: String, default: '' },
    useExternalPreview: { type: Boolean, default: false },
    previewDelay: { type: Number, default: 100 },
    emitPreviewState: { type: Boolean, default: true },
    previewStateDelay: { type: Number, default: null },
    allowMetadata: { type: Boolean, default: false }
  },
  data () {
    return {
      local: emptyDraft(),
      internalPreviewHtml: '',
      previewTimer: null,
      previewSourceTimer: null
    }
  },
  computed: {
    canSubmit () {
      const subjectReady = String(this.local.subject || '').trim().length > 0
      if (!this.allowMetadata) return !!(this.local.key && subjectReady)
      return !!(normalizeEventKey(this.local.key) && String(this.local.label || '').trim() && subjectReady)
    },
    generatedHtml () {
      return String(this.local.text || '')
    },
    visiblePlaceholderItems () {
      const map = new Map()
      ;(Array.isArray(this.placeholderItems) ? this.placeholderItems : []).forEach(item => {
        if (!(item && item.key)) return
        map.set(item.key, item)
      })
      if (this.allowMetadata) {
        parsePlaceholders(this.local.placeholdersText).forEach(key => {
          if (!map.has(key)) {
            map.set(key, {
              key,
              token: `{${key}}`,
              label: key
            })
          }
        })
      }
      return Array.from(map.values())
    },
    metadataKeyReadonly () {
      return !!(this.allowMetadata && this.value && this.value.isNew === false)
    },
    activePreviewHtml () {
      return this.useExternalPreview ? this.previewHtml : this.internalPreviewHtml
    },
    statusOptions () {
      return [
        { value: 'active', label: this.$t('common.status.active') },
        { value: 'inactive', label: this.$t('common.status.inactive') }
      ]
    },
    previewDebounceDelay () {
      return Math.max(0, Number(this.previewDelay) || 0)
    },
    previewStateDebounceDelay () {
      if (this.previewStateDelay === null || this.previewStateDelay === undefined) return this.previewDebounceDelay
      return Math.max(0, Number(this.previewStateDelay) || 0)
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (value) this.resetLocal()
      }
    },
    value: {
      deep: true,
      handler () {
        if (this.show) this.resetLocal()
      }
    },
    'local.text' () {
      this.schedulePreviewSourceChange()
      if (this.useExternalPreview) return
      this.schedulePreviewUpdate()
    },
    previewContext: {
      deep: true,
      handler () {
        this.schedulePreviewSourceChange()
        if (this.useExternalPreview) return
        this.schedulePreviewUpdate()
      }
    },
    useExternalPreview (value) {
      if (!value) this.updatePreviewHtml()
    }
  },
  beforeDestroy () {
    this.clearPreviewTimer()
    this.clearPreviewSourceTimer()
  },
  methods: {
    resetLocal () {
      const body = this.value && (this.value.html || this.value.text) ? String(this.value.html || this.value.text) : ''
      this.local = {
        key: this.value && this.value.key ? String(this.value.key) : '',
        label: this.value && this.value.label ? String(this.value.label) : '',
        description: this.value && this.value.description ? String(this.value.description) : '',
        subject: this.value && this.value.subject ? String(this.value.subject) : '',
        text: body,
        html: body,
        status: this.value && this.value.status === 'active' ? 'active' : 'inactive',
        placeholders: this.value && Array.isArray(this.value.placeholders) ? this.value.placeholders.slice() : [],
        placeholdersText: this.value && Object.prototype.hasOwnProperty.call(this.value, 'placeholdersText')
          ? String(this.value.placeholdersText)
          : (this.value && Array.isArray(this.value.placeholders) ? this.value.placeholders.join(', ') : '')
      }
      this.emitPreviewSourceChange()
      if (!this.useExternalPreview) this.updatePreviewHtml()
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
      if (!this.canSubmit) {
        this.$emit('invalid', this.$t(this.allowMetadata ? 'setting.emailNotifications.form.validation.customTemplate' : 'setting.emailNotifications.form.validation.subject'))
        return
      }
      const eventKey = normalizeEventKey(this.local.key)
      const placeholders = parsePlaceholders(this.local.placeholdersText)
      this.$emit('submit', Object.assign({}, this.local, {
        key: eventKey,
        eventKey: eventKey,
        label: String(this.local.label || '').trim(),
        description: String(this.local.description || '').trim(),
        placeholders,
        text: this.generatedHtml,
        html: this.generatedHtml,
        status: this.local.status === 'active' ? 'active' : 'inactive'
      }))
    },
    renderTemplate (template, context) {
      return String(template || '').replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) => {
        return Object.prototype.hasOwnProperty.call(context || {}, key) ? String(context[key]) : ''
      })
    },
    schedulePreviewUpdate () {
      this.clearPreviewTimer()
      this.previewTimer = window.setTimeout(() => {
        this.updatePreviewHtml()
      }, this.previewDebounceDelay)
    },
    schedulePreviewSourceChange () {
      this.clearPreviewSourceTimer()
      this.previewSourceTimer = window.setTimeout(() => {
        this.emitPreviewSourceChange()
      }, this.previewStateDebounceDelay)
    },
    clearPreviewTimer () {
      if (!this.previewTimer) return
      window.clearTimeout(this.previewTimer)
      this.previewTimer = null
    },
    clearPreviewSourceTimer () {
      if (!this.previewSourceTimer) return
      window.clearTimeout(this.previewSourceTimer)
      this.previewSourceTimer = null
    },
    emitPreviewSourceChange () {
      this.clearPreviewSourceTimer()
      if (!this.emitPreviewState) return
      this.$emit('preview-source-change', {
        html: this.generatedHtml,
        context: this.previewContext
      })
    },
    updatePreviewHtml () {
      this.clearPreviewTimer()
      this.internalPreviewHtml = this.buildPreviewDocument(this.renderTemplate(this.generatedHtml, this.previewContext))
    },
    buildPreviewDocument (html) {
      return [
        '<!doctype html>',
        '<html>',
        '<head>',
        '<meta charset="utf-8">',
        '<style>',
        'body{margin:0;padding:16px;font-family:Arial,sans-serif;color:#243447;background:#fff;font-size:14px;line-height:1.45;}',
        'a{color:#0d6efd;}',
        'p{margin:0 0 12px;}',
        '</style>',
        '</head>',
        '<body>',
        html || '<span style="color:#7b8798">No HTML body.</span>',
        '</body>',
        '</html>'
      ].join('')
    }
  }
}
</script>

<style scoped lang="scss">
.email-preview {
  border: 1px solid rgba(223, 230, 238, 0.9);
  border-radius: 0.75rem;
  overflow: hidden;
}

.email-preview__frame {
  border: 0;
  display: block;
  height: 320px;
  width: 100%;
}

.placeholder-panel__title {
  display: flex;
  align-items: center;
  color: #233247;
  font-size: 0.88rem;
  font-weight: 700;
  margin-bottom: 0.75rem;
}

.placeholder-panel__items {
  display: grid;
  gap: 0.55rem;
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.placeholder-panel__item {
  border: 1px solid #e2e8f0;
  border-radius: 0.65rem;
  background: #f8fafc;
  min-height: 58px;
  padding: 0.55rem 0.65rem;
}

.placeholder-panel__item code {
  color: #8c1515;
  display: block;
  font-size: 0.78rem;
  font-weight: 700;
  margin-bottom: 0.25rem;
  white-space: nowrap;
}

.placeholder-panel__item span {
  color: #5f6f86;
  display: block;
  font-size: 0.74rem;
  font-weight: 600;
  line-height: 1.25;
}

.email-metadata-fields {
  border-bottom: 1px solid rgba(223, 230, 238, 0.9);
  margin-bottom: 1rem;
  padding-bottom: 0.25rem;
}

.metadata-field-label {
  color: #334155;
  display: block;
  font-size: 0.78rem;
  font-weight: 700;
  margin-bottom: 0.35rem;
}

.metadata-field-label.required::after {
  color: #e55353;
  content: " *";
}

.email-editor-label {
  margin-top: 0.2rem;
}

@media (max-width: 767.98px) {
  .placeholder-panel__items {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
