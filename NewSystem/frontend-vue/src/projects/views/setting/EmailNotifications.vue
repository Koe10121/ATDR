<template>
  <div class="security-page email-notification-page">
    <AppSectionHero
      :title="$t('setting.emailNotifications.title')"
      :subtitle="$t('setting.emailNotifications.subtitle')"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <CCard class="bg-style2 email-config-card">
      <CCardBody>
        <div class="email-config-card__header">
          <div class="email-config-card__title">
            <CIcon name="cil-envelope-closed" class="mr-2" />
            {{ $t('setting.emailNotifications.delivery.title') }}
          </div>
          <CSwitch color="success" :checked="deliveryForm.enabled" @update:checked="setDeliveryEnabled" />
        </div>

        <CRow>
          <CCol md="6" col="12">
            <CInput v-model.trim="deliveryForm.appName" :label="$t('setting.emailNotifications.delivery.appName')" placeholder="NewSystem" />
          </CCol>
          <CCol md="6" col="12">
            <CInput v-model.trim="deliveryForm.appUrl" :label="$t('setting.emailNotifications.delivery.appUrl')" placeholder="https://new-system.mfu.ac.th" />
          </CCol>
          <CCol md="6" col="12">
            <CInput v-model.trim="deliveryForm.fromName" :label="$t('setting.emailNotifications.delivery.fromName')" placeholder="NewSystem" />
          </CCol>
          <CCol md="6" col="12">
            <CInput v-model.trim="deliveryForm.from" :label="$t('setting.emailNotifications.delivery.from')" placeholder="no-reply@example.com" />
          </CCol>
          <CCol md="6" col="12">
            <CInput v-model.trim="deliveryForm.replyTo" :label="$t('setting.emailNotifications.delivery.replyTo')" placeholder="support@example.com" />
          </CCol>
        </CRow>

        <div class="email-config-card__section-title">{{ $t('setting.emailNotifications.delivery.smtp') }}</div>
        <CRow>
          <CCol md="5" col="12">
            <CInput v-model.trim="deliveryForm.smtp.host" :label="$t('setting.emailNotifications.delivery.host')" placeholder="smtp.gmail.com" />
          </CCol>
          <CCol md="2" col="12">
            <CInput v-model.number="deliveryForm.smtp.port" type="number" :label="$t('setting.emailNotifications.delivery.port')" />
          </CCol>
          <CCol md="5" col="12">
            <CInput v-model.trim="deliveryForm.smtp.user" :label="$t('setting.emailNotifications.delivery.user')" placeholder="mail@example.com" />
          </CCol>
          <CCol md="6" col="12">
            <CInput v-model="deliveryForm.smtp.pass" type="password" :label="passwordLabel" :placeholder="$t('setting.emailNotifications.delivery.passwordHint')" />
          </CCol>
          <CCol md="6" col="12" class="d-flex align-items-center pt-md-4">
            <CInputCheckbox custom :checked="deliveryForm.smtp.secure" :label="$t('setting.emailNotifications.delivery.secure')" @change="deliveryForm.smtp.secure = !deliveryForm.smtp.secure" />
          </CCol>
        </CRow>

        <div class="email-config-card__actions">
          <CButton color="success" variant="outline" class="email-config-actions__btn" :disabled="savingDelivery" @click="saveDelivery">
            <CIcon name="cil-save" class="mr-1" />
            {{ $t('setting.emailNotifications.delivery.save') }}
          </CButton>
        </div>
      </CCardBody>
    </CCard>

    <ManagementTableBase
      :title="$t('setting.emailNotifications.tableTitle')"
      icon="cil-description"
      :add-label="$t('setting.emailNotifications.add')"
      :empty-message="$t('setting.emailNotifications.empty')"
      :items="templateItems"
      :fields="templateFields"
      :items-per-page="25"
      :allow-add-override="true"
      :allow-delete-override="false"
      @add="openCreateTemplateModal"
      @edit="openTemplateModal"
    >
      <template #state="{ item }">
        <td class="text-center">
          <CBadge :color="badgeColor(item.statusMode)">
            {{ item.statusLabel }}
          </CBadge>
        </td>
      </template>
      <template #actions="{ item }">
        <td class="text-center email-template-actions">
          <CButton
            size="sm"
            color="info"
            variant="outline"
            shape="pill"
            class="setting-action-btn"
            @click="openTemplateModal(item)"
          >
            <CIcon name="cil-pencil" />
          </CButton>
          <CButton
            v-if="item.hasOverride"
            size="sm"
            color="danger"
            variant="outline"
            shape="pill"
            class="setting-remove-btn ml-2"
            @click="requestRemoveWorkflow(item)"
          >
            <CIcon name="cil-trash" />
          </CButton>
        </td>
      </template>
    </ManagementTableBase>

    <EmailNotificationTemplateModal
      :show.sync="showTemplateModal"
      :title="templateModalTitle"
      :value="templateDraft"
      :saving="saving"
      :placeholder-items="activePlaceholderItems"
      :preview-context="previewContext"
      :allow-metadata="templateMetadataEditable"
      @submit="saveTemplate"
      @invalid="handleInvalid"
      @cancel="closeTemplateModal"
    />
  </div>
</template>

<script>
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import ManagementTableBase from '@/projects/views/setting/components/ManagementTableBase'
import EmailNotificationTemplateModal from '@/projects/views/setting/components/EmailNotificationTemplateModal'
import Service from '@/service/api'
import { formatDateTime24 } from '@/projects/utils/date-time'
import { notifyError, notifySuccess, notifyWarning } from '@/projects/utils/notify'

const APP_CONTEXT = Object.freeze({
  appId: 'newSystem',
  appName: 'NewSystem',
  appUrl: 'https://new-system.mfu.ac.th'
})

const COMMON_PLACEHOLDERS = Object.freeze([
  'appId',
  'appName',
  'appUrl',
  'email',
  'firstName',
  'lastName',
  'fullName'
])

const DEFAULT_TEMPLATES = Object.freeze({
  invite: {
    subject: 'You have been invited to {appName}',
    text: 'Hello {fullName},\n\nYou have been invited to use {appName}.\nSign in with this email: {email}\n{appUrl}',
    html: '<p>Hello {fullName},</p><p>You have been invited to use <b>{appName}</b>.</p><p>Sign in with this email: <b>{email}</b></p><p><a href="{appUrl}">{appUrl}</a></p>'
  },
  twoFa: {
    subject: 'Your {appName} verification code',
    text: 'Your verification code is {code}. This code expires in {expiresMinutes} minutes.',
    html: '<p>Your verification code is <b>{code}</b>.</p><p>This code expires in {expiresMinutes} minutes.</p>'
  }
})

function emptyDraft () {
  return {
    key: '',
    eventKey: '',
    label: '',
    description: '',
    subject: '',
    text: '',
    html: '',
    status: 'active',
    placeholders: [],
    placeholdersText: '',
    hasOverride: false,
    hasWorkflowRecord: false,
    managed: false,
    definition: null,
    isNew: false
  }
}

function emptyDeliveryForm () {
  return {
    key: '',
    appId: APP_CONTEXT.appId,
    enabled: true,
    appName: APP_CONTEXT.appName,
    appUrl: '',
    from: '',
    fromName: APP_CONTEXT.appName,
    replyTo: '',
    smtp: {
      host: '',
      port: 587,
      secure: false,
      user: '',
      pass: '',
      hasPass: false
    }
  }
}

function getPayload (response) {
  return response && response.data ? response.data.data : null
}

function normalizeWorkflowStep (workflow) {
  if (!(workflow && Array.isArray(workflow.steps) && workflow.steps.length)) return null
  return workflow.steps[0]
}

function normalizeEventKey (value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9._:-]+/g, '').replace(/^\.+|\.+$/g, '')
}

function normalizePlaceholders (values) {
  const unique = new Set()
  ;(Array.isArray(values) ? values : []).forEach(item => {
    const normalized = String(item || '').trim()
    if (/^[a-zA-Z0-9_]+$/.test(normalized)) unique.add(normalized)
  })
  return Array.from(unique)
}

export default {
  name: 'EmailNotifications',
  components: { AppSectionHero, ManagementTableBase, EmailNotificationTemplateModal },
  data () {
    return {
      deliveryForm: emptyDeliveryForm(),
      savingDelivery: false,
      saving: false,
      showTemplateModal: false,
      templateDraft: emptyDraft(),
      lastUpdatedAt: null,
      workflowDefinitions: [],
      workflowRecords: []
    }
  },
  computed: {
    templateFields () {
      return [
        { key: 'label', label: this.$t('setting.emailNotifications.fields.template') },
        { key: 'channel', label: this.$t('setting.emailNotifications.fields.channel') },
        { key: 'sourceLabel', label: this.$t('setting.emailNotifications.fields.source') },
        { key: 'subject', label: this.$t('setting.emailNotifications.fields.subject') },
        { key: 'state', label: this.$t('setting.emailNotifications.fields.state'), _style: 'width: 180px; text-align: center;' },
        { key: 'actions', label: '#', _style: 'width: 140px; text-align:center;' }
      ]
    },
    activePlaceholderItems () {
      return (this.templateDraft.placeholders || []).map(key => ({
        key,
        token: `{${key}}`,
        label: this.placeholderLabel(key)
      }))
    },
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    passwordLabel () {
      return this.deliveryForm.smtp.hasPass ? this.$t('setting.emailNotifications.delivery.passwordConfigured') : this.$t('setting.emailNotifications.delivery.password')
    },
    previewContext () {
      return {
        appId: APP_CONTEXT.appId,
        appName: this.deliveryForm.appName || APP_CONTEXT.appName,
        appUrl: this.deliveryForm.appUrl || APP_CONTEXT.appUrl,
        email: 'user@example.com',
        firstName: 'Jane',
        lastName: 'Doe',
        fullName: 'Jane Doe',
        code: '123456',
        expiresMinutes: '5',
        invited: 'true',
        fromStatus: 'ACTIVE',
        toStatus: 'LOCKED',
        statusTitle: 'Locked',
        statusDescription: 'Account is locked by security policy.',
        changedBy: 'an administrator'
      }
    },
    templateItems () {
      return this.workflowDefinitions.map(definition => {
        const workflow = this.workflowForEvent(definition.eventKey)
        const step = normalizeWorkflowStep(workflow)
        const fallback = this.fallbackTemplate(definition)
        const statusMode = workflow
          ? (this.isWorkflowActive(workflow) ? 'active' : 'inactive')
          : 'inherited'

        return {
          key: definition.eventKey,
          eventKey: definition.eventKey,
          label: this.labelForDefinition(definition),
          channel: this.channelForDefinition(definition),
          sourceLabel: workflow && workflow.managed !== true
            ? this.$t('setting.emailNotifications.sources.override')
            : this.$t('setting.emailNotifications.sources.default'),
          subject: step && step.template && step.template.subject ? step.template.subject : (fallback.subject || '-'),
          text: step && step.template ? step.template.text || '' : fallback.text || '',
          html: step && step.template ? step.template.html || '' : fallback.html || '',
          statusMode,
          statusLabel: this.statusLabel(statusMode),
          placeholders: Array.isArray(definition.placeholders) ? definition.placeholders : [],
          hasOverride: !!(workflow && workflow.managed !== true),
          hasWorkflowRecord: !!workflow,
          managed: !!(workflow && workflow.managed === true),
          definition,
          workflow
        }
      })
    },
    templateModalTitle () {
      if (this.templateDraft && this.templateDraft.isNew) return this.$t('setting.emailNotifications.form.createTitle')
      return this.templateDraft && this.templateDraft.label
        ? `${this.$t('common.actions.edit')} ${this.templateDraft.label}`
        : this.$t('setting.emailNotifications.form.editTitle')
    },
    templateMetadataEditable () {
      return !!(this.templateDraft && (this.templateDraft.isNew || (this.templateDraft.definition && this.templateDraft.definition.custom)))
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    normalizeDelivery (payload) {
      const base = emptyDeliveryForm()
      const data = Object.assign({}, base, payload || {})
      data.smtp = Object.assign({}, base.smtp, payload && payload.smtp ? payload.smtp : {})
      data.appId = APP_CONTEXT.appId
      data.smtp.pass = data.smtp.hasPass ? '********' : ''
      return data
    },
    setDeliveryEnabled (value) {
      this.deliveryForm.enabled = !!value
    },
    badgeColor (statusMode) {
      if (statusMode === 'active') return 'success'
      if (statusMode === 'inactive') return 'secondary'
      return 'info'
    },
    statusLabel (statusMode) {
      if (statusMode === 'active') return this.$t('common.status.active')
      if (statusMode === 'inactive') return this.$t('common.status.inactive')
      return this.$t('setting.emailNotifications.sources.inherited')
    },
    placeholderLabel (key) {
      const known = {
        appId: this.$t('setting.emailNotifications.placeholders.appId'),
        appName: this.$t('setting.emailNotifications.placeholders.appName'),
        appUrl: this.$t('setting.emailNotifications.placeholders.appUrl'),
        email: this.$t('setting.emailNotifications.placeholders.email'),
        firstName: this.$t('setting.emailNotifications.placeholders.firstName'),
        lastName: this.$t('setting.emailNotifications.placeholders.lastName'),
        fullName: this.$t('setting.emailNotifications.placeholders.fullName'),
        code: this.$t('setting.emailNotifications.placeholders.code'),
        expiresMinutes: this.$t('setting.emailNotifications.placeholders.expiresMinutes'),
        invited: this.$t('setting.emailNotifications.placeholders.invited'),
        fromStatus: this.$t('setting.emailNotifications.placeholders.fromStatus'),
        toStatus: this.$t('setting.emailNotifications.placeholders.toStatus'),
        statusTitle: this.$t('setting.emailNotifications.placeholders.statusTitle'),
        statusDescription: this.$t('setting.emailNotifications.placeholders.statusDescription'),
        groupCount: this.$t('setting.emailNotifications.placeholders.groupCount'),
        currentGroups: this.$t('setting.emailNotifications.placeholders.currentGroups'),
        addedGroups: this.$t('setting.emailNotifications.placeholders.addedGroups'),
        removedGroups: this.$t('setting.emailNotifications.placeholders.removedGroups'),
        changedBy: this.$t('setting.emailNotifications.placeholders.changedBy'),
        targetStatus: this.$t('setting.emailNotifications.placeholders.targetStatus'),
        provisioningState: this.$t('setting.emailNotifications.placeholders.provisioningState'),
        provisioningStrategy: this.$t('setting.emailNotifications.placeholders.provisioningStrategy'),
        recommendedProfiles: this.$t('setting.emailNotifications.placeholders.recommendedProfiles'),
        matchedRuleCount: this.$t('setting.emailNotifications.placeholders.matchedRuleCount'),
        warningCount: this.$t('setting.emailNotifications.placeholders.warningCount'),
        deprovisionReason: this.$t('setting.emailNotifications.placeholders.deprovisionReason'),
        revokeSessions: this.$t('setting.emailNotifications.placeholders.revokeSessions'),
        clearTrustedDevices: this.$t('setting.emailNotifications.placeholders.clearTrustedDevices'),
        triggeredBy: this.$t('setting.emailNotifications.placeholders.triggeredBy'),
        sessionCount: this.$t('setting.emailNotifications.placeholders.sessionCount'),
        deviceIds: this.$t('setting.emailNotifications.placeholders.deviceIds'),
        currentSessionIncluded: this.$t('setting.emailNotifications.placeholders.currentSessionIncluded'),
        clearedBy: this.$t('setting.emailNotifications.placeholders.clearedBy'),
        sessionId: this.$t('setting.emailNotifications.placeholders.sessionId'),
        deviceId: this.$t('setting.emailNotifications.placeholders.deviceId'),
        clientId: this.$t('setting.emailNotifications.placeholders.clientId'),
        audience: this.$t('setting.emailNotifications.placeholders.audience'),
        system: this.$t('setting.emailNotifications.placeholders.system'),
        userAgent: this.$t('setting.emailNotifications.placeholders.userAgent'),
        lastIp: this.$t('setting.emailNotifications.placeholders.lastIp'),
        trustedAt: this.$t('setting.emailNotifications.placeholders.trustedAt'),
        expiresAt: this.$t('setting.emailNotifications.placeholders.expiresAt'),
        revokedBy: this.$t('setting.emailNotifications.placeholders.revokedBy')
      }
      return known[key] || key
    },
    labelForDefinition (definition) {
      if (definition && definition.legacyType === 'invite') return this.$t('setting.emailNotifications.templates.invite')
      if (definition && definition.legacyType === 'twoFa') return this.$t('setting.emailNotifications.templates.twoFa')
      if (definition && definition.eventKey === 'account.locked') return this.$t('setting.emailNotifications.templates.locked')
      if (definition && definition.eventKey === 'account.unlocked') return this.$t('setting.emailNotifications.templates.unlocked')
      if (definition && definition.eventKey === 'account.activated') return this.$t('setting.emailNotifications.templates.activated')
      if (definition && definition.eventKey === 'account.deactivated') return this.$t('setting.emailNotifications.templates.deactivated')
      if (definition && definition.eventKey === 'account.suspended') return this.$t('setting.emailNotifications.templates.suspended')
      if (definition && definition.eventKey === 'account.archived') return this.$t('setting.emailNotifications.templates.archived')
      if (definition && definition.eventKey === 'account.status.changed') return this.$t('setting.emailNotifications.templates.statusChanged')
      if (definition && definition.eventKey === 'account.access.changed') return this.$t('setting.emailNotifications.templates.accessChanged')
      if (definition && definition.eventKey === 'account.provisioned') return this.$t('setting.emailNotifications.templates.provisioned')
      if (definition && definition.eventKey === 'account.deprovisioned') return this.$t('setting.emailNotifications.templates.deprovisioned')
      if (definition && definition.eventKey === 'auth.sessions.cleared') return this.$t('setting.emailNotifications.templates.sessionsCleared')
      if (definition && definition.eventKey === 'auth.trusted-device.added') return this.$t('setting.emailNotifications.templates.trustedDeviceAdded')
      if (definition && definition.eventKey === 'auth.session.revoked') return this.$t('setting.emailNotifications.templates.sessionRevoked')
      if (definition && definition.eventKey === 'auth.trusted-device.revoked') return this.$t('setting.emailNotifications.templates.trustedDeviceRevoked')
      return definition && definition.title ? definition.title : (definition && definition.eventKey ? definition.eventKey : '-')
    },
    channelForDefinition (definition) {
      if (definition && definition.legacyType === 'invite') return this.$t('setting.emailNotifications.templates.inviteChannel')
      if (definition && definition.legacyType === 'twoFa') return this.$t('setting.emailNotifications.templates.twoFaChannel')
      if (definition && definition.eventKey === 'account.locked') return this.$t('setting.emailNotifications.templates.lockedChannel')
      if (definition && definition.eventKey === 'account.unlocked') return this.$t('setting.emailNotifications.templates.unlockedChannel')
      if (definition && definition.eventKey === 'account.activated') return this.$t('setting.emailNotifications.templates.activatedChannel')
      if (definition && definition.eventKey === 'account.deactivated') return this.$t('setting.emailNotifications.templates.deactivatedChannel')
      if (definition && definition.eventKey === 'account.suspended') return this.$t('setting.emailNotifications.templates.suspendedChannel')
      if (definition && definition.eventKey === 'account.archived') return this.$t('setting.emailNotifications.templates.archivedChannel')
      if (definition && definition.eventKey === 'account.status.changed') return this.$t('setting.emailNotifications.templates.statusChangedChannel')
      if (definition && definition.eventKey === 'account.access.changed') return this.$t('setting.emailNotifications.templates.accessChangedChannel')
      if (definition && definition.eventKey === 'account.provisioned') return this.$t('setting.emailNotifications.templates.provisionedChannel')
      if (definition && definition.eventKey === 'account.deprovisioned') return this.$t('setting.emailNotifications.templates.deprovisionedChannel')
      if (definition && definition.eventKey === 'auth.sessions.cleared') return this.$t('setting.emailNotifications.templates.sessionsClearedChannel')
      if (definition && definition.eventKey === 'auth.trusted-device.added') return this.$t('setting.emailNotifications.templates.trustedDeviceAddedChannel')
      if (definition && definition.eventKey === 'auth.session.revoked') return this.$t('setting.emailNotifications.templates.sessionRevokedChannel')
      if (definition && definition.eventKey === 'auth.trusted-device.revoked') return this.$t('setting.emailNotifications.templates.trustedDeviceRevokedChannel')
      return definition && definition.description ? definition.description : ''
    },
    fallbackTemplate (definition) {
      const legacyType = definition && definition.legacyType ? String(definition.legacyType) : ''
      const definitionDefault = definition && definition.defaultTemplate ? definition.defaultTemplate : {}
      if (legacyType === 'invite') return Object.assign({}, DEFAULT_TEMPLATES.invite, definitionDefault)
      if (legacyType === 'twoFa') return Object.assign({}, DEFAULT_TEMPLATES.twoFa, definitionDefault)
      return Object.assign({ subject: '', text: '', html: '' }, definitionDefault)
    },
    workflowForEvent (eventKey) {
      return (this.workflowRecords || []).find(item => item && item.eventKey === eventKey) || null
    },
    isWorkflowActive (workflow) {
      const step = normalizeWorkflowStep(workflow)
      if (!(workflow && step)) return false
      return workflow.enabled !== false && step.enabled !== false
    },
    async loadDefinitions () {
      const response = await Service.settings('email-workflow-definitions', { appId: APP_CONTEXT.appId })
      this.workflowDefinitions = Array.isArray(getPayload(response)) ? getPayload(response) : []
    },
    async loadDelivery () {
      const response = await Service.settings('email-delivery', { appId: APP_CONTEXT.appId })
      this.deliveryForm = this.normalizeDelivery(getPayload(response))
    },
    async loadWorkflows () {
      const response = await Service.settings('email-workflows', { appId: APP_CONTEXT.appId })
      this.workflowRecords = Array.isArray(getPayload(response)) ? getPayload(response) : []
    },
    async loadData () {
      try {
        await Promise.all([
          this.loadDelivery(),
          this.loadDefinitions(),
          this.loadWorkflows()
        ])
        this.lastUpdatedAt = new Date()
      } catch (err) {
        notifyError(this.$store, this.$t('setting.emailNotifications.messages.loadError'))
      }
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    async saveDelivery () {
      this.savingDelivery = true
      try {
        const payload = JSON.parse(JSON.stringify(this.deliveryForm))
        payload.appId = APP_CONTEXT.appId
        if (!payload.smtp.pass || payload.smtp.pass === '********') delete payload.smtp.pass
        const response = await Service.settings('update-email-delivery', payload)
        this.deliveryForm = this.normalizeDelivery(getPayload(response))
        this.lastUpdatedAt = new Date()
        notifySuccess(this.$store, this.$t('setting.emailNotifications.messages.saved'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.emailNotifications.messages.saveError'))
      } finally {
        this.savingDelivery = false
      }
    },
    openTemplateModal (item) {
      const workflow = item && item.workflow ? item.workflow : null
      const step = normalizeWorkflowStep(workflow)
      const fallback = item && item.definition ? this.fallbackTemplate(item.definition) : { subject: '', text: '', html: '' }
      this.templateDraft = {
        key: item && item.eventKey ? String(item.eventKey) : '',
        eventKey: item && item.eventKey ? String(item.eventKey) : '',
        label: item && item.label ? String(item.label) : '',
        description: item && item.definition && item.definition.description ? String(item.definition.description) : '',
        subject: step && step.template && step.template.subject ? String(step.template.subject) : String(fallback.subject || ''),
        text: step && step.template && step.template.text ? String(step.template.text) : String(fallback.text || ''),
        html: step && step.template && step.template.html ? String(step.template.html) : String(fallback.html || ''),
        status: item && item.statusMode === 'inactive' ? 'inactive' : 'active',
        placeholders: item && Array.isArray(item.placeholders) ? item.placeholders.slice() : [],
        hasOverride: !!(item && item.hasOverride),
        hasWorkflowRecord: !!(item && item.hasWorkflowRecord),
        managed: !!(item && item.managed),
        definition: item && item.definition ? item.definition : null,
        isNew: false
      }
      this.showTemplateModal = true
    },
    openCreateTemplateModal () {
      this.templateDraft = Object.assign(emptyDraft(), {
        status: 'active',
        placeholders: COMMON_PLACEHOLDERS.slice(),
        placeholdersText: '',
        isNew: true
      })
      this.showTemplateModal = true
    },
    closeTemplateModal () {
      this.showTemplateModal = false
      this.templateDraft = emptyDraft()
    },
    buildWorkflowPayload (draft) {
      const definition = draft && draft.definition ? draft.definition : {}
      const eventKey = normalizeEventKey(draft && (draft.eventKey || draft.key))
      const isCustom = !!(draft && (draft.isNew || definition.custom))
      return {
        appId: APP_CONTEXT.appId,
        eventKey,
        title: isCustom ? String(draft && draft.label ? draft.label : eventKey).trim() : this.labelForDefinition(definition),
        description: isCustom
          ? String(draft && draft.description ? draft.description : '').trim()
          : (definition && definition.description ? definition.description : ''),
        enabled: true,
        placeholders: normalizePlaceholders(draft && draft.placeholders),
        managed: false,
        steps: [
          {
            key: 'primary',
            type: 'email',
            enabled: draft && draft.status === 'active',
            recipient: {
              mode: 'request',
              value: ''
            },
            template: {
              subject: draft && draft.subject ? draft.subject : '',
              text: draft && draft.text ? draft.text : '',
              html: draft && draft.html ? draft.html : ''
            }
          }
        ]
      }
    },
    async saveTemplate (draft) {
      if (!(draft && normalizeEventKey(draft.eventKey || draft.key))) return
      this.saving = true
      try {
        const payload = this.buildWorkflowPayload(draft)
        if (draft.hasWorkflowRecord) {
          await Service.settings('update-email-workflow', payload)
        } else {
          await Service.settings('create-email-workflow', payload)
        }
        await Promise.all([
          this.loadDefinitions(),
          this.loadWorkflows()
        ])
        this.lastUpdatedAt = new Date()
        notifySuccess(this.$store, this.$t('setting.emailNotifications.messages.workflowSaved'))
        this.closeTemplateModal()
      } catch (err) {
        notifyError(this.$store, this.$t('setting.emailNotifications.messages.workflowSaveError'))
      } finally {
        this.saving = false
      }
    },
    requestRemoveWorkflow (item) {
      if (!(item && item.eventKey && item.hasOverride)) return Promise.resolve(false)
      return this.$store.dispatch('dialog/openConfirm', {
        title: this.$t('setting.emailNotifications.messages.removeConfirmTitle'),
        message: this.$t('setting.emailNotifications.messages.removeConfirmMessage', { template: item.label }),
        confirmText: this.$t('common.actions.remove'),
        confirmIcon: 'cil-trash'
      }).then(confirmed => {
        if (!confirmed) return false
        return this.confirmRemoveWorkflow(item)
      })
    },
    async confirmRemoveWorkflow (item) {
      this.saving = true
      try {
        await Service.settings('delete-email-workflow', {
          appId: APP_CONTEXT.appId,
          eventKey: item.eventKey
        })
        await Promise.all([
          this.loadDefinitions(),
          this.loadWorkflows()
        ])
        this.lastUpdatedAt = new Date()
        notifySuccess(this.$store, this.$t('setting.emailNotifications.messages.workflowRemoved'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.emailNotifications.messages.workflowRemoveError'))
      } finally {
        this.saving = false
      }
    }
  }
}
</script>

<style scoped lang="scss">
@import "./components/setting-page.shared";

:deep(.email-template-actions .setting-action-btn),
:deep(.email-template-actions .setting-remove-btn) {
  width: 2.15rem;
  height: 2.15rem;
  padding: 0;
  border-radius: 999px !important;
  background-color: #fff !important;
}

.email-config-card {
  border: 1px solid rgba(223, 230, 238, 0.78);
  border-radius: 0.5rem;
  box-shadow: 0 14px 30px rgba(44, 52, 71, 0.06);
  margin-bottom: 1rem;
}

.email-config-card__header,
.email-config-card__actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.email-config-card__header {
  border-bottom: 1px solid rgba(221, 228, 236, 0.85);
  margin-bottom: 1rem;
  padding-bottom: 0.85rem;
}

.email-config-card__title,
.email-config-card__section-title {
  color: #233247;
  font-weight: 700;
}

.email-config-card__title .c-icon,
.email-config-card__title svg {
  color: #8c1515;
}

.email-config-card__section-title {
  font-size: 0.86rem;
  margin: 0.25rem 0 0.9rem;
}

.email-config-card__actions {
  justify-content: flex-end;
}

.email-config-actions__btn {
  border-radius: 999px;
  font-weight: 700;
  min-width: 120px;
}

@media (max-width: 767px) {
  .email-config-card__actions {
    align-items: stretch;
    flex-direction: column;
  }

  .email-config-actions__btn {
    width: 100%;
  }
}
</style>
