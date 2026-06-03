<template>
  <div class="security-page workflow-actions-page">
    <AppSectionHero
      :title="$t('setting.workflowActions.title')"
      :subtitle="$t('setting.workflowActions.subtitle')"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <CRow>
      <CCol lg="5" col="12">
        <CCard class="bg-style2 workflow-actions-card">
          <CCardBody>
            <div class="workflow-actions-card__title">
              <CIcon name="cil-list" class="mr-2" />
              {{ $t('setting.workflowActions.eventsTitle') }}
            </div>

            <div class="workflow-action-list">
              <button
                v-for="item in actionItems"
                :key="item.eventKey"
                type="button"
                class="workflow-action-list__item"
                :class="{ active: item.eventKey === selectedEventKey }"
                @click="selectAction(item)"
              >
                <span>
                  <strong>{{ item.label }}</strong>
                  <small>{{ item.eventKey }}</small>
                </span>
                <CBadge :color="item.enabled ? 'success' : 'secondary'">
                  {{ item.enabled ? $t('common.status.active') : $t('common.status.inactive') }}
                </CBadge>
              </button>
            </div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol lg="7" col="12">
        <CCard class="bg-style2 workflow-actions-card">
          <CCardBody>
            <div class="workflow-actions-card__header">
              <div>
                <div class="workflow-actions-card__title">
                  <CIcon name="cil-bolt" class="mr-2" />
                  {{ selectedLabel }}
                </div>
                <div class="workflow-actions-card__hint">{{ selectedEventKey || '-' }}</div>
              </div>
              <CSwitch color="success" :checked="actionForm.workflowEnabled" @update:checked="setWorkflowEnabled" />
            </div>

            <CRow>
              <CCol md="6" col="12">
                <CSelect
                  v-model="actionForm.actionType"
                  :label="$t('setting.workflowActions.fields.actionType')"
                  :options="actionTypeOptions"
                  disabled
                />
              </CCol>
              <CCol md="6" col="12">
                <CSelect
                  v-model="actionForm.recipientMode"
                  :label="$t('setting.workflowActions.fields.recipientMode')"
                  :options="recipientModeOptions"
                />
              </CCol>
              <CCol md="6" col="12">
                <CInput
                  v-model.trim="actionForm.recipientValue"
                  :disabled="actionForm.recipientMode === 'request'"
                  :label="$t('setting.workflowActions.fields.recipientValue')"
                  :placeholder="recipientValuePlaceholder"
                />
              </CCol>
              <CCol md="6" col="12">
                <CInput
                  v-model.trim="actionForm.conditionField"
                  :label="$t('setting.workflowActions.fields.conditionField')"
                  :placeholder="$t('setting.workflowActions.placeholders.conditionField')"
                />
              </CCol>
              <CCol md="12" col="12">
                <CInput
                  v-model.trim="actionForm.subject"
                  :label="$t('setting.workflowActions.fields.templateSubject')"
                  disabled
                />
              </CCol>
              <CCol md="12" col="12" class="d-flex align-items-center workflow-actions-card__enabled">
                <CInputCheckbox
                  custom
                  :checked="actionForm.actionEnabled"
                  :label="$t('setting.workflowActions.fields.actionEnabled')"
                  @change="actionForm.actionEnabled = !actionForm.actionEnabled"
                />
              </CCol>
            </CRow>

            <div class="workflow-actions-card__footer">
              <CButton color="success" variant="outline" class="workflow-actions-save" :disabled="saving || !selectedEventKey" @click="saveAction">
                <CIcon name="cil-save" class="mr-1" />
                {{ $t('setting.workflowActions.actions.save') }}
              </CButton>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  </div>
</template>

<script>
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import Service from '@/service/api'
import { formatDateTime24 } from '@/projects/utils/date-time'
import { notifyError, notifySuccess } from '@/projects/utils/notify'

const APP_CONTEXT = Object.freeze({
  appId: 'newSystem'
})

const DEFAULT_TEMPLATES = Object.freeze({
  'account.invite': {
    subject: 'You have been invited to {appName}',
    text: 'Hello {fullName},\n\nYou have been invited to use {appName}.',
    html: '<p>Hello {fullName},</p><p>You have been invited to use <b>{appName}</b>.</p>'
  },
  'auth.2fa.request': {
    subject: 'Your {appName} verification code',
    text: 'Your verification code is {code}.',
    html: '<p>Your verification code is <b>{code}</b>.</p>'
  }
})

function getPayload (response) {
  return response && response.data ? response.data.data : null
}

function normalizeWorkflowStep (workflow) {
  if (!(workflow && Array.isArray(workflow.steps) && workflow.steps.length)) return null
  return workflow.steps[0]
}

function emptyActionForm () {
  return {
    eventKey: '',
    workflowEnabled: true,
    actionType: 'email',
    actionEnabled: true,
    conditionField: '',
    recipientMode: 'request',
    recipientValue: '',
    subject: '',
    text: '',
    html: ''
  }
}

export default {
  name: 'WorkflowActions',
  components: { AppSectionHero },
  data () {
    return {
      loading: false,
      saving: false,
      lastUpdatedAt: null,
      selectedEventKey: '',
      actionForm: emptyActionForm(),
      workflowDefinitions: [],
      workflowRecords: []
    }
  },
  computed: {
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    actionTypeOptions () {
      return [
        { value: 'email', label: this.$t('setting.workflowActions.actionTypes.email') }
      ]
    },
    recipientModeOptions () {
      return [
        { value: 'request', label: this.$t('setting.workflowActions.recipientModes.request') },
        { value: 'context', label: this.$t('setting.workflowActions.recipientModes.context') },
        { value: 'literal', label: this.$t('setting.workflowActions.recipientModes.literal') }
      ]
    },
    recipientValuePlaceholder () {
      if (this.actionForm.recipientMode === 'context') return this.$t('setting.workflowActions.placeholders.contextRecipient')
      if (this.actionForm.recipientMode === 'literal') return this.$t('setting.workflowActions.placeholders.literalRecipient')
      return ''
    },
    selectedDefinition () {
      return this.workflowDefinitions.find(item => item && item.eventKey === this.selectedEventKey) || null
    },
    selectedLabel () {
      return this.labelForDefinition(this.selectedDefinition)
    },
    actionItems () {
      return this.workflowDefinitions.map(definition => {
        const workflow = this.workflowForEvent(definition.eventKey)
        const step = normalizeWorkflowStep(workflow)
        return {
          eventKey: definition.eventKey,
          label: this.labelForDefinition(definition),
          enabled: workflow
            ? workflow.enabled !== false && (!step || step.enabled !== false)
            : true
        }
      })
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    labelForDefinition (definition) {
      if (!definition) return this.$t('setting.workflowActions.emptySelection')
      if (definition.legacyType === 'invite') return this.$t('setting.emailNotifications.templates.invite')
      if (definition.legacyType === 'twoFa') return this.$t('setting.emailNotifications.templates.twoFa')
      return definition.title || definition.eventKey || '-'
    },
    workflowForEvent (eventKey) {
      return (this.workflowRecords || []).find(item => item && item.eventKey === eventKey) || null
    },
    fallbackTemplate (definition) {
      const eventKey = definition && definition.eventKey ? definition.eventKey : ''
      return Object.assign(
        { subject: '', text: '', html: '' },
        DEFAULT_TEMPLATES[eventKey] || {},
        definition && definition.defaultTemplate ? definition.defaultTemplate : {}
      )
    },
    selectAction (item) {
      if (!(item && item.eventKey)) return
      this.selectedEventKey = item.eventKey
      this.applyActionForm()
    },
    setWorkflowEnabled (value) {
      this.actionForm.workflowEnabled = !!value
    },
    applyActionForm () {
      const definition = this.selectedDefinition
      const workflow = this.workflowForEvent(this.selectedEventKey)
      const step = normalizeWorkflowStep(workflow)
      const fallback = this.fallbackTemplate(definition)
      const template = step && step.template ? step.template : fallback
      this.actionForm = Object.assign(emptyActionForm(), {
        eventKey: this.selectedEventKey,
        workflowEnabled: workflow ? workflow.enabled !== false : true,
        actionType: 'email',
        actionEnabled: step ? step.enabled !== false : true,
        conditionField: step && step.conditionField ? step.conditionField : '',
        recipientMode: step && step.recipient && step.recipient.mode ? step.recipient.mode : 'request',
        recipientValue: step && step.recipient && step.recipient.value ? step.recipient.value : '',
        subject: template.subject || '',
        text: template.text || '',
        html: template.html || ''
      })
    },
    buildWorkflowPayload () {
      const definition = this.selectedDefinition || {}
      return {
        appId: APP_CONTEXT.appId,
        eventKey: this.actionForm.eventKey,
        title: this.labelForDefinition(definition),
        description: definition.description || '',
        enabled: this.actionForm.workflowEnabled,
        managed: false,
        steps: [
          {
            key: 'primary',
            type: 'email',
            enabled: this.actionForm.actionEnabled,
            conditionField: this.actionForm.conditionField || '',
            recipient: {
              mode: this.actionForm.recipientMode || 'request',
              value: this.actionForm.recipientMode === 'request' ? '' : this.actionForm.recipientValue || ''
            },
            template: {
              subject: this.actionForm.subject || '',
              text: this.actionForm.text || '',
              html: this.actionForm.html || ''
            }
          }
        ]
      }
    },
    async loadDefinitions () {
      const response = await Service.settings('email-workflow-definitions', { appId: APP_CONTEXT.appId })
      this.workflowDefinitions = Array.isArray(getPayload(response)) ? getPayload(response) : []
    },
    async loadWorkflows () {
      const response = await Service.settings('email-workflows', { appId: APP_CONTEXT.appId })
      this.workflowRecords = Array.isArray(getPayload(response)) ? getPayload(response) : []
    },
    async loadData () {
      this.loading = true
      try {
        await Promise.all([
          this.loadDefinitions(),
          this.loadWorkflows()
        ])
        if (!this.selectedEventKey && this.workflowDefinitions.length) {
          this.selectedEventKey = this.workflowDefinitions[0].eventKey
        }
        this.applyActionForm()
        this.lastUpdatedAt = new Date()
      } catch (err) {
        notifyError(this.$store, this.$t('setting.workflowActions.messages.loadError'))
      } finally {
        this.loading = false
      }
    },
    async saveAction () {
      if (!this.selectedEventKey) return
      this.saving = true
      try {
        const payload = this.buildWorkflowPayload()
        if (this.workflowForEvent(this.selectedEventKey)) {
          await Service.settings('update-email-workflow', payload)
        } else {
          await Service.settings('create-email-workflow', payload)
        }
        await this.loadWorkflows()
        this.applyActionForm()
        this.lastUpdatedAt = new Date()
        notifySuccess(this.$store, this.$t('setting.workflowActions.messages.saved'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.workflowActions.messages.saveError'))
      } finally {
        this.saving = false
      }
    }
  }
}
</script>

<style scoped lang="scss">
@import "./components/setting-page.shared";

.workflow-actions-card {
  border: 1px solid rgba(223, 230, 238, 0.78);
  border-radius: 0.5rem;
  box-shadow: 0 14px 30px rgba(44, 52, 71, 0.06);
  margin-bottom: 1rem;
}

.workflow-actions-card__header {
  align-items: flex-start;
  border-bottom: 1px solid rgba(221, 228, 236, 0.85);
  display: flex;
  gap: 1rem;
  justify-content: space-between;
  margin-bottom: 1rem;
  padding-bottom: 0.85rem;
}

.workflow-actions-card__title {
  color: #233247;
  font-weight: 700;
}

.workflow-actions-card__title .c-icon,
.workflow-actions-card__title svg {
  color: #8c1515;
}

.workflow-actions-card__hint {
  color: #68778d;
  font-size: 0.78rem;
  margin-top: 0.25rem;
}

.workflow-action-list {
  display: grid;
  gap: 0.5rem;
  margin-top: 1rem;
}

.workflow-action-list__item {
  align-items: center;
  background: #fff;
  border: 1px solid rgba(223, 230, 238, 0.9);
  border-radius: 0.5rem;
  color: #233247;
  display: flex;
  gap: 0.75rem;
  justify-content: space-between;
  padding: 0.75rem 0.8rem;
  text-align: left;
  width: 100%;
}

.workflow-action-list__item.active {
  border-color: rgba(140, 21, 21, 0.5);
  box-shadow: 0 0 0 0.12rem rgba(140, 21, 21, 0.08);
}

.workflow-action-list__item small {
  color: #68778d;
  display: block;
  font-size: 0.74rem;
  margin-top: 0.2rem;
}

.workflow-actions-card__enabled {
  padding-top: 0.5rem;
}

.workflow-actions-card__footer {
  display: flex;
  justify-content: flex-end;
  margin-top: 1rem;
}

.workflow-actions-save {
  border-radius: 999px;
  font-weight: 700;
  min-width: 128px;
}

@media (max-width: 767px) {
  .workflow-actions-card__header {
    align-items: stretch;
    flex-direction: column;
  }

  .workflow-actions-card__footer,
  .workflow-actions-save {
    width: 100%;
  }
}
</style>
