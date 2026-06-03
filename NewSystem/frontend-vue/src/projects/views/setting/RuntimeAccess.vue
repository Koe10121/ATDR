<template>
  <div class="security-page runtime-access-page">
    <AppSectionHero
      :title="$t('setting.runtimeAccess.title')"
      :subtitle="$t('setting.runtimeAccess.subtitle')"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <CCard class="bg-style2 runtime-access-card">
      <CCardBody>
        <div class="runtime-access-card__header">
          <div>
            <div class="runtime-access-card__title">
              <CIcon name="cil-shield-alt" class="mr-2" />
              {{ $t('setting.runtimeAccess.cardTitle') }}
            </div>
            <div class="runtime-access-card__subtitle">
              {{ $t('setting.runtimeAccess.sourceLabel') }}
              <CBadge :color="sourceBadgeColor" class="ml-2">{{ sourceLabel }}</CBadge>
            </div>
          </div>
          <div class="runtime-access-card__actions">
            <CButton color="secondary" variant="outline" class="mr-2" :disabled="saving || !canEditRuntimeAccess" @click="applyDefaults">
              <CIcon name="cil-loop-circular" class="mr-1" />
              {{ $t('setting.runtimeAccess.actions.useFallback') }}
            </CButton>
            <CButton color="success" variant="outline" :disabled="saving || !canEditRuntimeAccess" @click="save">
              <CIcon name="cil-save" class="mr-1" />
              {{ $t('common.actions.save') }}
            </CButton>
          </div>
        </div>

        <CRow>
          <CCol md="6" col="12">
            <div class="runtime-access-toggle">
              <div>
                <div class="runtime-access-toggle__label">{{ $t('setting.runtimeAccess.fields.trustProxy') }}</div>
                <div class="runtime-access-toggle__hint">{{ $t('setting.runtimeAccess.hints.trustProxy') }}</div>
              </div>
              <CSwitch color="success" :checked="form.trustProxy" :disabled="!canEditRuntimeAccess" @update:checked="form.trustProxy = !!$event" />
            </div>
          </CCol>
          <CCol md="6" col="12">
            <div class="runtime-access-toggle">
              <div>
                <div class="runtime-access-toggle__label">{{ $t('setting.runtimeAccess.fields.rateLimitEnabled') }}</div>
                <div class="runtime-access-toggle__hint">{{ $t('setting.runtimeAccess.hints.rateLimitEnabled') }}</div>
              </div>
              <CSwitch color="success" :checked="form.rateLimitEnabled" :disabled="!canEditRuntimeAccess" @update:checked="form.rateLimitEnabled = !!$event" />
            </div>
          </CCol>
        </CRow>

        <CRow>
          <CCol md="4" col="12">
            <CTextarea
              v-model="form.corsAllowedOriginsText"
              :label="$t('setting.runtimeAccess.fields.corsAllowedOrigins')"
              rows="7"
              :disabled="!canEditRuntimeAccess"
              :placeholder="$t('setting.runtimeAccess.placeholders.origins')"
            />
            <div class="runtime-access-field-hint">{{ $t('setting.runtimeAccess.hints.corsAllowedOrigins') }}</div>
          </CCol>
          <CCol md="4" col="12">
            <CTextarea
              v-model="form.socketCorsOriginsText"
              :label="$t('setting.runtimeAccess.fields.socketCorsOrigins')"
              rows="7"
              :disabled="!canEditRuntimeAccess"
              :placeholder="$t('setting.runtimeAccess.placeholders.origins')"
            />
            <div class="runtime-access-field-hint">{{ $t('setting.runtimeAccess.hints.socketCorsOrigins') }}</div>
          </CCol>
          <CCol md="4" col="12">
            <CTextarea
              v-model="form.allowedIPsText"
              :label="$t('setting.runtimeAccess.fields.allowedIPs')"
              rows="7"
              :disabled="!canEditRuntimeAccess"
              :placeholder="$t('setting.runtimeAccess.placeholders.ips')"
            />
            <div class="runtime-access-field-hint">{{ $t('setting.runtimeAccess.hints.allowedIPs') }}</div>
          </CCol>
        </CRow>

        <div class="runtime-access-defaults">
          <div class="runtime-access-defaults__title">{{ $t('setting.runtimeAccess.defaultsTitle') }}</div>
          <CRow>
            <CCol md="4" col="12">
              <div class="runtime-access-defaults__item">
                <div class="runtime-access-defaults__label">{{ $t('setting.runtimeAccess.fields.corsAllowedOrigins') }}</div>
                <pre>{{ defaults.corsAllowedOriginsText || '-' }}</pre>
              </div>
            </CCol>
            <CCol md="4" col="12">
              <div class="runtime-access-defaults__item">
                <div class="runtime-access-defaults__label">{{ $t('setting.runtimeAccess.fields.socketCorsOrigins') }}</div>
                <pre>{{ defaults.socketCorsOriginsText || '-' }}</pre>
              </div>
            </CCol>
            <CCol md="4" col="12">
              <div class="runtime-access-defaults__item">
                <div class="runtime-access-defaults__label">{{ $t('setting.runtimeAccess.fields.allowedIPs') }}</div>
                <pre>{{ defaults.allowedIPsText || '-' }}</pre>
              </div>
            </CCol>
          </CRow>
        </div>
      </CCardBody>
    </CCard>

    <CCard class="bg-style2 runtime-access-card runtime-access-card--monitor">
      <CCardBody>
        <div class="runtime-access-monitor__header">
          <div>
            <div class="runtime-access-card__title">
              <CIcon name="cil-ban" class="mr-2" />
              {{ $t('setting.runtimeAccess.monitoring.blockedTitle') }}
            </div>
            <div class="runtime-access-card__subtitle">
              {{ $t('setting.runtimeAccess.monitoring.blockedSubtitle') }}
            </div>
          </div>
          <CBadge color="danger">{{ blockedItems.length }}</CBadge>
        </div>

        <div v-if="!blockedItems.length" class="runtime-access-empty">
          {{ $t('setting.runtimeAccess.monitoring.emptyBlocked') }}
        </div>

        <CDataTable
          v-else
          :items="blockedItems"
          :fields="blockedIpFields"
          hover
          striped
          sorter
          :items-per-page="5"
          pagination
        >
          <template #blockedAt="{ item }">
            <td>{{ formatTimestamp(item.blockedAt) }}</td>
          </template>
          <template #expiresAt="{ item }">
            <td>{{ formatTimestamp(item.expiresAt) }}</td>
          </template>
          <template #remaining="{ item }">
            <td>{{ formatRemaining(item.remainingMs) }}</td>
          </template>
          <template #target="{ item }">
            <td>
              <div>{{ formatTarget(item) }}</div>
              <div class="runtime-access-table__sub">{{ item.origin || '-' }}</div>
            </td>
          </template>
          <template v-if="canUnblockRuntimeAccess" #actions="{ item }">
            <td>
              <CButton
                color="danger"
                size="sm"
                variant="outline"
                :disabled="saving || unblockingIp === item.ip"
                @click="unblockIp(item)"
              >
                {{ $t('setting.runtimeAccess.actions.unblock') }}
              </CButton>
            </td>
          </template>
        </CDataTable>
      </CCardBody>
    </CCard>

    <CCard class="bg-style2 runtime-access-card runtime-access-card--monitor">
      <CCardBody>
        <div class="runtime-access-monitor__header">
          <div>
            <div class="runtime-access-card__title">
              <CIcon name="cil-list-rich" class="mr-2" />
              {{ $t('setting.runtimeAccess.monitoring.eventsTitle') }}
            </div>
            <div class="runtime-access-card__subtitle">
              {{ $t('setting.runtimeAccess.monitoring.eventsSubtitle') }}
            </div>
          </div>
          <CBadge color="info">{{ recentEvents.length }}</CBadge>
        </div>

        <div class="runtime-access-monitor__hint">
          {{ $t('setting.runtimeAccess.monitoring.eventsHint') }}
        </div>

        <div v-if="!recentEvents.length" class="runtime-access-empty">
          {{ $t('setting.runtimeAccess.monitoring.emptyEvents') }}
        </div>

        <CDataTable
          v-else
          :items="recentEvents"
          :fields="eventFields"
          hover
          striped
          sorter
          :items-per-page="10"
          pagination
        >
          <template #occurredAt="{ item }">
            <td>{{ formatTimestamp(item.occurredAt) }}</td>
          </template>
          <template #decision="{ item }">
            <td>
              <CBadge :color="decisionColor(item.decision)">
                {{ item.decision || '-' }}
              </CBadge>
            </td>
          </template>
          <template #target="{ item }">
            <td>
              <div>{{ formatTarget(item) }}</div>
              <div class="runtime-access-table__sub">{{ item.origin || '-' }}</div>
            </td>
          </template>
          <template #detail="{ item }">
            <td>
              <span class="runtime-access-detail">{{ stringifyDetail(item.detail) }}</span>
            </td>
          </template>
        </CDataTable>
      </CCardBody>
    </CCard>
  </div>
</template>

<script>
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import securityAccess from '@/projects/mixins/securityAccess'
import Service from '@/service/api'
import { formatDateTime24 } from '@/projects/utils/date-time'
import { notifyError, notifyInfo, notifySuccess } from '@/projects/utils/notify'

function splitLines (value) {
  return String(value || '')
    .split('\n')
    .map(item => String(item || '').trim())
    .filter(Boolean)
}

function joinLines (items) {
  return Array.isArray(items) ? items.join('\n') : ''
}

function emptyForm () {
  return {
    trustProxy: false,
    rateLimitEnabled: true,
    corsAllowedOriginsText: '',
    socketCorsOriginsText: '',
    allowedIPsText: '',
    source: 'environment'
  }
}

function emptyInsights () {
  return {
    generatedAt: null,
    activeBlockedIps: [],
    recentEvents: [],
    stats: {
      activeBlockedIpCount: 0,
      recentEventCount: 0
    }
  }
}

function getPayload (response) {
  return response && response.data ? response.data.data : null
}

export default {
  name: 'RuntimeAccess',
  mixins: [securityAccess],
  components: { AppSectionHero },
  data () {
    return {
      form: emptyForm(),
      defaults: {
        trustProxy: false,
        rateLimitEnabled: true,
        corsAllowedOriginsText: '',
        socketCorsOriginsText: '',
        allowedIPsText: ''
      },
      insights: emptyInsights(),
      lastUpdatedAt: null,
      saving: false,
      unblockingIp: ''
    }
  },
  computed: {
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    sourceLabel () {
      return this.form.source === 'database'
        ? this.$t('setting.runtimeAccess.sources.database')
        : this.$t('setting.runtimeAccess.sources.environment')
    },
    sourceBadgeColor () {
      return this.form.source === 'database' ? 'success' : 'warning'
    },
    canEditRuntimeAccess () {
      return this.canEditPath('/config/runtime-access')
    },
    canUnblockRuntimeAccess () {
      return this.canActionPath('/config/runtime-access')
    },
    blockedItems () {
      return Array.isArray(this.insights.activeBlockedIps) ? this.insights.activeBlockedIps : []
    },
    recentEvents () {
      return Array.isArray(this.insights.recentEvents) ? this.insights.recentEvents : []
    },
    blockedIpFields () {
      const fields = [
        { key: 'ip', label: this.$t('setting.runtimeAccess.monitoring.fields.ip') },
        { key: 'reason', label: this.$t('setting.runtimeAccess.monitoring.fields.reason') },
        { key: 'source', label: this.$t('setting.runtimeAccess.monitoring.fields.source') },
        { key: 'blockedAt', label: this.$t('setting.runtimeAccess.monitoring.fields.blockedAt') },
        { key: 'expiresAt', label: this.$t('setting.runtimeAccess.monitoring.fields.expiresAt') },
        { key: 'remaining', label: this.$t('setting.runtimeAccess.monitoring.fields.remaining') },
        { key: 'target', label: this.$t('setting.runtimeAccess.monitoring.fields.target') }
      ]
      if (this.canUnblockRuntimeAccess) {
        fields.push({ key: 'actions', label: this.$t('setting.runtimeAccess.monitoring.fields.actions') })
      }
      return fields
    },
    eventFields () {
      return [
        { key: 'occurredAt', label: this.$t('setting.runtimeAccess.monitoring.fields.occurredAt') },
        { key: 'source', label: this.$t('setting.runtimeAccess.monitoring.fields.source') },
        { key: 'type', label: this.$t('setting.runtimeAccess.monitoring.fields.type') },
        { key: 'decision', label: this.$t('setting.runtimeAccess.monitoring.fields.decision') },
        { key: 'ip', label: this.$t('setting.runtimeAccess.monitoring.fields.ip') },
        { key: 'target', label: this.$t('setting.runtimeAccess.monitoring.fields.target') },
        { key: 'statusCode', label: this.$t('setting.runtimeAccess.monitoring.fields.statusCode') },
        { key: 'message', label: this.$t('setting.runtimeAccess.monitoring.fields.message') },
        { key: 'detail', label: this.$t('setting.runtimeAccess.monitoring.fields.detail') }
      ]
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    normalize (payload) {
      return {
        trustProxy: !!(payload && payload.trustProxy),
        rateLimitEnabled: !(payload && payload.rateLimitEnabled === false),
        corsAllowedOriginsText: joinLines(payload && payload.corsAllowedOrigins),
        socketCorsOriginsText: joinLines(payload && payload.socketCorsOrigins),
        allowedIPsText: joinLines(payload && payload.allowedIPs),
        source: payload && payload.source ? String(payload.source) : 'environment'
      }
    },
    normalizeInsights (insights) {
      const blocked = Array.isArray(insights && insights.activeBlockedIps) ? insights.activeBlockedIps : []
      const recent = Array.isArray(insights && insights.recentEvents) ? insights.recentEvents : []
      const stats = insights && insights.stats ? insights.stats : {}
      return {
        generatedAt: insights && insights.generatedAt ? insights.generatedAt : null,
        activeBlockedIps: blocked.map(item => ({
          ip: item && item.ip ? String(item.ip) : '',
          reason: item && item.reason ? String(item.reason) : '',
          source: item && item.source ? String(item.source) : '',
          blockedAt: item && item.blockedAt ? item.blockedAt : null,
          expiresAt: item && item.expiresAt ? item.expiresAt : null,
          remainingMs: item && item.remainingMs ? Number(item.remainingMs) : 0,
          method: item && item.method ? String(item.method) : '',
          path: item && item.path ? String(item.path) : '',
          origin: item && item.origin ? String(item.origin) : ''
        })),
        recentEvents: recent.map(item => ({
          occurredAt: item && item.occurredAt ? item.occurredAt : null,
          source: item && item.source ? String(item.source) : '',
          type: item && item.type ? String(item.type) : '',
          decision: item && item.decision ? String(item.decision) : '',
          ip: item && item.ip ? String(item.ip) : '',
          method: item && item.method ? String(item.method) : '',
          path: item && item.path ? String(item.path) : '',
          origin: item && item.origin ? String(item.origin) : '',
          statusCode: item && item.statusCode ? String(item.statusCode) : '',
          message: item && item.message ? String(item.message) : '',
          detail: item && item.detail ? item.detail : null
        })),
        stats: {
          activeBlockedIpCount: Number(stats.activeBlockedIpCount) || blocked.length,
          recentEventCount: Number(stats.recentEventCount) || recent.length
        }
      }
    },
    updateDefaults (defaults) {
      this.defaults = {
        trustProxy: !!(defaults && defaults.trustProxy),
        rateLimitEnabled: !(defaults && defaults.rateLimitEnabled === false),
        corsAllowedOriginsText: joinLines(defaults && defaults.corsAllowedOrigins),
        socketCorsOriginsText: joinLines(defaults && defaults.socketCorsOrigins),
        allowedIPsText: joinLines(defaults && defaults.allowedIPs)
      }
    },
    formatTimestamp (value) {
      return value ? formatDateTime24(value) : '-'
    },
    formatTarget (item) {
      const method = item && item.method ? String(item.method).toUpperCase() : ''
      const path = item && item.path ? item.path : ''
      if (method && path) return `${method} ${path}`
      return method || path || '-'
    },
    formatRemaining (value) {
      const totalSeconds = Math.max(0, Math.ceil((Number(value) || 0) / 1000))
      if (!totalSeconds) {
        return this.$t('setting.runtimeAccess.monitoring.remainingExpired')
      }
      const minutes = Math.floor(totalSeconds / 60)
      const seconds = totalSeconds % 60
      if (minutes && seconds) {
        return this.$t('setting.runtimeAccess.monitoring.remainingMinutesSeconds', { minutes, seconds })
      }
      if (minutes) {
        return this.$t('setting.runtimeAccess.monitoring.remainingMinutes', { minutes })
      }
      return this.$t('setting.runtimeAccess.monitoring.remainingSeconds', { seconds })
    },
    stringifyDetail (value) {
      if (!value) return '-'
      try {
        return JSON.stringify(value)
      } catch (err) {
        return '-'
      }
    },
    decisionColor (decision) {
      if (decision === 'blocked' || decision === 'denied') return 'danger'
      if (decision === 'allowed') return 'success'
      return 'secondary'
    },
    async loadData () {
      try {
        const response = await Service.settings('runtime-access', {})
        const payload = getPayload(response) || {}
        this.form = this.normalize(payload)
        this.updateDefaults(payload.defaults || {})
        this.insights = this.normalizeInsights(payload.insights || {})
        this.lastUpdatedAt = new Date()
      } catch (error) {
        notifyError(this.$store, this.$t('setting.runtimeAccess.messages.loadError'))
      }
    },
    applyDefaults () {
      this.form = Object.assign({}, this.form, this.defaults, { source: 'environment' })
      notifyInfo(this.$store, this.$t('setting.runtimeAccess.messages.defaultsApplied'))
    },
    buildPayload () {
      return {
        trustProxy: this.form.trustProxy,
        rateLimitEnabled: this.form.rateLimitEnabled,
        corsAllowedOrigins: splitLines(this.form.corsAllowedOriginsText),
        socketCorsOrigins: splitLines(this.form.socketCorsOriginsText),
        allowedIPs: splitLines(this.form.allowedIPsText)
      }
    },
    async save () {
      if (!this.canEditRuntimeAccess) {
        notifyError(this.$store, this.$t('setting.runtimeAccess.messages.permissionDenied'))
        return
      }
      this.saving = true
      try {
        const response = await Service.settings('update-runtime-access', this.buildPayload())
        const payload = getPayload(response) || {}
        this.form = this.normalize(payload)
        this.updateDefaults(payload.defaults || {})
        this.insights = this.normalizeInsights(payload.insights || {})
        this.lastUpdatedAt = new Date()
        notifySuccess(this.$store, this.$t('setting.runtimeAccess.messages.saved'))
      } catch (error) {
        const status = error && error.response ? error.response.status : 0
        notifyError(this.$store, this.$t(status === 403
          ? 'setting.runtimeAccess.messages.permissionDenied'
          : 'setting.runtimeAccess.messages.saveError'))
      } finally {
        this.saving = false
      }
    },
    async unblockIp (item) {
      if (!item || !item.ip) return
      this.unblockingIp = item.ip
      try {
        const response = await Service.settings('unblock-runtime-access-ip', { ip: item.ip })
        const payload = getPayload(response) || {}
        this.form = this.normalize(payload)
        this.updateDefaults(payload.defaults || {})
        this.insights = this.normalizeInsights(payload.insights || {})
        this.lastUpdatedAt = new Date()
        notifySuccess(this.$store, this.$t('setting.runtimeAccess.messages.unblocked'))
      } catch (error) {
        notifyError(this.$store, this.$t('setting.runtimeAccess.messages.unblockError'))
      } finally {
        this.unblockingIp = ''
      }
    }
  }
}
</script>

<style lang="scss" scoped>
@import "./components/setting-page.shared";

.runtime-access-card {
  animation: setting-fade-up 0.65s ease-out both;
}

.runtime-access-card--monitor {
  margin-top: 1.5rem;
}

.runtime-access-card__header,
.runtime-access-monitor__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.runtime-access-card__title {
  font-size: 1.1rem;
  font-weight: 700;
  display: flex;
  align-items: center;
}

.runtime-access-card__subtitle {
  color: #5c6873;
  margin-top: 0.35rem;
}

.runtime-access-card__actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
}

.runtime-access-toggle {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  padding: 1rem 1.1rem;
  border: 1px solid rgba(44, 56, 74, 0.1);
  border-radius: 0.85rem;
  background: linear-gradient(180deg, rgba(248, 249, 250, 0.95), rgba(255, 255, 255, 0.98));
  min-height: 100%;
  margin-bottom: 1rem;
}

.runtime-access-toggle__label {
  font-weight: 700;
  color: #2c384a;
}

.runtime-access-toggle__hint,
.runtime-access-field-hint,
.runtime-access-monitor__hint {
  color: #768192;
  font-size: 0.88rem;
}

.runtime-access-defaults {
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 1px solid rgba(44, 56, 74, 0.08);
}

.runtime-access-defaults__title {
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 1rem;
}

.runtime-access-defaults__item {
  padding: 1rem;
  border-radius: 0.85rem;
  background: #f8f9fa;
  height: 100%;
}

.runtime-access-defaults__label {
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.runtime-access-defaults__item pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  color: #2c384a;
  font-size: 0.85rem;
}

.runtime-access-empty {
  padding: 1rem 1.1rem;
  border-radius: 0.85rem;
  background: #f8f9fa;
  color: #5c6873;
}

.runtime-access-table__sub,
.runtime-access-detail {
  display: inline-block;
  max-width: 420px;
  white-space: normal;
  word-break: break-word;
  color: #768192;
  font-size: 0.75rem;
}

.runtime-access-detail {
  color: #2c384a;
  font-family: monospace;
}

@media (max-width: 991px) {
  .runtime-access-card__header,
  .runtime-access-monitor__header {
    flex-direction: column;
  }
}
</style>
