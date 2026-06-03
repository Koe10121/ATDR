<template>
  <div class="security-page database-backup-page">
    <AppSectionHero
      :title="$t('setting.databaseBackup.title')"
      :subtitle="$t('setting.databaseBackup.subtitle')"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <CCard class="bg-style2 database-backup-card">
      <CCardBody>
        <div class="database-backup-card__header">
          <div>
            <div class="database-backup-card__title">
              <CIcon name="cil-storage" class="mr-2" />
              {{ $t('setting.databaseBackup.cardTitle') }}
            </div>
            <CBadge v-if="active" color="warning" class="mt-2">{{ $t('setting.databaseBackup.activeBadge') }}</CBadge>
          </div>
          <div class="database-backup-card__actions">
            <CButton color="info" variant="outline" class="mr-2" :disabled="previewing" :title="$t('setting.databaseBackup.actions.previewCollections')" @click="loadCollectionPreview">
              <CIcon name="cil-magnifying-glass" class="mr-1" />
              {{ $t('setting.databaseBackup.actions.previewCollections') }}
            </CButton>
            <CButton color="primary" variant="outline" class="mr-2" :disabled="saving || active || !canActionDatabaseBackup" :title="$t('setting.databaseBackup.actions.runNow')" @click="runBackup">
              <CIcon name="cil-cloud-upload" class="mr-1" />
              {{ $t('setting.databaseBackup.actions.runNow') }}
            </CButton>
            <CButton color="success" variant="outline" :disabled="saving || !canEditDatabaseBackup" :title="$t('setting.databaseBackup.actions.saveSettings')" @click="saveSettings">
              <CIcon name="cil-save" class="mr-1" />
              {{ $t('setting.databaseBackup.actions.saveSettings') }}
            </CButton>
          </div>
        </div>

        <CRow>
          <CCol lg="4" md="6" col="12">
            <div class="database-backup-form-field">
              <label class="database-backup-form-field__label">{{ $t('setting.databaseBackup.fields.autoEnabled') }}</label>
              <button
                type="button"
                class="database-backup-toggle-control"
                :class="{
                  'database-backup-toggle-control--active': settings.autoEnabled,
                  'database-backup-toggle-control--disabled': !canEditDatabaseBackup
                }"
                role="switch"
                :aria-checked="settings.autoEnabled ? 'true' : 'false'"
                :disabled="!canEditDatabaseBackup"
                @click="toggleAutoBackup"
              >
                <span class="database-backup-toggle-control__content">
                  <span class="database-backup-toggle-control__status">{{ autoBackupStatusLabel }}</span>
                  <span class="database-backup-toggle-control__next">{{ nextRunLabel }}</span>
                </span>
                <span class="database-backup-toggle-control__switch" aria-hidden="true">
                  <span />
                </span>
              </button>
            </div>
          </CCol>
          <CCol lg="4" md="6" col="12">
            <CInput
              v-model.number="settings.intervalHours"
              type="number"
              min="1"
              max="720"
              :label="$t('setting.databaseBackup.fields.intervalHours')"
              :disabled="!canEditDatabaseBackup"
            />
          </CCol>
          <CCol lg="4" md="6" col="12">
            <CInput
              v-model.number="settings.retentionCount"
              type="number"
              min="1"
              max="100"
              :label="$t('setting.databaseBackup.fields.retentionCount')"
              :disabled="!canEditDatabaseBackup"
            />
          </CCol>
          <CCol col="12">
            <CInput
              :value="settings.backupDir"
              :label="$t('setting.databaseBackup.fields.backupDir')"
              disabled
            />
          </CCol>
        </CRow>
      </CCardBody>
    </CCard>

    <CCard class="bg-style2 database-backup-card database-backup-card--preview">
      <CCardBody>
        <div class="database-backup-card__header">
          <div>
            <div class="database-backup-card__title">
              <CIcon name="cil-magnifying-glass" class="mr-2" />
              {{ $t('setting.databaseBackup.previewTitle') }}
            </div>
            <div class="database-backup-table__sub">{{ previewLoadedLabel }}</div>
          </div>
          <CBadge color="info">{{ previewSummary.collectionCount || 0 }}</CBadge>
        </div>

        <CDataTable
          v-if="collectionPreview.length"
          :items="collectionPreview"
          :fields="previewFields"
          hover
          striped
          sorter
          :items-per-page="10"
          pagination
        >
          <template #documentCount="{ item }">
            <td>{{ item.documentCount || 0 }}</td>
          </template>
        </CDataTable>
        <div v-else class="database-backup-empty">
          {{ $t('setting.databaseBackup.previewEmpty') }}
        </div>
      </CCardBody>
    </CCard>

    <CCard class="bg-style2 database-backup-card database-backup-card--history">
      <CCardBody>
        <div class="database-backup-card__header">
          <div class="database-backup-card__title">
            <CIcon name="cil-history" class="mr-2" />
            {{ $t('setting.databaseBackup.historyTitle') }}
          </div>
          <CBadge color="info">{{ runs.length }}</CBadge>
        </div>

        <div v-if="historyPreview" class="database-backup-history-preview">
          <div class="database-backup-card__header">
            <div>
              <div class="database-backup-card__title">
                <CIcon name="cil-magnifying-glass" class="mr-2" />
                {{ $t('setting.databaseBackup.historyPreviewTitle') }}
              </div>
              <div class="database-backup-table__sub">{{ historyPreviewLoadedLabel }}</div>
            </div>
            <CBadge color="info">{{ historyPreview.collectionCount || 0 }}</CBadge>
          </div>
          <CDataTable
            v-if="historyPreview.collections && historyPreview.collections.length"
            :items="historyPreview.collections"
            :fields="backupPreviewFields"
            hover
            striped
            sorter
            :items-per-page="5"
            pagination
          >
            <template #documentCount="{ item }">
              <td>{{ item.documentCount || 0 }}</td>
            </template>
          </CDataTable>
          <div v-else class="database-backup-empty">
            {{ $t('setting.databaseBackup.historyPreviewEmpty') }}
          </div>
        </div>

        <CDataTable
          :items="runs"
          :fields="runFields"
          hover
          striped
          sorter
          :items-per-page="10"
          pagination
        >
          <template #mode="{ item }">
            <td>
              <CBadge :color="item.mode === 'auto' ? 'info' : 'secondary'">{{ modeLabel(item.mode) }}</CBadge>
            </td>
          </template>
          <template #status="{ item }">
            <td>
              <CBadge :color="statusColor(item.status)">{{ statusLabel(item.status) }}</CBadge>
            </td>
          </template>
          <template #startedAt="{ item }">
            <td>{{ formatTimestamp(item.startedAt) }}</td>
          </template>
          <template #completedAt="{ item }">
            <td>{{ formatTimestamp(item.completedAt) }}</td>
          </template>
          <template #sizeBytes="{ item }">
            <td>{{ formatBytes(item.sizeBytes) }}</td>
          </template>
          <template #collections="{ item }">
            <td>
              <div>{{ item.collectionCount || 0 }}</div>
              <div class="database-backup-table__sub">{{ item.documentCount || 0 }} {{ $t('setting.databaseBackup.fields.documentCount') }}</div>
            </td>
          </template>
          <template #checksum="{ item }">
            <td>
              <code class="database-backup-checksum">{{ item.checksum || '-' }}</code>
            </td>
          </template>
          <template #actions="{ item }">
            <td class="database-backup-table__actions">
              <CButton
                color="info"
                size="sm"
                variant="outline"
                :disabled="historyPreviewing || !item.downloadable"
                :title="$t('setting.databaseBackup.actions.previewBackup')"
                :aria-label="$t('setting.databaseBackup.actions.previewBackup')"
                @click="previewBackup(item)"
              >
                <CIcon name="cil-magnifying-glass" />
              </CButton>
              <CButton
                color="warning"
                size="sm"
                variant="outline"
                :disabled="restoring || !item.downloadable || !canActionDatabaseBackup"
                :title="$t('setting.databaseBackup.actions.restore')"
                :aria-label="$t('setting.databaseBackup.actions.restore')"
                @click="requestRestoreBackup(item)"
              >
                <CIcon name="cil-action-undo" />
              </CButton>
              <CButton
                color="primary"
                size="sm"
                variant="outline"
                :disabled="saving || !item.downloadable || !canActionDatabaseBackup"
                :title="$t('setting.databaseBackup.actions.download')"
                :aria-label="$t('setting.databaseBackup.actions.download')"
                @click="downloadBackup(item)"
              >
                <CIcon name="cil-cloud-download" />
              </CButton>
              <CButton
                color="danger"
                size="sm"
                variant="outline"
                :disabled="saving || !canDeleteDatabaseBackup"
                :title="$t('setting.databaseBackup.actions.delete')"
                :aria-label="$t('setting.databaseBackup.actions.delete')"
                @click="requestDeleteBackup(item)"
              >
                <CIcon name="cil-trash" />
              </CButton>
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
import { notifyError, notifySuccess } from '@/projects/utils/notify'

const PERMISSION_PATH = '/config/database-backup'

function getPayload (response) {
  return response && response.data ? response.data.data : null
}

function emptySettings () {
  return {
    autoEnabled: false,
    intervalHours: 24,
    retentionCount: 10,
    backupDir: '',
    lastRunAt: null,
    nextRunAt: null
  }
}

function clampNumber (value, fallback, min, max) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, parsed))
}

export default {
  name: 'DatabaseBackup',
  mixins: [securityAccess],
  components: { AppSectionHero },
  data () {
    return {
      settings: emptySettings(),
      runs: [],
      collectionPreview: [],
      historyPreview: null,
      restoreSummary: null,
      previewSummary: {
        generatedAt: null,
        collectionCount: 0,
        documentCount: 0
      },
      active: false,
      saving: false,
      previewing: false,
      historyPreviewing: false,
      restoring: false,
      lastUpdatedAt: null
    }
  },
  computed: {
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    nextRunLabel () {
      return this.settings.nextRunAt ? formatDateTime24(this.settings.nextRunAt) : '-'
    },
    autoBackupStatusLabel () {
      return this.settings.autoEnabled
        ? this.$t('setting.databaseBackup.fields.enabled')
        : this.$t('setting.databaseBackup.fields.disabled')
    },
    previewLoadedLabel () {
      if (!this.previewSummary.generatedAt) return this.$t('setting.databaseBackup.previewNotLoaded')
      return this.$t('setting.databaseBackup.previewLoaded', {
        time: formatDateTime24(this.previewSummary.generatedAt),
        documents: this.previewSummary.documentCount || 0
      })
    },
    historyPreviewLoadedLabel () {
      if (!this.historyPreview) return this.$t('setting.databaseBackup.historyPreviewEmpty')
      const metadata = this.historyPreview.metadata || {}
      return this.$t('setting.databaseBackup.historyPreviewLoaded', {
        name: (this.historyPreview.run && this.historyPreview.run.filename) || '-',
        documents: this.historyPreview.documentCount || 0,
        createdAt: metadata.createdAt ? formatDateTime24(metadata.createdAt) : '-'
      })
    },
    canEditDatabaseBackup () {
      return this.canEditPath(PERMISSION_PATH)
    },
    canActionDatabaseBackup () {
      return this.canActionPath(PERMISSION_PATH)
    },
    canDeleteDatabaseBackup () {
      return this.canDeletePath(PERMISSION_PATH)
    },
    runFields () {
      return [
        { key: 'mode', label: this.$t('setting.databaseBackup.fields.mode') },
        { key: 'status', label: this.$t('setting.databaseBackup.fields.status') },
        { key: 'databaseName', label: this.$t('setting.databaseBackup.fields.databaseName') },
        { key: 'startedAt', label: this.$t('setting.databaseBackup.fields.startedAt') },
        { key: 'completedAt', label: this.$t('setting.databaseBackup.fields.completedAt') },
        { key: 'sizeBytes', label: this.$t('setting.databaseBackup.fields.sizeBytes') },
        { key: 'collections', label: this.$t('setting.databaseBackup.fields.collections') },
        { key: 'checksum', label: this.$t('setting.databaseBackup.fields.checksum') },
        { key: 'actions', label: this.$t('setting.databaseBackup.fields.actions') }
      ]
    },
    previewFields () {
      return [
        { key: 'name', label: this.$t('setting.databaseBackup.fields.collectionName') },
        { key: 'type', label: this.$t('setting.databaseBackup.fields.type') },
        { key: 'documentCount', label: this.$t('setting.databaseBackup.fields.documentCount') }
      ]
    },
    backupPreviewFields () {
      return [
        { key: 'name', label: this.$t('setting.databaseBackup.fields.collectionName') },
        { key: 'documentCount', label: this.$t('setting.databaseBackup.fields.documentCount') }
      ]
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    normalizeSettings (settings) {
      return Object.assign(emptySettings(), {
        autoEnabled: !!(settings && settings.autoEnabled),
        intervalHours: clampNumber(settings && settings.intervalHours, 24, 1, 720),
        retentionCount: clampNumber(settings && settings.retentionCount, 10, 1, 100),
        backupDir: settings && settings.backupDir ? String(settings.backupDir) : '',
        lastRunAt: settings && settings.lastRunAt ? settings.lastRunAt : null,
        nextRunAt: settings && settings.nextRunAt ? settings.nextRunAt : null
      })
    },
    normalizeRun (item) {
      return {
        _id: item && item._id ? String(item._id) : '',
        mode: item && item.mode ? String(item.mode) : 'manual',
        status: item && item.status ? String(item.status) : 'running',
        databaseName: item && item.databaseName ? String(item.databaseName) : '-',
        filename: item && item.filename ? String(item.filename) : '',
        sizeBytes: Number(item && item.sizeBytes) || 0,
        checksum: item && item.checksum ? String(item.checksum) : '',
        collectionCount: Number(item && item.collectionCount) || 0,
        documentCount: Number(item && item.documentCount) || 0,
        collections: Array.isArray(item && item.collections) ? item.collections : [],
        error: item && item.error ? String(item.error) : '',
        startedAt: item && item.startedAt ? item.startedAt : null,
        completedAt: item && item.completedAt ? item.completedAt : null,
        downloadable: !!(item && item.downloadable)
      }
    },
    normalizeCollectionPreview (item) {
      return {
        name: item && item.name ? String(item.name) : '-',
        type: item && item.type ? String(item.type) : 'collection',
        documentCount: Number(item && item.documentCount) || 0
      }
    },
    normalizeBackupArchivePreview (payload) {
      const data = payload || {}
      return {
        run: this.normalizeRun(data.run || {}),
        metadata: Object.assign({
          app: '',
          databaseName: '',
          mode: '',
          createdAt: null
        }, data.metadata || {}),
        collectionCount: Number(data.collectionCount) || 0,
        documentCount: Number(data.documentCount) || 0,
        collections: Array.isArray(data.collections)
          ? data.collections.map(item => ({
            name: item && item.name ? String(item.name) : '-',
            documentCount: Number(item && item.documentCount) || 0
          }))
          : []
      }
    },
    applyPayload (payload) {
      const data = payload || {}
      this.settings = this.normalizeSettings(data.settings)
      this.runs = Array.isArray(data.runs) ? data.runs.map(this.normalizeRun) : []
      this.active = !!data.active
      this.lastUpdatedAt = new Date()
    },
    applySettingsPayload (payload) {
      const data = payload || {}
      const settings = data.settings || (Object.prototype.hasOwnProperty.call(data, 'autoEnabled') ? data : null)
      if (settings) this.settings = this.normalizeSettings(settings)
      if (Object.prototype.hasOwnProperty.call(data, 'active')) this.active = !!data.active
      this.lastUpdatedAt = new Date()
    },
    applyPreviewPayload (payload) {
      const data = payload || {}
      this.collectionPreview = Array.isArray(data.collections) ? data.collections.map(this.normalizeCollectionPreview) : []
      this.previewSummary = {
        generatedAt: data.generatedAt || new Date(),
        collectionCount: Number(data.collectionCount) || this.collectionPreview.length,
        documentCount: Number(data.documentCount) || this.collectionPreview.reduce((total, item) => total + (Number(item.documentCount) || 0), 0)
      }
    },
    applyHistoryPreviewPayload (payload) {
      this.historyPreview = this.normalizeBackupArchivePreview(payload)
    },
    buildPayload () {
      return {
        autoEnabled: !!this.settings.autoEnabled,
        intervalHours: clampNumber(this.settings.intervalHours, 24, 1, 720),
        retentionCount: clampNumber(this.settings.retentionCount, 10, 1, 100)
      }
    },
    toggleAutoBackup () {
      if (!this.canEditDatabaseBackup) return
      this.settings.autoEnabled = !this.settings.autoEnabled
    },
    formatTimestamp (value) {
      return value ? formatDateTime24(value) : '-'
    },
    formatBytes (value) {
      const bytes = Number(value) || 0
      if (bytes < 1024) return `${bytes} B`
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
      if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
    },
    modeLabel (value) {
      const key = `setting.databaseBackup.modes.${value}`
      return this.$te(key) ? this.$t(key) : value || '-'
    },
    statusLabel (value) {
      const key = `setting.databaseBackup.statuses.${value}`
      return this.$te(key) ? this.$t(key) : value || '-'
    },
    statusColor (value) {
      if (value === 'completed') return 'success'
      if (value === 'failed') return 'danger'
      if (value === 'running') return 'warning'
      return 'secondary'
    },
    async loadData () {
      try {
        const response = await Service.settings('database-backup', {})
        this.applyPayload(getPayload(response) || {})
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.loadError'))
      }
    },
    async loadCollectionPreview () {
      this.previewing = true
      try {
        const response = await Service.settings('database-backup-collections', {})
        this.applyPreviewPayload(getPayload(response) || {})
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.previewError'))
      } finally {
        this.previewing = false
      }
    },
    async saveSettings () {
      if (!this.canEditDatabaseBackup) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.permissionDenied'))
        return
      }
      this.saving = true
      try {
        const response = await Service.settings('update-database-backup', this.buildPayload())
        this.applySettingsPayload(getPayload(response) || {})
        notifySuccess(this.$store, this.$t('setting.databaseBackup.messages.saved'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.saveError'))
      } finally {
        this.saving = false
      }
    },
    async runBackup () {
      if (!this.canActionDatabaseBackup) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.permissionDenied'))
        return
      }
      this.saving = true
      try {
        const response = await Service.settings('run-database-backup', {})
        this.applyPayload(getPayload(response) || {})
        notifySuccess(this.$store, this.$t('setting.databaseBackup.messages.manualStarted'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.manualError'))
      } finally {
        this.saving = false
      }
    },
    async downloadBackup (item) {
      if (!(item && item._id)) return
      try {
        const response = await Service.settings('download-database-backup', { id: item._id })
        const blob = new Blob([response.data], { type: 'application/gzip' })
        const urlApi = window.URL || window.webkitURL
        const url = urlApi.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = item.filename || 'newSystem-database-backup.json.gz'
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        urlApi.revokeObjectURL(url)
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.downloadError'))
      }
    },
    async previewBackup (item) {
      if (!(item && item._id)) return
      this.historyPreviewing = true
      try {
        const response = await Service.settings('preview-database-backup', { id: item._id })
        this.applyHistoryPreviewPayload(getPayload(response) || {})
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.previewBackupError'))
      } finally {
        this.historyPreviewing = false
      }
    },
    requestRestoreBackup (item) {
      if (!(item && item._id)) return Promise.resolve(false)
      return this.$store.dispatch('dialog/openConfirm', {
        title: this.$t('setting.databaseBackup.messages.restoreConfirmTitle'),
        message: this.$t('setting.databaseBackup.messages.restoreConfirmMessage', { name: item.filename || item._id }),
        confirmText: this.$t('setting.databaseBackup.actions.restore'),
        confirmIcon: 'cil-action-undo'
      }).then(confirmed => {
        if (!confirmed) return false
        return this.restoreBackup(item)
      })
    },
    async restoreBackup (item) {
      if (!(item && item._id)) return
      this.restoring = true
      try {
        const response = await Service.settings('restore-database-backup', { id: item._id })
        const payload = getPayload(response) || {}
        this.applyHistoryPreviewPayload(payload)
        this.restoreSummary = payload
        notifySuccess(this.$store, this.$t('setting.databaseBackup.messages.restored'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.restoreError'))
      } finally {
        this.restoring = false
      }
    },
    requestDeleteBackup (item) {
      if (!(item && item._id)) return Promise.resolve(false)
      return this.$store.dispatch('dialog/openConfirm', {
        title: this.$t('setting.databaseBackup.messages.deleteConfirmTitle'),
        message: this.$t('setting.databaseBackup.messages.deleteConfirmMessage', { name: item.filename || item._id }),
        confirmText: this.$t('common.actions.remove'),
        confirmIcon: 'cil-trash'
      }).then(confirmed => {
        if (!confirmed) return false
        return this.deleteBackup(item)
      })
    },
    async deleteBackup (item) {
      this.saving = true
      try {
        const response = await Service.settings('delete-database-backup', { id: item._id })
        this.applyPayload(getPayload(response) || {})
        notifySuccess(this.$store, this.$t('setting.databaseBackup.messages.deleted'))
      } catch (err) {
        notifyError(this.$store, this.$t('setting.databaseBackup.messages.deleteError'))
      } finally {
        this.saving = false
      }
    }
  }
}
</script>

<style lang="scss" scoped>
@import "./components/setting-page.shared";

.database-backup-card {
  animation: setting-fade-up 0.65s ease-out both;
  border: 1px solid rgba(223, 230, 238, 0.78);
  border-radius: 0.5rem;
  box-shadow: 0 14px 30px rgba(44, 52, 71, 0.06);
}

.database-backup-card--preview,
.database-backup-card--history {
  margin-top: 1.5rem;
}

.database-backup-card__header {
  align-items: flex-start;
  display: flex;
  gap: 1rem;
  justify-content: space-between;
  margin-bottom: 1.25rem;
}

.database-backup-card__title {
  align-items: center;
  color: #233247;
  display: flex;
  font-size: 1.1rem;
  font-weight: 700;
}

.database-backup-card__actions {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  justify-content: flex-end;
}

.database-backup-form-field {
  margin-bottom: 1rem;
}

.database-backup-form-field__label {
  color: #3b4a63;
  display: block;
  font-size: 0.875rem;
  margin-bottom: 0.45rem;
}

.database-backup-toggle-control {
  align-items: center;
  background: #fff;
  border: 1px solid #d8dbe0;
  border-radius: 0.25rem;
  color: #233247;
  display: flex;
  gap: 0.75rem;
  justify-content: space-between;
  min-height: 35px;
  padding: 0.35rem 0.75rem;
  text-align: left;
  width: 100%;
}

.database-backup-toggle-control:focus {
  box-shadow: 0 0 0 0.2rem rgba(46, 184, 92, 0.16);
  outline: 0;
}

.database-backup-toggle-control--active {
  background: #f4fff8;
  border-color: rgba(46, 184, 92, 0.6);
}

.database-backup-toggle-control--disabled {
  cursor: not-allowed;
  opacity: 0.68;
}

.database-backup-toggle-control__content {
  align-items: baseline;
  display: flex;
  gap: 0.65rem;
  min-width: 0;
}

.database-backup-toggle-control__status {
  font-weight: 600;
  white-space: nowrap;
}

.database-backup-toggle-control__next {
  color: #6c7684;
  font-size: 0.82rem;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.database-backup-toggle-control__switch {
  background: #d8dee8;
  border-radius: 999px;
  display: inline-flex;
  flex: 0 0 auto;
  height: 20px;
  padding: 2px;
  transition: background-color 0.2s ease;
  width: 38px;
}

.database-backup-toggle-control__switch span {
  background: #fff;
  border-radius: 999px;
  box-shadow: 0 1px 3px rgba(44, 52, 71, 0.22);
  display: block;
  height: 16px;
  transform: translateX(0);
  transition: transform 0.2s ease;
  width: 16px;
}

.database-backup-toggle-control--active .database-backup-toggle-control__switch {
  background: #2eb85c;
}

.database-backup-toggle-control--active .database-backup-toggle-control__switch span {
  transform: translateX(18px);
}

.database-backup-table__sub {
  color: #6c7684;
  font-size: 0.82rem;
  margin-top: 0.3rem;
}

.database-backup-table__actions {
  display: flex;
  gap: 0.45rem;
}

.database-backup-table__actions .btn {
  align-items: center;
  border-radius: 999px;
  display: inline-flex;
  height: 2rem;
  justify-content: center;
  padding: 0;
  width: 2rem;
}

.database-backup-checksum {
  display: inline-block;
  max-width: 10rem;
  overflow: hidden;
  text-overflow: ellipsis;
  vertical-align: middle;
  white-space: nowrap;
}

.database-backup-empty {
  background: #f7f9fc;
  border: 1px dashed rgba(196, 207, 221, 0.9);
  border-radius: 0.5rem;
  color: #6c7684;
  padding: 1rem;
  text-align: center;
}

.database-backup-history-preview {
  background: #f7f9fc;
  border: 1px solid rgba(221, 228, 236, 0.9);
  border-radius: 0.5rem;
  margin-bottom: 1rem;
  padding: 1rem;
}

@media (max-width: 767px) {
  .database-backup-card__header,
  .database-backup-card__actions {
    align-items: stretch;
    flex-direction: column;
  }

  .database-backup-card__actions .btn {
    width: 100%;
  }
}
</style>
