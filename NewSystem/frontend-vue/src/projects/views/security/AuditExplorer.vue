<template>
  <div class="security-page">
    <AppSectionHero
      :title="$t('security.auditExplorer.title')"
      :subtitle="$t('security.auditExplorer.subtitle')"
      :stats="heroStats"
      :meta-label="$t('security.auditExplorer.eventsLoaded')"
      :meta-value="String(items.length)"
      @refresh="loadData"
    />

    <CCard>
      <CCardBody>
        <div class="d-flex flex-wrap align-items-center mb-3">
          <CInput v-model.trim="filters.module" :placeholder="$t('security.auditExplorer.filters.module')" class="mr-2 mb-2 audit-filter" />
          <CInput v-model.trim="filters.action" :placeholder="$t('security.auditExplorer.filters.action')" class="mr-2 mb-2 audit-filter" />
          <CInput v-model.trim="filters.actorId" :placeholder="$t('security.auditExplorer.filters.actorId')" class="mr-2 mb-2 audit-filter" />
          <CInput v-model.trim="filters.resourceId" :placeholder="$t('security.auditExplorer.filters.resourceId')" class="mr-2 mb-2 audit-filter" />
          <CButton color="dark" class="mb-2" @click="loadData">{{ $t('common.actions.apply') }}</CButton>
          <CButton color="light" class="mb-2 ml-2" @click="exportCsv">{{ $t('common.actions.exportCsv') }}</CButton>
        </div>

        <CDataTable
          :items="items"
          :fields="fields"
          hover
          striped
          :items-per-page="10"
          pagination
        >
          <template #detail="{ item }">
            <td>
              <span class="audit-detail">{{ stringify(item.detail) }}</span>
            </td>
          </template>
        </CDataTable>
      </CCardBody>
    </CCard>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import { notifyError } from '@/projects/utils/notify'

export default {
  name: 'AuditExplorer',
  components: { AppSectionHero },
  data () {
    return {
      filters: {
        module: '',
        action: '',
        actorId: '',
        resourceId: '',
        limit: 100
      }
    }
  },
  computed: {
    ...mapGetters({
      items: 'security/audit/items'
    }),
    fields () {
      return [
        { key: 'createdAt', label: this.$t('security.auditExplorer.fields.timestamp') },
        { key: 'module', label: this.$t('security.auditExplorer.fields.module') },
        { key: 'action', label: this.$t('security.auditExplorer.fields.action') },
        { key: 'actorId', label: this.$t('security.auditExplorer.fields.actor') },
        { key: 'resourceId', label: this.$t('security.auditExplorer.fields.resource') },
        { key: 'ip', label: this.$t('security.auditExplorer.fields.ip') },
        { key: 'detail', label: this.$t('security.auditExplorer.fields.detail') }
      ]
    },
    heroStats () {
      return [
        { label: this.$t('security.auditExplorer.stats.events'), value: this.items.length, icon: 'cil-description', iconClass: 'security-stat__icon--warning' },
        { label: this.$t('security.auditExplorer.stats.auth'), value: this.items.filter(item => item.module === 'auth').length, icon: 'cil-lock-locked', iconClass: 'security-stat__icon--primary' },
        { label: this.$t('security.auditExplorer.stats.accounts'), value: this.items.filter(item => item.module === 'accounts').length, icon: 'cil-people', iconClass: 'security-stat__icon--success' }
      ]
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    async loadData () {
      try {
        await this.$store.dispatch('security/audit/explorer', this.filters)
      } catch (error) {
        notifyError(this.$store, this.$t('security.auditExplorer.messages.loadError'))
      }
    },
    stringify (value) {
      if (!value) return '-'
      try {
        return JSON.stringify(value)
      } catch (err) {
        return '-'
      }
    },
    exportCsv () {
      const rows = [
        ['createdAt', 'module', 'action', 'actorId', 'resourceId', 'targetId', 'ip', 'detail']
      ].concat(this.items.map(item => ([
        item.createdAt || '',
        item.module || '',
        item.action || '',
        item.actorId || '',
        item.resourceId || '',
        item.targetId || '',
        item.ip || '',
        this.stringify(item.detail)
      ])))

      const csv = rows.map(row => row.map(value => `"${String(value).replace(/"/g, '""')}"`).join(',')).join('\n')
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', this.$t('security.auditExplorer.exportFile'))
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    }
  }
}
</script>

<style scoped lang="scss">
.audit-filter {
  min-width: 180px;
}

.audit-detail {
  display: inline-block;
  max-width: 420px;
  white-space: normal;
  word-break: break-word;
  font-family: monospace;
  font-size: 0.75rem;
}
</style>
