<template>
  <div class="security-page">
    <AppSectionHero
      :title="$t('security.permissionMatrix.title')"
      :subtitle="$t('security.permissionMatrix.subtitle')"
      :stats="heroStats"
      :meta-label="$t('security.permissionMatrix.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />
    <CRow>
      <CCol col="12">
        <PermissionMatrixTable
          :items="filteredPermissionRows"
          :fields="fields"
          @toggle="onToggle"
        >
          <template #header-actions>
            <div class="d-flex flex-wrap align-items-center mt-2 mt-md-0">
              <span class="small text-muted mr-2">{{ $t('security.permissionMatrix.selectedGroup') }}</span>
              <CSelect
                size="sm"
                class="permission-filter mr-2"
                :value.sync="selectedGroupId"
                :options="groupOptions"
              />
              <CSelect
                size="sm"
                class="permission-filter mr-2"
                :value.sync="selectedMenuType"
                :options="menuTypeOptions"
              />
            </div>
          </template>
        </PermissionMatrixTable>
      </CCol>
    </CRow>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import PermissionMatrixTable from '@/projects/views/security/components/PermissionMatrixTable'
import { formatDateTime24 } from '@/projects/utils/date-time'
import { notifyError } from '@/projects/utils/notify'
import { getTextByLanguage } from '@/store/modules/Security/shared'

export default {
  name: 'PermissionMatrix',
  components: { AppSectionHero, PermissionMatrixTable },
  data () {
    return {
      lastUpdatedAt: null,
      selectedGroupId: '',
      selectedMenuType: 'all'
    }
  },
  computed: {
    ...mapGetters({
      groups: 'security/permissionMatrix/groups',
      types: 'security/permissionMatrix/types',
      menus: 'security/permissionMatrix/menus',
      permissions: 'security/permissionMatrix/permissions',
      currentLang: 'setting/lang'
    }),
    fields () {
      return [
        { key: 'menu', label: this.$t('security.permissionMatrix.fields.menu') },
        { key: 'type', label: this.$t('security.permissionMatrix.fields.type') },
        { key: 'path', label: this.$t('security.permissionMatrix.fields.path') },
        { key: 'source', label: this.$t('security.permissionMatrix.fields.source') },
        { key: 'all', label: this.$t('security.permissionMatrix.fields.all'), _style: 'width: 100px; text-align: center;' },
        { key: 'view', label: this.$t('security.permissionMatrix.fields.view'), _style: 'width: 100px; text-align: center;' },
        { key: 'edit', label: this.$t('security.permissionMatrix.fields.edit'), _style: 'width: 100px; text-align: center;' },
        { key: 'delete', label: this.$t('security.permissionMatrix.fields.delete'), _style: 'width: 100px; text-align: center;' },
        { key: 'action', label: this.$t('security.permissionMatrix.fields.action'), _style: 'width: 100px; text-align: center;' },
        { key: 'logs', label: this.$t('security.permissionMatrix.fields.logs'), _style: 'width: 100px; text-align: center;' }
      ]
    },
    heroStats () {
      const visibleRows = this.filteredPermissionRows
      return [
        { label: this.$t('security.permissionMatrix.selectedGroup'), value: this.selectedGroupName, icon: 'cil-people', iconClass: 'security-stat__icon--primary' },
        { label: this.$t('security.permissionMatrix.menus'), value: this.menus.length, icon: 'cil-list', iconClass: 'security-stat__icon--success' },
        { label: this.$t('security.permissionMatrix.visibleRules'), value: visibleRows.length, icon: 'cil-shield-alt', iconClass: 'security-stat__icon--warning' }
      ]
    },
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    groupOptions () {
      return this.groups.map(group => ({
        value: group._id,
        label: getTextByLanguage(group.title, this.currentLang) || group.name
      }))
    },
    selectedGroup () {
      return this.groups.find(group => group && group._id === this.selectedGroupId) || null
    },
    selectedGroupName () {
      return this.selectedGroup
        ? (getTextByLanguage(this.selectedGroup.title, this.currentLang) || this.selectedGroup.name)
        : '-'
    },
    menuTypeOptions () {
      return [{ value: 'all', label: this.$t('security.permissionMatrix.allTypes') }, ...this.types.map(type => ({
        value: type._id,
        label: getTextByLanguage(type.title, this.currentLang) || type.name
      }))]
    },
    permissionTableRows () {
      const map = {}
      this.permissions.forEach(row => {
        map[`${row.groupId}:${row.menuId}`] = row
      })

      const rows = []
      this.groups.forEach(group => {
        this.menus.forEach(menu => {
          if (group.visibleTypeId && menu.typeId && group.visibleTypeId !== menu.typeId) return
          const key = `${group._id}:${menu._id}`
          const current = map[key] || {}
          rows.push({
            _id: current._id || null,
            groupId: group._id,
            menuId: menu._id,
            all: !!current.all,
            view: !!current.view,
            edit: !!current.edit,
            delete: !!current.delete,
            action: !!current.action,
            logs: !!current.logs,
            group: getTextByLanguage(group.title, this.currentLang) || group.name,
            menu: getTextByLanguage(menu.title, this.currentLang) || menu.name,
            type: this.resolveTypeName(menu.typeId) || '-',
            path: menu.path || '-',
            source: menu.source || '-'
          })
        })
      })
      return rows
    },
    filteredPermissionRows () {
      let rows = this.permissionTableRows
      if (this.selectedGroupId) {
        rows = rows.filter(row => row.groupId === this.selectedGroupId)
      }
      if (this.selectedMenuType !== 'all') {
        rows = rows.filter(row => {
          const menu = this.menus.find(item => item._id === row.menuId)
          return menu && menu.typeId === this.selectedMenuType
        })
      }
      return rows
    }
  },
  async created () {
    await this.loadData()
  },
  methods: {
    ensureSelectedGroup () {
      const groupIds = this.groups.map(group => group && group._id).filter(Boolean)
      if (!groupIds.length) {
        this.selectedGroupId = ''
        return
      }
      if (!groupIds.includes(this.selectedGroupId)) {
        this.selectedGroupId = groupIds[0]
      }
    },
    resolveTypeName (typeId) {
      const type = this.types.find(item => item && item._id === typeId)
      return type ? (getTextByLanguage(type.title, this.currentLang) || type.name) : ''
    },
    async loadData () {
      try {
        await this.$store.dispatch('security/permissionMatrix/explorer')
        this.ensureSelectedGroup()
        this.lastUpdatedAt = new Date()
      } catch (err) {
        notifyError(this.$store, this.$t('security.permissionMatrix.messages.loadError'))
      }
    },
    async onToggle (row, key, checked) {
      const working = {
        _id: row._id || null,
        groupId: row.groupId,
        menuId: row.menuId,
        all: !!row.all,
        view: !!row.view,
        edit: !!row.edit,
        delete: !!row.delete,
        action: !!row.action,
        logs: !!row.logs
      }

      if (!working._id) {
        Object.assign(working, {
          _id: null,
          groupId: row.groupId,
          menuId: row.menuId,
          all: false,
          view: false,
          edit: false,
          delete: false,
          action: false,
          logs: false
        })
      }

      if (key === 'all') {
        working.all = checked
        working.view = checked
        working.edit = checked
        working.delete = checked
        working.action = checked
        working.logs = checked
      } else {
        working[key] = checked
        working.all = working.view && working.edit && working.delete && working.action && working.logs
      }

      try {
        await this.$store.dispatch('security/permissionMatrix/save', working)
      } catch (err) {
        notifyError(this.$store, this.$t('security.permissionMatrix.messages.saveError'))
      }
    }
  },
  watch: {
    groups () {
      this.ensureSelectedGroup()
    }
  }
}
</script>

<style scoped lang="scss">
@import "./security-page.shared";

.permission-filter {
  min-width: 180px;
}
</style>
