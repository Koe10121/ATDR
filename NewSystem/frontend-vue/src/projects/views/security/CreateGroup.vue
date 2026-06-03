<template>
  <div class="security-page">
    <AppSectionHero
      :title="$t('security.createGroup.title')"
      :subtitle="$t('security.createGroup.subtitle')"
      :stats="heroStats"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />
    <CRow>
      <CCol col="12">
        <GroupManagementTable
          :items="groupTableItems"
          :fields="fields"
          @add="openCreateGroupModal"
          @edit="openEditGroupModal"
          @remove="removeGroup"
        />
      </CCol>

      <GroupFormModal
        :show.sync="groupModal"
        :title="groupDraft._id ? $t('security.createGroup.editGroup') : $t('security.createGroup.title')"
        :value="groupDraft"
        :visible-type-options="visibleTypeOptions"
        @submit="saveGroup"
        @invalid="handleInvalid"
        @cancel="closeGroupModal"
      />
    </CRow>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import GroupManagementTable from '@/projects/views/security/components/GroupManagementTable'
import GroupFormModal from '@/projects/views/security/components/GroupFormModal'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import { formatDateTime24 } from '@/projects/utils/date-time'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'
import { normalizeOrDefault } from '@/projects/views/security/components/security-multilang.shared'
import { getTextByLanguage } from '@/store/modules/Security/shared'

const createGroupDraft = (defaultVisibleTypeId = '') => ({
  _id: null,
  title: normalizeOrDefault([]),
  description: normalizeOrDefault([]),
  visibleTypeId: defaultVisibleTypeId,
  state: true
})

export default {
  name: 'CreateGroup',
  components: {
    AppSectionHero,
    GroupManagementTable,
    GroupFormModal
  },
  data () {
    return {
      groupModal: false,
      lastUpdatedAt: null,
      groupDraft: createGroupDraft()
    }
  },
  computed: {
    ...mapGetters({
      groups: 'security/group/groups',
      types: 'security/group/types',
      currentLang: 'setting/lang'
    }),
    fields () {
      return [
        { key: 'name', label: this.$t('security.createGroup.fields.groupTitle') },
        { key: 'descriptionText', label: this.$t('common.description') },
        { key: 'visibleTypeName', label: this.$t('security.createGroup.fields.visibleType') },
        { key: 'stateLabel', label: this.$t('common.status.label') },
        { key: 'actions', label: '', _style: 'width: 200px; text-align: center;' }
      ]
    },
    heroStats () {
      return [
        { label: this.$t('security.createGroup.stats.groups'), value: this.groups.length, icon: 'cil-people', iconClass: 'security-stat__icon--primary' },
        { label: this.$t('security.createGroup.stats.visibleTypes'), value: this.types.length, icon: 'cil-layers', iconClass: 'security-stat__icon--success' },
        { label: this.$t('security.createGroup.stats.readyToAssign'), value: this.groups.filter(item => item && item.visibleTypeId).length, icon: 'cil-check-circle', iconClass: 'security-stat__icon--warning' }
      ]
    },
    visibleTypeOptions () {
      return this.types.map(type => ({
        value: type._id,
        label: getTextByLanguage(type.title, this.currentLang) || type.name
      }))
    },
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    groupTableItems () {
      return this.groups.map(group => ({
        ...group,
        name: getTextByLanguage(group.title, this.currentLang) || group.name,
        descriptionText: getTextByLanguage(group.description, this.currentLang) || group.descriptionText,
        visibleTypeName: this.resolveVisibleTypeName(group.visibleTypeId)
      }))
    }
  },
  async created () {
    await this.loadData()
  },
  methods: {
    resolveVisibleTypeName (typeId) {
      const type = this.types.find(item => item && item._id === typeId)
      return type ? (getTextByLanguage(type.title, this.currentLang) || type.name) : ''
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    async loadData () {
      try {
        await this.$store.dispatch('security/group/explorer')
        this.lastUpdatedAt = new Date()
      } catch (err) {
        notifyError(this.$store, this.$t('security.messages.loadError'))
      }
    },
    openCreateGroupModal () {
      this.groupDraft = createGroupDraft(this.types[0] ? this.types[0]._id : '')
      this.groupModal = true
    },
    openEditGroupModal (group) {
      this.groupDraft = {
        _id: group._id,
        title: normalizeOrDefault(group && group.title),
        description: normalizeOrDefault(group && group.description),
        visibleTypeId: group.visibleTypeId || (this.types[0] ? this.types[0]._id : ''),
        state: typeof group.state === 'boolean' ? group.state : true
      }
      this.groupModal = true
    },
    async saveGroup (payload) {
      try {
        if (payload._id) {
          await this.$store.dispatch('security/group/update', payload)
          notifySuccess(this.$store, this.$t('security.createGroup.messages.groupUpdated'))
        } else {
          await this.$store.dispatch('security/group/create', payload)
          notifySuccess(this.$store, this.$t('security.createGroup.messages.groupCreated'))
        }
        this.closeGroupModal()
      } catch (err) {
        notifyError(this.$store, this.$t('security.createGroup.messages.cannotSave'))
      }
    },
    async removeGroup (group) {
      try {
        await this.$store.dispatch('security/group/remove', group)
        notifyInfo(this.$store, this.$t('security.createGroup.messages.groupRemoved'))
      } catch (err) {
        notifyError(this.$store, this.$t('security.createGroup.messages.cannotRemove'))
      }
    },
    closeGroupModal () {
      this.groupDraft = createGroupDraft(this.types[0] ? this.types[0]._id : '')
      this.groupModal = false
    }
  }
}
</script>

<style scoped lang="scss">
@import "./security-page.shared";
</style>
