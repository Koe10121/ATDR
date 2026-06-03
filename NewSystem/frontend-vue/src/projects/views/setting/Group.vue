<template>
  <div class="security-page">
    <AppSectionHero
      title="Setting Group"
      subtitle="Maintain reusable master groups, language titles, and visibility state for downstream settings."
      :meta-label="'Last updated'"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <ManagementTableBase
      title="Group Management"
      icon="cil-people"
      add-label="Add Group"
      empty-message="No groups found"
      :items="items"
      :fields="fields"
      @add="openCreateModal"
      @edit="openEditModal"
      @remove="removeItem"
    >
      <template #state="{ item }">
        <td class="text-center">
          <CBadge :color="item.state ? 'success' : 'secondary'">
            {{ item.state ? 'Active' : 'Inactive' }}
          </CBadge>
        </td>
      </template>
    </ManagementTableBase>

    <GroupFormModal
      :show.sync="showModal"
      :title="modalTitle"
      :value="draft"
      @submit="saveItem"
      @invalid="handleInvalid"
      @cancel="closeModal"
    />
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import { formatDateTime24 } from '@/projects/utils/date-time'
import ManagementTableBase from '@/projects/views/setting/components/ManagementTableBase'
import GroupFormModal from '@/projects/views/setting/components/GroupFormModal'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'

function createEmptyDraft () {
  return {
    _id: null,
    key: '',
    titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    state: true
  }
}

export default {
  name: 'SettingGroup',
  components: {
    AppSectionHero,
    ManagementTableBase,
    GroupFormModal
  },
  data () {
    return {
      showModal: false,
      lastUpdatedAt: null,
      draft: createEmptyDraft(),
      selectedItem: null,
      fields: [
        { key: 'key', label: 'Key' },
        { key: 'titleTh', label: 'Title (TH)' },
        { key: 'titleEn', label: 'Title (EN)' },
        { key: 'descriptionTh', label: 'Description (TH)' },
        { key: 'descriptionEn', label: 'Description (EN)' },
        { key: 'state', label: 'State', _style: 'width: 180px; text-align: center;' },
        { key: 'actions', label: '#', _style: 'width: 120px; text-align: center;' }
      ]
    }
  },
  computed: {
    ...mapGetters({
      items: 'setting/settingGroup/items'
    }),
    modalTitle () {
      return this.draft && this.draft._id ? 'Edit Group' : 'Create Group'
    },
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    loadData () {
      return this.$store.dispatch('setting/settingGroup/explorer')
        .then(() => { this.lastUpdatedAt = new Date() })
        .catch(() => {
          notifyError(this.$store, 'Failed to load group list.')
        })
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    openCreateModal () {
      this.draft = createEmptyDraft()
      this.showModal = true
    },
    openEditModal (item) {
      this.$store.dispatch('setting/settingGroup/toDraft', item)
        .then((draft) => {
          this.draft = draft
          this.showModal = true
        })
        .catch(() => {
          notifyError(this.$store, 'Cannot load selected group.')
        })
    },
    closeModal () {
      this.draft = createEmptyDraft()
      this.showModal = false
    },
    saveItem (payload) {
      const action = payload && payload._id
        ? 'setting/settingGroup/update'
        : 'setting/settingGroup/create'

      return this.$store.dispatch(action, payload)
        .then(() => {
          notifySuccess(this.$store, payload && payload._id ? 'Group updated.' : 'Group created successfully.')
          this.closeModal()
        })
        .catch(() => {
          notifyError(this.$store, 'Cannot save group.')
        })
    },
    removeItem (item) {
      this.selectedItem = item
      return this.$store.dispatch('dialog/openConfirm', {
        title: 'Remove Group',
        message: 'Are you sure you want to remove this group?'
      }).then((confirmed) => {
        if (!confirmed) {
          this.selectedItem = null
          return
        }
        return this.confirmRemove()
      })
    },
    confirmRemove () {
      if (!this.selectedItem) return
      return this.$store.dispatch('setting/settingGroup/remove', this.selectedItem)
        .then(() => {
          notifyInfo(this.$store, 'Group removed.')
          this.selectedItem = null
        })
        .catch(() => {
          notifyError(this.$store, 'Cannot remove group.')
          this.selectedItem = null
        })
    }
  }
}
</script>
