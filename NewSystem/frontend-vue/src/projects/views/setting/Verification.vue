<template>
  <div class="security-page">
    <AppSectionHero
      title="Setting Verification"
      subtitle="Manage verification definitions, related groups, and status mappings from one place."
      :meta-label="'Last updated'"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <ManagementTableBase
      title="Verification Management"
      icon="cil-shield-check"
      add-label="Add Verification"
      empty-message="No verification settings found"
      :items="items"
      :fields="fields"
      @add="openCreate"
      @edit="openEdit"
      @remove="removeItem"
    />

    <VerificationFormModal
      :show.sync="showModal"
      :title="modalTitle"
      :value="draft"
      :groups="groups"
      :statuses="statuses"
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
import VerificationFormModal from '@/projects/views/setting/components/VerificationFormModal'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'

function emptyDraft () {
  return { _id: null, titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }], descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }], groupId: '', statusId: '' }
}

export default {
  name: 'SettingVerification',
  components: { AppSectionHero, ManagementTableBase, VerificationFormModal },
  data () {
    return {
      showModal: false,
      lastUpdatedAt: null,
      draft: emptyDraft(),
      selectedItem: null,
      fields: [
        { key: 'titleTh', label: 'Title (TH)' },
        { key: 'titleEn', label: 'Title (EN)' },
        { key: 'groupName', label: 'Group' },
        { key: 'statusName', label: 'Status' },
        { key: 'actions', label: '#', _style: 'width:120px;text-align:center;' }
      ]
    }
  },
  computed: {
    ...mapGetters({
      items: 'setting/settingVerification/items',
      groups: 'setting/settingVerification/groups',
      statuses: 'setting/settingVerification/statuses'
    }),
    lastUpdatedLabel () { return formatDateTime24(this.lastUpdatedAt) },
    modalTitle () { return this.draft && this.draft._id ? 'Edit Verification' : 'Create Verification' }
  },
  created () {
    this.loadData()
  },
  methods: {
    loadData () {
      return this.$store.dispatch('setting/settingVerification/explorer')
        .then(() => { this.lastUpdatedAt = new Date() })
        .catch(() => notifyError(this.$store, 'Failed to load verification list.'))
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    openCreate () { this.draft = emptyDraft(); this.showModal = true },
    openEdit (item) {
      this.$store.dispatch('setting/settingVerification/toDraft', item)
        .then(v => { this.draft = v; this.showModal = true })
        .catch(() => notifyError(this.$store, 'Cannot load selected verification.'))
    },
    closeModal () { this.showModal = false; this.draft = emptyDraft() },
    saveItem (payload) {
      const action = payload && payload._id ? 'setting/settingVerification/update' : 'setting/settingVerification/create'
      return this.$store.dispatch(action, payload)
        .then(() => {
          notifySuccess(this.$store, payload && payload._id ? 'Verification updated.' : 'Verification created successfully.')
          this.closeModal()
        })
        .catch(() => notifyError(this.$store, 'Cannot save verification.'))
    },
    removeItem (item) {
      this.selectedItem = item
      return this.$store.dispatch('dialog/openConfirm', {
        title: 'Remove Verification',
        message: 'Are you sure you want to remove this verification setting?'
      }).then((confirmed) => {
        if (!confirmed) {
          this.selectedItem = null
          return
        }
        return this.$store.dispatch('setting/settingVerification/remove', this.selectedItem)
          .then(() => {
            notifyInfo(this.$store, 'Verification removed.')
            this.selectedItem = null
          })
          .catch(() => {
            notifyError(this.$store, 'Cannot remove verification.')
            this.selectedItem = null
          })
      })
    }
  }
}
</script>
