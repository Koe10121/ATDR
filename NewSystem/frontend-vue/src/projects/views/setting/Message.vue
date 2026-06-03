<template>
  <div class="security-page">
    <AppSectionHero
      title="Setting Message"
      subtitle="Manage localized message templates and keep reusable communication copy aligned."
      :meta-label="'Last updated'"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <ManagementTableBase
      title="Message Management"
      icon="cil-description"
      add-label="Add Message"
      empty-message="No messages found"
      :items="items"
      :fields="fields"
      @add="openCreate"
      @edit="openEdit"
      @remove="removeItem"
    />

    <MessageFormModal
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
import MessageFormModal from '@/projects/views/setting/components/MessageFormModal'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'

function emptyDraft () {
  return {
    _id: null,
    number: 0,
    code: 0,
    messageItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }]
  }
}

export default {
  name: 'SettingMessage',
  components: { AppSectionHero, ManagementTableBase, MessageFormModal },
  data () {
    return {
      showModal: false,
      lastUpdatedAt: null,
      draft: emptyDraft(),
      selectedItem: null,
      fields: [
        { key: 'number', label: 'Number' },
        { key: 'code', label: 'Code' },
        { key: 'messageTh', label: 'Message (TH)' },
        { key: 'messageEn', label: 'Message (EN)' },
        { key: 'descriptionTh', label: 'Description (TH)' },
        { key: 'descriptionEn', label: 'Description (EN)' },
        { key: 'actions', label: '#', _style: 'width: 120px; text-align:center;' }
      ]
    }
  },
  computed: {
    ...mapGetters({ items: 'setting/settingMessage/items' }),
    lastUpdatedLabel () { return formatDateTime24(this.lastUpdatedAt) },
    modalTitle () { return this.draft && this.draft._id ? 'Edit Message' : 'Create Message' }
  },
  created () {
    this.loadData()
  },
  methods: {
    loadData () {
      return this.$store.dispatch('setting/settingMessage/explorer')
        .then(() => { this.lastUpdatedAt = new Date() })
        .catch(() => notifyError(this.$store, 'Failed to load message list.'))
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    openCreate () { this.draft = emptyDraft(); this.showModal = true },
    openEdit (item) {
      this.$store.dispatch('setting/settingMessage/toDraft', item)
        .then(v => { this.draft = v; this.showModal = true })
        .catch(() => notifyError(this.$store, 'Cannot load selected message.'))
    },
    closeModal () { this.showModal = false; this.draft = emptyDraft() },
    saveItem (payload) {
      const action = payload && payload._id ? 'setting/settingMessage/update' : 'setting/settingMessage/create'
      return this.$store.dispatch(action, payload)
        .then(() => {
          notifySuccess(this.$store, payload && payload._id ? 'Message updated.' : 'Message created successfully.')
          this.closeModal()
        })
        .catch(() => notifyError(this.$store, 'Cannot save message.'))
    },
    removeItem (item) {
      this.selectedItem = item
      return this.$store.dispatch('dialog/openConfirm', {
        title: 'Remove Message',
        message: 'Are you sure you want to remove this message?'
      }).then((confirmed) => {
        if (!confirmed) {
          this.selectedItem = null
          return
        }
        return this.$store.dispatch('setting/settingMessage/remove', this.selectedItem)
          .then(() => {
            notifyInfo(this.$store, 'Message removed.')
            this.selectedItem = null
          })
          .catch(() => {
            notifyError(this.$store, 'Cannot remove message.')
            this.selectedItem = null
          })
      })
    }
  }
}
</script>
