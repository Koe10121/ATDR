<template>
  <div class="security-page">
    <AppSectionHero
      title="Setting Message Authen"
      subtitle="Manage login message banners, display periods, and activation state from one workflow."
      :meta-label="'Last updated'"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <CRow>
      <CCol col="12">
        <ManagementTableBase
          title="Setting Message Authen"
          icon="cil-envelope-open"
          add-label="Add Message"
          empty-message="No setting message authen found"
          :items="items"
          :fields="fields"
          @add="openCreateModal"
          @edit="openEditModal"
          @remove="removeItem"
        >
          <template #statusText="{ item }">
            <td class="text-center">
              <CBadge :color="item.isActive ? 'success' : 'secondary'" class="mr-2">
                {{ item.statusText }}
              </CBadge>
              <CSwitch
                class="d-inline-block align-middle"
                color="success"
                :checked="item.isActive"
                @update:checked="() => toggleStatus(item)"
              />
            </td>
          </template>
        </ManagementTableBase>
      </CCol>

      <MessageAuthenFormModal
        :show.sync="showModal"
        :title="modalTitle"
        :value="draft"
        @submit="saveItem"
        @invalid="handleInvalid"
        @cancel="closeModal"
      />
    </CRow>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import { formatDateTime24 } from '@/projects/utils/date-time'
import ManagementTableBase from '@/projects/views/setting/components/ManagementTableBase'
import MessageAuthenFormModal from '@/projects/views/setting/components/MessageAuthenFormModal'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'

function createEmptyDraft () {
  return {
    _id: null,
    titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    startDate: '',
    endDate: '',
    statusOption: 'active',
    createdByName: '',
    createdAt: ''
  }
}

export default {
  name: 'SettingMessageAuthen',
  components: {
    AppSectionHero,
    ManagementTableBase,
    MessageAuthenFormModal
  },
  data () {
    return {
      showModal: false,
      lastUpdatedAt: null,
      fields: [
        { key: 'titleText', label: 'Title' },
        { key: 'descriptionText', label: 'Description' },
        { key: 'periodText', label: 'Display Period' },
        { key: 'statusText', label: 'Status', _style: 'width: 220px; text-align: center;' },
        { key: 'actions', label: '#', _style: 'width: 120px; text-align: center;' }
      ],
      draft: createEmptyDraft(),
      selectedItem: null,
      
    }
  },
  computed: {
    ...mapGetters({
      items: 'setting/settingMessageAuthen/items'
    }),
    modalTitle () {
      return this.draft && this.draft._id ? 'Edit Setting Message Authen' : 'Create Setting Message Authen'
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
      return this.$store.dispatch('setting/settingMessageAuthen/explorer')
        .then(() => { this.lastUpdatedAt = new Date() })
        .catch(() => {
          notifyError(this.$store, 'Failed to load Setting Message Authen.')
        })
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    resetDraft () {
      this.draft = createEmptyDraft()
    },
    hasValidTitle (titleItems) {
      return Array.isArray(titleItems) && titleItems.some(item => {
        const hasKey = item && item.key && String(item.key).trim()
        const hasValue = item && item.value && String(item.value).trim()
        return hasKey && hasValue
      })
    },
    openCreateModal () {
      this.resetDraft()
      this.showModal = true
    },
    openEditModal (item) {
      this.$store.dispatch('setting/settingMessageAuthen/toDraft', item)
        .then((draft) => {
          this.draft = draft
          this.showModal = true
        })
        .catch(() => {
          notifyError(this.$store, 'Cannot load selected message.')
        })
    },
    closeModal () {
      this.resetDraft()
      this.showModal = false
    },
    saveItem (payload) {
      if (!this.hasValidTitle(payload.titleItems)) {
        notifyWarning(this.$store, 'Please provide at least one language title.')
        return
      }

      const action = payload._id ? 'setting/settingMessageAuthen/update' : 'setting/settingMessageAuthen/create'
      return this.$store.dispatch(action, payload)
        .then(() => {
          notifySuccess(this.$store, payload._id ? 'Login message updated.' : 'Login message created successfully.')
          this.closeModal()
        })
        .catch(() => {
          notifyError(this.$store, 'Cannot save login message.')
        })
    },
    removeItem (item) {
      this.selectedItem = item
      return this.$store.dispatch('dialog/openConfirm', {
        title: 'Remove Setting Message Authen',
        message: 'Are you sure you want to remove this login message?'
      }).then((confirmed) => {
        if (!confirmed) {
          this.selectedItem = null
          return
        }
        return this.confirmRemove()
      })
    },
    confirmRemove () {
      if (!this.selectedItem) {
        return
      }
      return this.$store.dispatch('setting/settingMessageAuthen/remove', this.selectedItem)
        .then(() => {
          notifyInfo(this.$store, 'Login message removed.')
          this.selectedItem = null
        })
        .catch(() => {
          notifyError(this.$store, 'Cannot remove login message.')
          this.selectedItem = null
        })
    },
    toggleStatus (item) {
      return this.$store.dispatch('setting/settingMessageAuthen/toggle', item)
        .then(() => {
          notifySuccess(this.$store, `Message ${item.isActive ? 'disabled' : 'enabled'}.`)
        })
        .catch((err) => {
          notifyError(this.$store, (err && err.message) || 'Cannot update message status.')
        })
    }
  }
}
</script>
