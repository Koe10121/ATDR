<template>
  <div class="security-page">
    <AppSectionHero
      :title="$t('setting.status.title')"
      :subtitle="$t('setting.status.subtitle')"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <ManagementTableBase
      :title="$t('setting.status.tableTitle')"
      icon="cil-tags"
      :add-label="$t('setting.status.add')"
      :empty-message="$t('setting.status.empty')"
      :items="localizedItems"
      :fields="fields"
      @add="openCreateModal"
      @edit="openEditModal"
      @remove="removeItem"
    >
      <template #state="{ item }">
        <td class="text-center">
          <CBadge :color="item.state ? 'success' : 'secondary'">
            {{ item.statusLabel }}
          </CBadge>
        </td>
      </template>
    </ManagementTableBase>

    <StatusFormModal
      :show.sync="showModal"
      :title="modalTitle"
      :value="draft"
      :groups="groups"
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
import StatusFormModal from '@/projects/views/setting/components/StatusFormModal'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'

function pickLocalizedText (items, lang) {
  const normalized = Array.isArray(items) ? items : []
  const direct = normalized.find(item => item && item.key === lang && item.value)
  if (direct) return direct.value
  const fallbackEn = normalized.find(item => item && item.key === 'en' && item.value)
  if (fallbackEn) return fallbackEn.value
  const fallbackTh = normalized.find(item => item && item.key === 'th' && item.value)
  if (fallbackTh) return fallbackTh.value
  const first = normalized.find(item => item && item.value)
  return first ? first.value : ''
}

function createEmptyDraft () {
  return {
    _id: null,
    groupId: '',
    key: '',
    titleItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    descriptionItems: [{ key: 'th', value: '' }, { key: 'en', value: '' }],
    state: true
  }
}

export default {
  name: 'SettingStatus',
  components: {
    AppSectionHero,
    ManagementTableBase,
    StatusFormModal
  },
  data () {
    return {
      showModal: false,
      lastUpdatedAt: null,
      draft: createEmptyDraft(),
      selectedItem: null,
    }
  },
  computed: {
    ...mapGetters({
      items: 'setting/settingStatus/items',
      groups: 'setting/settingStatus/groups'
    }),
    activeLang () {
      return String(this.$i18n.locale || 'th').toLowerCase()
    },
    localizedItems () {
      return (this.items || []).map(item => Object.assign({}, item, {
        titleText: pickLocalizedText(item && item.titleItems, this.activeLang),
        descriptionText: pickLocalizedText(item && item.descriptionItems, this.activeLang),
        statusLabel: item && item.state ? this.$t('common.status.active') : this.$t('common.status.inactive')
      }))
    },
    fields () {
      return [
        { key: 'groupName', label: this.$t('setting.status.fields.group') },
        { key: 'key', label: this.$t('setting.status.fields.key') },
        { key: 'titleText', label: this.$t('setting.status.fields.title') },
        { key: 'descriptionText', label: this.$t('setting.status.fields.description') },
        { key: 'state', label: this.$t('setting.status.fields.state'), _style: 'width: 180px; text-align: center;' },
        { key: 'actions', label: '#', _style: 'width: 120px; text-align: center;' }
      ]
    },
    modalTitle () {
      return this.draft && this.draft._id ? this.$t('setting.status.editTitle') : this.$t('setting.status.createTitle')
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
      return this.$store.dispatch('setting/settingStatus/explorer')
        .then(() => { this.lastUpdatedAt = new Date() })
        .catch(() => {
          notifyError(this.$store, this.$t('setting.status.messages.loadError'))
        })
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    openCreateModal () {
      this.draft = Object.assign(createEmptyDraft(), {
        groupId: this.groups && this.groups[0] ? this.groups[0]._id : ''
      })
      this.showModal = true
    },
    openEditModal (item) {
      this.$store.dispatch('setting/settingStatus/toDraft', item)
        .then((draft) => {
          this.draft = draft
          this.showModal = true
        })
        .catch(() => {
          notifyError(this.$store, this.$t('setting.status.messages.loadSelectedError'))
        })
    },
    closeModal () {
      this.draft = Object.assign(createEmptyDraft(), {
        groupId: this.groups && this.groups[0] ? this.groups[0]._id : ''
      })
      this.showModal = false
    },
    saveItem (payload) {
      const action = payload && payload._id
        ? 'setting/settingStatus/update'
        : 'setting/settingStatus/create'

      return this.$store.dispatch(action, payload)
        .then(() => {
          notifySuccess(this.$store, payload && payload._id ? this.$t('setting.status.messages.updated') : this.$t('setting.status.messages.created'))
          this.closeModal()
        })
        .catch(() => {
          notifyError(this.$store, this.$t('setting.status.messages.saveError'))
        })
    },
    removeItem (item) {
      this.selectedItem = item
      return this.$store.dispatch('dialog/openConfirm', {
        title: this.$t('setting.status.messages.removeTitle'),
        message: this.$t('setting.status.messages.removeConfirm')
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
      return this.$store.dispatch('setting/settingStatus/remove', this.selectedItem)
        .then(() => {
          notifyInfo(this.$store, this.$t('setting.status.messages.removed'))
          this.selectedItem = null
        })
        .catch(() => {
          notifyError(this.$store, this.$t('setting.status.messages.removeError'))
          this.selectedItem = null
        })
    }
  }
}
</script>
