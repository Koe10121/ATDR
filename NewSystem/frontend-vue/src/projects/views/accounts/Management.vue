<template>
  <div class="account-page">
    <AppSectionHero
      :title="$t('accounts.directory.title')"
      :subtitle="$t('accounts.directory.subtitle')"
      :stats="heroStats"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <AccountDirectoryTable
      :items="items"
      @invite="openInviteModal"
      @edit="openEditModal"
      @access="openPermissionsModal"
      @remove-newSystem-access="removeNewSystemAccess"
    />

    <InviteAccountModal
      :show.sync="showInviteModal"
      :group-options="groupOptions"
      @submit="submitInvite"
      @cancel="closeInviteModal"
    />

    <EditAccountModal
      :show.sync="showEditModal"
      :value="selectedAccount"
      :status-options="statusOptions"
      :group-options="groupOptions"
      @submit="submitAccountUpdate"
      @cancel="closeEditModal"
    />

    <AccountPermissionsModal
      :show.sync="showPermissionsModal"
      :account="selectedAccount"
      :groups="accessGroups"
      :permissions="accessPermissions"
      :sessions="accountSessions"
      :trusted-devices="trustedDevices"
      @revoke-session="revokeSession"
      @revoke-trusted-device="revokeTrustedDevice"
      @close="closePermissionsModal"
    />
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import AccountDirectoryTable from './components/AccountDirectoryTable'
import InviteAccountModal from './InviteAccountModal'
import EditAccountModal from './EditAccountModal'
import AccountPermissionsModal from './AccountPermissionsModal'
import { notifyError, notifyInfo, notifySuccess } from '@/projects/utils/notify'

export default {
  name: 'AccountManagement',
  components: { AppSectionHero, AccountDirectoryTable, InviteAccountModal, EditAccountModal, AccountPermissionsModal },
  data () {
    return {
      showEditModal: false,
      showPermissionsModal: false,
      showInviteModal: false,
      selectedAccount: null
    }
  },
  computed: {
    ...mapGetters({
      items: 'accounts/items',
      lastUpdatedLabel: 'accounts/lastUpdatedLabel',
      statusOptions: 'accounts/statusOptions',
      groupOptions: 'accounts/groupOptions',
      accessGroups: 'accounts/accessGroups',
      accessPermissions: 'accounts/accessPermissions',
      accountSessions: 'accounts/accountSessions',
      trustedDevices: 'accounts/trustedDevices'
    }),
    activeCount () {
      return this.items.filter(item => item && item.statusKey === 'ACTIVE').length
    },
    attentionCount () {
      return this.items.filter(item => item && ['LOCKED', 'SUSPENDED', 'PENDING'].includes(item.statusKey)).length
    },
    heroStats () {
      return [
        { label: this.$t('accounts.directory.stats.total.label'), value: this.items.length, hint: this.$t('accounts.directory.stats.total.hint'), icon: 'cil-people', iconClass: 'app-section-stat__icon--total' },
        { label: this.$t('accounts.directory.stats.active.label'), value: this.activeCount, hint: this.$t('accounts.directory.stats.active.hint'), icon: 'cil-check-circle', iconClass: 'app-section-stat__icon--active' },
        { label: this.$t('accounts.directory.stats.attention.label'), value: this.attentionCount, hint: this.$t('accounts.directory.stats.attention.hint'), icon: 'cil-warning', iconClass: 'app-section-stat__icon--attention' }
      ]
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    async loadData () {
      try {
        await this.$store.dispatch('accounts/explorer')
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.loadError'))
      }
    },
    openEditModal (item) {
      if (!(item && item._id)) return
      this.selectedAccount = item
      this.showEditModal = true
    },
    openInviteModal () {
      this.showInviteModal = true
    },
    closeInviteModal () {
      this.showInviteModal = false
    },
    async submitInvite (payload) {
      try {
        await this.$store.dispatch('accounts/invite', payload)
        notifySuccess(this.$store, this.$t('accounts.directory.messages.inviteSuccess'))
        this.closeInviteModal()
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.inviteError'))
      }
    },
    async openPermissionsModal (item) {
      if (!(item && item._id)) return
      try {
        await this.$store.dispatch('accounts/fetchAccessReview', item._id)
        this.selectedAccount = item
        this.showPermissionsModal = true
        await Promise.all([
          this.$store.dispatch('accounts/fetchSessions', item._id).catch(() => null),
          this.$store.dispatch('accounts/fetchTrustedDevices', item._id).catch(() => null)
        ])
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.loadSecurityWorkspaceError'))
      }
    },
    async submitAccountUpdate (payload) {
      try {
        await this.$store.dispatch('accounts/update', payload)
        notifySuccess(this.$store, this.$t('accounts.directory.messages.updateSuccess'))
        this.closeEditModal()
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.updateError'))
      }
    },
    async removeNewSystemAccess (item) {
      if (!(item && item._id)) return
      try {
        const accountLabel = item.email || item.fullName || 'this account'
        const confirmed = await this.$store.dispatch('dialog/openConfirm', {
          title: this.$t('accounts.directory.messages.removeConfirmTitle'),
          message: this.$t('accounts.directory.messages.removeConfirmMessage', { account: accountLabel }),
          confirmText: this.$t('accounts.directory.actions.remove'),
          confirmIcon: 'cil-trash'
        })
        if (!confirmed) return
        await this.$store.dispatch('accounts/removeNewSystemAccess', item)
        notifyInfo(this.$store, this.$t('accounts.directory.messages.removeSuccess'))
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.removeError'))
      }
    },
    async revokeSession (session) {
      if (!(this.selectedAccount && this.selectedAccount._id && session && session._id)) return
      try {
        await this.$store.dispatch('accounts/revokeSession', {
          id: this.selectedAccount._id,
          sessionId: session._id
        })
        notifyInfo(this.$store, this.$t('accounts.directory.messages.revokeSessionSuccess'))
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.revokeSessionError'))
      }
    },
    async revokeTrustedDevice (device) {
      if (!(this.selectedAccount && this.selectedAccount._id && device && device._id)) return
      try {
        await this.$store.dispatch('accounts/revokeTrustedDevice', {
          id: this.selectedAccount._id,
          trustedDeviceId: device._id
        })
        notifyInfo(this.$store, this.$t('accounts.directory.messages.revokeTrustedDeviceSuccess'))
      } catch (error) {
        notifyError(this.$store, this.$t('accounts.directory.messages.revokeTrustedDeviceError'))
      }
    },
    closeEditModal () {
      this.showEditModal = false
      this.selectedAccount = null
    },
    closePermissionsModal () {
      this.showPermissionsModal = false
      this.selectedAccount = null
      this.$store.commit('accounts/clearSecurityWorkspace')
    }
  }
}
</script>

<style scoped lang="scss">
.account-page {}
</style>
