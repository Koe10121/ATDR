<template>
  <CModal :show="show" @update:show="onShowChange" size="md" class="account-invite-modal" add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="account-modal__header">
      <div class="account-modal__hero">
        <div>
          <div class="account-modal__title">{{ $t('accounts.directory.messages.inviteTitle') }}</div>
          <div class="account-modal__subtitle">{{ $t('accounts.directory.messages.inviteSubtitle') }}</div>
        </div>
      </div>
    </div>

    <div class="account-modal__body">
      <div class="account-modal__section">
        <CPInput
          v-model.trim="local.email"
          type="email"
          :label="$t('accounts.directory.invite.email')"
          icon="cil-envelope-closed"
          required
          wrapper-class="account-invite-modal__field"
        />
        <div class="account-invite-modal__grid">
          <CPInput
            v-model.trim="local.firstName"
            :label="$t('accounts.directory.invite.firstName')"
            wrapper-class="account-invite-modal__field"
          />
          <CPInput
            v-model.trim="local.lastName"
            :label="$t('accounts.directory.invite.lastName')"
            wrapper-class="account-invite-modal__field"
          />
        </div>
        <div class="account-invite-modal__select">
          <CPSelect
            v-model="groupSelection"
            :options="inviteGroupOptions"
            :label="$t('accounts.directory.invite.groups')"
            multiple
            required
            :close-on-select="true"
            :allow-empty="false"
            @change="onGroupChange"
          />
        </div>
        <div v-if="groupError" class="account-invite-modal__error">{{ $t('accounts.directory.invite.groupRequired') }}</div>
      </div>
    </div>

    <template #footer-wrapper>
      <div class="account-modal__footer">
        <CButton color="dark" variant="outline" class="mr-2 account-modal__btn" @click="onCancel">
          <CIcon name="cil-ban" class="mr-1" />
          {{ $t('common.actions.cancel') }}
        </CButton>
        <CButton color="success" variant="outline" class="account-modal__btn" @click="onSubmit">
          <CIcon name="cil-envelope-open" class="mr-1" />
          {{ $t('accounts.directory.actions.invite') }}
        </CButton>
      </div>
    </template>
  </CModal>
</template>

<script>
import CPInput from '@/projects/components/custom/CPInput'
import CPSelect from '@/projects/components/custom/CPSelect'

export default {
  name: 'InviteAccountModal',
  components: { CPInput, CPSelect },
  props: {
    show: { type: Boolean, default: false },
    groupOptions: { type: Array, default: () => [] }
  },
  data () {
    return {
      groupError: false,
      groupSelection: [],
      local: {
        email: '',
        firstName: '',
        lastName: '',
        groupIds: []
      }
    }
  },
  computed: {
    inviteGroupOptions () {
      return this.groupOptions.map(group => ({
        value: String(group._id || ''),
        label: group.label || group.name || String(group._id || '')
      })).filter(group => group.value)
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (!value) return
        this.resetForm()
      }
    }
  },
  methods: {
    resetForm () {
      this.groupSelection = []
      this.groupError = false
      this.local = {
        email: '',
        firstName: '',
        lastName: '',
        groupIds: []
      }
    },
    onShowChange (value) {
      this.$emit('update:show', value)
      if (!value) this.$emit('cancel')
    },
    onCancel () {
      this.$emit('update:show', false)
      this.$emit('cancel')
    },
    onGroupChange (value) {
      const selected = Array.isArray(value) ? value : []
      this.groupSelection = selected
      this.local.groupIds = selected.map(group => group && group.value).filter(Boolean)
      this.groupError = false
    },
    onSubmit () {
      if (!this.local.groupIds.length) {
        this.groupError = true
        return
      }
      this.$emit('submit', Object.assign({}, this.local))
    }
  }
}
</script>
