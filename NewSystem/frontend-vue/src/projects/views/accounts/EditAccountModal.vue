<template>
  <CModal :show="show" @update:show="onShowChange" size="lg" class="account-edit-modal" add-content-classes="border-radius-1">
    <template #header-wrapper><div></div></template>

    <div class="account-modal__header">
      <div class="account-modal__hero">
        <div class="account-modal__title">Edit Account</div>
        <div class="account-modal__subtitle">Update identity and contact details in one place.</div>
      </div>
    </div>

    <div class="account-modal__body">
      <div class="account-image-panel account-image-panel--top mb-4">
        <div class="account-image-preview-wrap">
          <div class="account-image-preview account-image-preview--hero">
            <img v-if="hasRenderableImage" :src="local.image" alt="Profile preview" @error="onImageError">
            <div v-else class="account-image-fallback">{{ initials }}</div>
          </div>
          <button type="button" class="account-image-upload" @click="openFilePicker">
            <CIcon name="cil-camera" />
          </button>
        </div>
        <input ref="fileInput" type="file" accept="image/*" class="d-none" @change="onFileChange">
      </div>

      <AccountAccessSection
        class="account-modal__section floating-section mb-3"
        :value="local"
        :status-options="statusOptions"
        :group-options="groupOptions"
      />

      <AccountIdentitySection
        class="account-modal__section floating-section mb-3"
        :value="local"
      />

      <AccountContactSection
        class="account-modal__section floating-section"
        :value="local"
      />
    </div>

    <template #footer-wrapper>
      <div class="account-modal__footer mr-2 mb-1 mt-1">
        <CButton color="dark" variant="outline" class="mr-2 account-modal__btn" @click="onCancel">
          <CIcon name="cil-ban" class="mr-1" />
          Cancel
        </CButton>
        <CButton color="success" variant="outline" class="account-modal__btn" @click="onSubmit">
          <CIcon name="cil-save" class="mr-1" />
          Update
        </CButton>
      </div>
    </template>
  </CModal>
</template>

<script>
import AccountAccessSection from './components/AccountAccessSection'
import AccountIdentitySection from './components/AccountIdentitySection'
import AccountContactSection from './components/AccountContactSection'

export default {
  name: 'EditAccountModal',
  components: { AccountAccessSection, AccountIdentitySection, AccountContactSection },
  props: {
    show: { type: Boolean, default: false },
    value: { type: Object, default: () => ({}) },
    statusOptions: { type: Array, default: () => [] },
    groupOptions: { type: Array, default: () => [] }
  },
  data () {
    return {
      local: {
        _id: '',
        code: '',
        email: '',
        prefix: '',
        firstName: '',
        lastName: '',
        msisdn: '',
        lineId: '',
        cardId: '',
        religion: '',
        birthday: '',
        image: '',
        groupIds: [],
        statusKey: ''
      },
      imageBroken: false
    }
  },
  computed: {
    hasImage () {
      return String(this.local.image || '').trim().length > 0
    },
    hasRenderableImage () {
      return this.hasImage && !this.imageBroken
    },
    initials () {
      const fullName = `${this.local.firstName} ${this.local.lastName}`.trim()
      if (!fullName) return 'NA'
      return fullName
        .split(/\s+/)
        .slice(0, 2)
        .map(part => part.charAt(0).toUpperCase())
        .join('')
    }
  },
  watch: {
    show: {
      immediate: true,
      handler (value) {
        if (!value) return
        this.local = {
          _id: this.value && this.value._id ? this.value._id : '',
          code: this.value && this.value.code && this.value.code !== '-' ? this.value.code : '',
          email: this.value && this.value.email && this.value.email !== '-' ? this.value.email : '',
          prefix: this.value && this.value.prefix ? this.value.prefix : '',
          firstName: this.value && this.value.firstName ? this.value.firstName : '',
          lastName: this.value && this.value.lastName ? this.value.lastName : '',
          msisdn: this.value && this.value.msisdn ? this.value.msisdn : '',
          lineId: this.value && this.value.lineId ? this.value.lineId : '',
          cardId: this.value && this.value.cardId ? this.value.cardId : '',
          religion: this.value && this.value.religion ? this.value.religion : '',
          birthday: this.value && this.value.birthday ? this.value.birthday : '',
          image: this.value && this.value.image ? this.value.image : '',
          groupIds: Array.isArray(this.value && this.value.groupIds) ? this.value.groupIds.slice() : [],
          statusKey: this.value && this.value.statusKey ? this.value.statusKey : ''
        }
        this.imageBroken = false
      }
    }
  },
  methods: {
    onImageError () {
      this.imageBroken = true
    },
    openFilePicker () {
      if (this.$refs.fileInput) this.$refs.fileInput.click()
    },
    onFileChange (event) {
      const file = event && event.target && event.target.files ? event.target.files[0] : null
      if (!file) return
      const reader = new FileReader()
      reader.onload = (loadEvent) => {
        this.local.image = loadEvent && loadEvent.target ? String(loadEvent.target.result || '') : ''
        this.imageBroken = false
      }
      reader.readAsDataURL(file)
      if (event && event.target) event.target.value = ''
    },
    onShowChange (value) {
      this.$emit('update:show', value)
      if (!value) this.$emit('cancel')
    },
    onCancel () {
      this.$emit('update:show', false)
      this.$emit('cancel')
    },
    onSubmit () {
      this.$emit('submit', Object.assign({}, this.local))
    }
  }
}
</script>
