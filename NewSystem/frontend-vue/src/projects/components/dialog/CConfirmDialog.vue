<template>
  <CModal
    add-content-classes="bg-style2"
    :show.sync="showDialog"
    :centered="true"
    :close-on-backdrop="false"
    color="danger"
  >
    <template #header-wrapper>
      <div></div>
    </template>
    <template #body-wrapper>
      <CCard class="bg-style2">
        <CCardHeader class="text-white" color="danger" style="border-top-left-radius: 1rem; border-top-right-radius: 1rem ">
          <span class="font-weight-bold h6"><CIcon name="cil-speech" size="lg" class="mr-2" /> {{ resolvedTitle }} </span>
          <div class="card-header-actions">
          </div>
        </CCardHeader>
        <CCardBody>
          <CRow>
            <CCol col="12">
              <label class="text-dark">{{ resolvedMessage }}</label>
            </CCol>
          </CRow>

          <CDropdownDivider />
          <CRow class="text-right mt-3">
            <CCol>

              <CButton class="ml-2" size="sm" color="dark" shape="pill" variant="outline" @click="onCancel">
                <CIcon name="cil-ban" size="lg" />
                <span class="font-weight-bold pr-1 pl-1 pt-2"> {{ resolvedCancelText }} </span>
              </CButton>

              <CButton class="ml-2" size="sm" color="danger" shape="pill" variant="outline" @click="onConfirm">
                <CIcon :name="resolvedConfirmIcon" size="lg" />
                <span class="font-weight-bold pr-1 pl-1 pt-2"> {{ resolvedConfirmText }} </span>
              </CButton>

            </CCol>
          </CRow>
        </CCardBody>
      </CCard>
    </template>
    <template #footer-wrapper>
      <div class=""></div>
    </template>
  </CModal>
</template>

<script>
import { mapGetters } from 'vuex'

export default {
  name: 'CConfirmDialog',
  computed: {
    ...mapGetters({
      confirmDialog: 'dialog/confirm'
    }),
    showDialog: {
      get () {
        return !!(this.confirmDialog && this.confirmDialog.show)
      },
      set (value) {
        if (!value) {
          this.$store.dispatch('dialog/cancelConfirm')
        }
      }
    },
    resolvedTitle () {
      return (this.confirmDialog && this.confirmDialog.title) || this.$t('common.remove')
    },
    resolvedMessage () {
      return (this.confirmDialog && this.confirmDialog.message) || this.$t('common.confirmDelete')
    },
    resolvedConfirmText () {
      return (this.confirmDialog && this.confirmDialog.confirmText) || this.$t('common.delete')
    },
    resolvedCancelText () {
      return (this.confirmDialog && this.confirmDialog.cancelText) || this.$t('common.cancel')
    },
    resolvedConfirmIcon () {
      return (this.confirmDialog && this.confirmDialog.confirmIcon) || 'cil-trash'
    }
  },
  methods: {
    onConfirm () {
      this.$store.dispatch('dialog/confirm')
      this.$emit('confirm')
    },
    onCancel () {
      this.$store.dispatch('dialog/cancelConfirm')
      this.$emit('cancel')
    }
  }
}
</script>

<style>
</style>
