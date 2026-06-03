<template>
  <div>
    <CModal
        add-content-classes="test"
        :title="message.title"
        color="danger"
        :show.sync="message.status"
        :centered="true"
        :close-on-backdrop="false"
    >
      <template #header-wrapper>
        <div ></div>
      </template>
      <template #body-wrapper>
        <CCard class="bg-style2">
          <CCardHeader class="bg-gradient-danger text-white" style="border-top-left-radius: 1rem; border-top-right-radius: 1rem ">
            <span  class="font-weight-bold h6"><CIcon name="cil-speech" size="lg" class="mr-2"/> {{ $t('common.dialog.error') }} </span>
            <div class="card-header-actions">
                <small class="text-muted"># {{message.number}}-{{message.code}}</small>
            </div>
          </CCardHeader>
          <CCardBody>
            <CRow>
              <CCol col="12">
                {{message.message}}
              </CCol>
            </CRow>

            <CDropdownDivider/>
            <CRow class="text-right mt-3">
              <CCol>

                <CButton class="ml-2" size="sm" :color="objs.color" shape="pill" variant="outline" @click="onSubmit(objs.code)" v-for="(objs, index) in message.button" :key="`${objs.code || 'btn'}-${index}`">
                  <span class="font-weight-bold pr-1 pl-1">
                    <CIcon :name="objs.icon" size="lg"/> {{objs.label}}
                  </span>
                </CButton>
<!--                <CButton size="sm" color="danger" shape="pill" variant="outline" @click="onDismiss">-->
<!--                  <span class="font-weight-bold pr-1 pl-1"><CIcon name="cil-ban" size="lg"/> CANCEL </span>-->
<!--                </CButton>-->
<!--                <CButton size="sm" color="success" shape="pill" variant="outline" @click="onSubmit">-->
<!--                  <span class="font-weight-bold pr-1 pl-1"><CIcon name="cil-save" size="lg"/> SUBMIT </span>-->
<!--                </CButton>-->
              </CCol>
            </CRow>
          </CCardBody>
        </CCard>
      </template>
      <template #footer-wrapper>
        <div class=""></div>
      </template>
    </CModal>
  </div>
</template>

<script>

import {mapGetters} from 'vuex'

export default {
  name: 'DialogMessage',
  props: {
    disable: {
      type: Boolean,
      default: false
    },
    dialog: {
      type: Boolean,
      default: false
    },

  },
  data: function () {
    return {

    }
  },
  mounted() {
  },

  created() {
  },

  beforeDestroy() {

  },

  methods: {
    onDismiss(){
      this.$store.commit('dialog/hideDialog')
      this.$store.commit('dialog/loading', false)
    },

    onSubmit(values){
      this.$store.commit('dialog/hideDialog')
      this.$emit('submit', values)
    }
  },

  computed: {
    ...mapGetters({
      message: 'dialog/dialog'
    })
  },

  watch: {

  }
}
</script>

<style>
.input-group-append .form-group {
  margin-bottom: 0px;
}
.text-right{
  text-align: end;
}
.bg-login1 {
  border-radius: 1.5rem;
  background: linear-gradient(180deg, #a54af0 0%, #539cf8 60%, #C8CED3 80%);
}
.test{
  border-top-left-radius: 1rem;
  border-top-right-radius: 1rem;
  border-bottom-left-radius: 1rem;
  border-bottom-right-radius: 1rem
}
</style>
