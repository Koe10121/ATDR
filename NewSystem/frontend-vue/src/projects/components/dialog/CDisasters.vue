<template>
    <div>
        <CModal
            :show.sync="isDisaters"
            add-content-classes="test"
            size="lg"
            color="danger"
            :centered="true"
            :close-on-backdrop="false"

        >
          <template #header-wrapper>
            <div ></div>
          </template>
          <template #body-wrapper>

            <CCard class="bg-style2 p-0">
                    <CCardHeader class="bg-gradient-danger text-white" style="border-top-left-radius: 1rem; border-top-right-radius: 1rem;" >
                      <span  class="font-weight-bold h6"><CIcon name="cil-bell" size="lg"/> แจ้งเหตุฉุกเฉิน </span>
                      <div class="card-header-actions" @click="handleClose">
                        <CIcon name="cil-x" size="lg" />
                      </div>
                    </CCardHeader>
              <CCardBody>
                <Report/>
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
import Report from "@/projects/views/reports/index.vue";

export default {
  name: 'CDisasters',
  components: {Report},
    methods: {
      handleClose() {
          this.$store.commit("dialog/isDisaters", false)
      }

    },

    computed: {
        ...mapGetters({
          isDisaters: "dialog/isDisaters",
        })
    }
}
</script>
