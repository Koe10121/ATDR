<template>
  <div>
    <CRow class="mb-4">
      <CCol>
        <CCard class="bg-style2">
          <CCardHeader class="bg-gradient-danger text-white" style="border-top-left-radius: 1rem; border-top-right-radius: 1rem ">
            <span class="font-weight-bold h6"><CIcon name="cil-layers" size="lg"/> {{ caption }}</span>
          </CCardHeader>
          <CCardBody>
            <CRow>
              <CCol col="12">
                <CRow class="mb-3">
                  <CCol col="3">
                    <label class="mt-2">{{ $t('campus')}}</label>
                  </CCol>
                  <CCol>
                    <Multiselect class="os"
                                 v-model="select.campus"
                                 :options="options.campus"
                                 label="label"
                                 track-by="label"
                                 :multiple="false"
                                 :search="true"
                    >
                    </Multiselect>
                  </CCol>
                </CRow>
              </CCol>
              <CCol col="12">
                <CRow>
                  <CCol col="3">
                    <label class="mt-2">{{ $t('department')}}</label>
                  </CCol>
                  <CCol>
                    <Multiselect class="os"
                                 v-model="select.facultys"
                                 :options="options.facultys"
                                 label="label"
                                 track-by="label"
                                 :multiple="false"
                                 :search="true"
                    >
                    </Multiselect>
                  </CCol>
                </CRow>
              </CCol>
            </CRow>
<!--            <CRow>-->
<!--              <CCol col="12" v-if="!disable" class="mt-3">-->
<!--                <CInput :label="$t('year')"-->
<!--                        type="number"-->
<!--                        :horizontal="{label: 'col-sm-3 mt-1', input: 'col-sm-9 pl-2'}"-->
<!--                        v-model="option.year"/>-->

<!--              </CCol>-->
<!--            </CRow>-->
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

  </div>
</template>

<script>


import {mapGetters} from 'vuex'
import Multiselect from 'vue-multiselect'
import 'vue-multiselect/dist/vue-multiselect.min.css'

export default {
  name: 'FilterOrganization',
  components: {Multiselect},
  props: {
    caption: {
      type: String,
      default: ""
    },
    disable: {
      type: Boolean,
      default: false
    },
    option: {
      type: Object,
      default() {
        return {}
      }
    }
  },
  data: function () {
    return {
      options: {
        campus: [],
        facultys: [],
      },


      select: {
        campus:"",
        facultys:""
      },





    }


  },

  mounted() {
  },

  created() {
    this.onInit()

  },
  beforeDestroy() {

  },

  methods: {
    onInit() {

      this.$store.dispatch("campus/config",{})
      this.$store.dispatch("faculty/config",{})
      // this.$store.dispatch("agency/config",{})

    },

    //
    // onSelectOrganizations(value, e) {
    //   this.option.campusId = value;
    //   this.$emit("option", this.option)
    // },
    //
    // onSelectAgencys(value, e) {
    //   this.option.agency = value;
    //   this.$emit("option", this.option)
    // },


  },


  computed: {
    ...mapGetters({
      lang: 'setting/lang',
      campus: 'campus/campus',
      facultys: 'faculty/facultys',
    }),
  },

  watch: {

    lang: function () {
      var lang = this.$store.getters['setting/lang'];
      // var data = {};
      // data.label = "-"
      // data.value = 0

      this.options.campus =  [ ...this.campus.map(objs => ({ label: objs.title.filter(title => { if (title.key === lang) { return title } })[0].value, value:objs._id }))];
      this.options.facultys =  [ ...this.facultys.map(objs => ({ label: objs.title.filter(title => { if (title.key === lang) { return title } })[0].value, value:objs._id }))];
      // this.agencys =  [ data,...this.agency.map(objs => ({ label: objs.title.filter(title => { if (title.key == lang) { return title } })[0].value, value:objs._id }))]
    },

    campus: function (value) {
      this.options.campus = [];
      var lang = this.$store.getters['setting/lang'];
      this.options.campus =  [ ...value.map(objs => ({ label: objs.title.filter(title => { if (title.key === lang) { return title } })[0].value, value:objs._id }))];
    },


    facultys: function (value) {
      this.options.facultys = [];
      var lang = this.$store.getters['setting/lang'];
      this.options.facultys =  [ ...value.map(objs => ({ label: objs.title.filter(title => { if (title.key === lang) { return title } })[0].value, value:objs._id }))];
    },

    // agency: function (value) {
    //   this.agencys = [];
    //
    //   var lang = this.$store.getters['setting/lang'];
    //
    //   var data = {};
    //   data.label = "-"
    //   data.value = 0
    //   this.agencys =  [ data,...value.map(objs => ({ label: objs.title.filter(title => { if (title.key === lang) { return title } })[0].value, value:objs._id }))]
    // },

    agencySelect(value){
      this.option.agency = value.value;
      this.$emit("option", this.option)
    }
  }

}
</script>
<style>


</style>
