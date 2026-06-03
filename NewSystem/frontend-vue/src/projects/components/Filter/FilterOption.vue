<template>
  <div>
    <CRow>
      <CCol>
        <CCard class="bg-style2">
          <CCardHeader class="bg-gradient-danger text-white" style="border-top-left-radius: 1rem; border-top-right-radius: 1rem ">
            <span className="font-weight-bold h6"><CIcon name="cil-layers" size="lg"/> {{ caption }}</span>
          </CCardHeader>
          <CCardBody>
            <CRow>
              <CCol col="12">
                <CSelect :label="$t('nameOfUniversity')"
                         :disabled="disable"
                         :horizontal="{label: 'col-sm-3', input: 'col-sm-9'}"
                         :options="campus"
                         @update:value="onSelectCampus"
                />
              </CCol>
              <CCol col="6">
                <CInput :label="$t('academicYear')"
                        type="number"
                        :disabled="disable"
                        :horizontal="{label: 'col-sm-6', input: 'col-sm-5 ml-1'}"
                        v-model="option.academicYear"/>
              </CCol>
              <CCol col="6">
                <CSelect :label="$t('semester')"
                         :disabled="disable"
                         :horizontal="{label: 'col-sm-3', input: 'col-sm-9'}"
                         @update:value="onSemester"
                         :options="semesters"/>
              </CCol>
            </CRow>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

  </div>
</template>

<script>


import {mapGetters} from 'vuex'

export default {
  name: 'FilterOption',
  props: {
    caption: {
      type: String,
      default: ""
    },
    disable: {
      type: Boolean,
      default: false
    }
  },
  data: function () {
    return {
      campus: [],
      semesters: [
        {
          label: " 1",
          value: 1
        }, {
          label: " 2",
          value: 2
        }, {
          label: " 3",
          value: 3
        }
      ],
      option: {
        code: null,
        campusId: null,
        semester: 1,
        academicYear: new Date().getFullYear() + 542,
      }
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
      this.$store.dispatch("campus/config", {})

    },

    onSelectCampus(value) {
      this.option.campusId = value;
      this.$emit("option", this.option)
    },

    onSemester(value) {
      this.option.semester = value;
      this.$emit("option", this.option)
    },

  },


  computed: {
    ...mapGetters({
      objsLang: "setting/lang",
      objsCampus: "campus/campus",
    }),
  },

  watch: {
    objsLang(){
      this.onInit();
    },
    objsCampus(value) {
      var lang = this.$store.getters['setting/lang']
      var items = [];
      value.filter(item => {
        var objs = item.title.filter(title => {
          if (title.key == lang) {
            return title
          }
        })[0].value;
        var data = {};
        data.label = objs
        data.value = item._id;
        items.push(data)
      })
      this.campus = items;

      this.option.campusId = this.campus[0].value;
    },

    "option.code"() {
      this.$emit("option", this.option)
    },
    "option.academicYear"() {
      this.$emit("option", this.option)
    }
  }

}
</script>
<style>


</style>
