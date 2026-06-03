<template>
  <div>
    <CRow class="mb-2" v-if="caption != null">
      <CCol class="font-weight-bold">
        <label> {{caption}} </label>
      </CCol>
    </CRow>
    <CDropdownDivider v-if="disable"/>
    <CRow class="mt-3" v-for="(objs , index) in items" :key="caption+index">
      <CCol col="3">
        <CInput prepend="Key" v-model="objs.key"></CInput>
      </CCol>
      <CCol >
        <CInput prepend="Value" v-model="objs.value"></CInput>
      </CCol>
      <CCol v-if="disable" class="text-right" col="2">
        <CButton @click="onAddRow" class="mr-2" size="sm" color="success" shape="pill" variant="outline" v-c-tooltip.hover.click="'Add'" >
          <CIcon name="cil-library-add"/>
        </CButton>
        <CButton @click="onRemove(objs)" size="sm" color="danger" shape="pill" variant="outline" v-c-tooltip.hover.click="'Remove'">
          <CIcon name="cil-trash"/>
        </CButton>
      </CCol>
    </CRow>
  </div>
</template>

<script>

import {mapGetters} from 'vuex'
export default {
  name: 'MultiLanguage',
  props: {
    caption: {
      type: String,
      default: null
    },
    items: {
      type: Array,
      default () {
        return [ {key:"th", value:""},{key:"en", value:""}  ]
      }

    },
    disable: {
      type: Boolean,
      default: true
    }
  },

  data: function () {
    return {
    }
  },

  mounted () {
  },

  created () {
    this.onInit()

  },
  beforeDestroy () {

  },

  methods: {
    onInit(){
    },

    onAddRow() {
      var objs = {};
      objs.key = "";
      objs.value = "";
      this.items.push(objs)
    },
    onRemove(item){
      this.items =  this.items.filter(objs => {
        return item.key != objs.key;
      });

      if(this.items.length == 0){
        // var objs = {};
        // objs.key = "th";
        // objs.value = "";
        // this.items.push(objs)
      }


      // console.log(objsFilter)


    }


  },

  computed:{
    ...mapGetters({
    })
  },

  watch: {
  }

}
</script>
<style >


</style>
