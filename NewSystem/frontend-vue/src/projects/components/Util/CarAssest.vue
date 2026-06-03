<template>
  <div>
    <CCard class="bg-style2">
      <CCardHeader class="bg-gradient-dark text-white" style="border-top-left-radius: 1rem; border-top-right-radius: 1rem ">
        <span class="font-weight-bold h6"><CIcon :name="icon" size="lg"/> {{ caption }} </span>
        <div class="card-header-actions">
        </div>
      </CCardHeader>
      <CCardBody>
        <CRow>
          <CCol>
            <CDataTable
                :hover="hover"
                :striped="striped"
                :bordered="bordered"
                :small="small"
                :fixed="fixed"
                :fields="fields"
                :items="item"
                :items-per-page="small ? 50 : 20"
                :dark="dark"
                pagination
            >
              <template #car>
                <td class="mt-3">
                  <label><CIcon :name="icon" size="lg"/>  </label>
                </td>
              </template>

              <template #name="{item}">
                <td class="mt-3">
                  <label>{{ item.name }} มฟ-8000 </label>
                </td>
              </template>

              <template #total="{item}">
                <td>
                  <CInput v-model="item.maxByOrder" type="number" :max="item.total" min="1">
                    <template #append>
                      <CButton color="dark" >
                        / {{ Number(item.total).toLocaleString('en-US')}}
                      </CButton>
                    </template>
                  </CInput>
                </td>
              </template>



              <template #action>
                <td style="width: 140px">
                  <CRow>
                    <CCol class="text-center ">
                      <CButton  class="mr-1 "  size="sm" color="info" shape="pill" variant="outline"  >
                        <CIcon name="cil-pencil"/>
                      </CButton>
                    </CCol>
                  </CRow>
                </td>
              </template>


            </CDataTable>
          </CCol>
        </CRow>
      </CCardBody>
    </CCard>
  </div>
</template>
<script>
export default {
  name: 'CarAssest',
  props: {
    icon: {
      type: String,
      default: 'cil-fastfood'
    },
    caption: {
      type: String,
      default: 'อาหาร'
    },
    fields:{
      type: Array,
      default() {
        return [
          {key: "car", label: "#", _style: 'width:50px; text-align: center'},
          {key: "name", label: "รายการ"},
          {key: "license", label: "หมายเลข"},

          {key: "distance", label: "ระยะทาง"},
          {key: "#", label: "#"},

        ]
      }
    },
    hover: Boolean,
    striped: Boolean,
    bordered: Boolean,
    small: Boolean,
    fixed: Boolean,
    dark: Boolean,

    item: {
      type: Array,
      default() {
        return []
      }
    },



  },
}

</script>
