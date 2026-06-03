<template>
  <CCard class="bg-style2 security-table-card" :class="cardClass">
    <CCardBody>
      <div class="security-table-card__header">
        <div class="security-table-card__title d-flex align-items-center">
          <CIcon :name="icon" class="mr-2 security-table-card__icon" />
          <span>{{ title }}</span>
        </div>
        <slot name="header-actions">
          <CButton
            v-if="showAdd && allowAdd"
            size="sm"
            :color="addColor"
            class="security-add-btn"
            @click="$emit('add')"
          >
            <CIcon name="cil-plus" class="mr-1" />
            {{ addLabel || $t('common.actions.add') }}
          </CButton>
        </slot>
      </div>

      <CDataTable
        :items="items"
        :fields="fields"
        :table-filter="tableFilter"
        :sorter="sorter"
        :items-per-page-select="itemsPerPageSelect"
        :striped="striped"
        :hover="hover"
        :small="small"
        :items-per-page="itemsPerPage"
        :pagination="{ doubleArrows: false, align: paginationAlign }"
      >
        <template v-for="slotName in scopedSlotNames" v-slot:[slotName]="scope">
          <slot :name="slotName" v-bind="scope" />
        </template>

        <template #actions="{ item }">
          <slot name="actions" :item="item">
            <td class="text-center">
              <CButton v-if="allowEdit" size="sm" color="info" variant="outline" shape="pill" class="mr-1 security-action-btn" v-c-tooltip="{ content: $t('common.actions.edit'), placement: 'top' }" @click="$emit('edit', item)">
                <CIcon name="cil-pencil" />
              </CButton>
              <CButton v-if="allowDelete" size="sm" color="danger" variant="outline" shape="pill" class="security-remove-btn" v-c-tooltip="{ content: $t('common.actions.remove'), placement: 'top' }" @click="$emit('remove', item)">
                <CIcon name="cil-trash" />
              </CButton>
            </td>
          </slot>
        </template>

        <template #empty>
          <div class="text-center text-muted py-4">{{ emptyMessage }}</div>
        </template>
      </CDataTable>
    </CCardBody>
  </CCard>
</template>

<script>
import SecurityAccess from '@/projects/mixins/securityAccess'

export default {
  name: 'SecurityManagementTableBase',
  mixins: [SecurityAccess],
  props: {
    title: { type: String, default: '' },
    icon: { type: String, default: 'cil-list' },
    addLabel: { type: String, default: '' },
    addColor: { type: String, default: 'success' },
    emptyMessage: { type: String, default: '' },
    itemsPerPage: { type: Number, default: 10 },
    itemsPerPageSelect: { type: Boolean, default: true },
    striped: { type: Boolean, default: true },
    hover: { type: Boolean, default: true },
    small: { type: Boolean, default: false },
    sorter: { type: Boolean, default: true },
    tableFilter: { type: Boolean, default: true },
    showAdd: { type: Boolean, default: true },
    paginationAlign: { type: String, default: 'end' },
    cardClass: { type: [String, Array, Object], default: '' },
    items: { type: Array, default: () => [] },
    fields: { type: Array, default: () => [] },
    scopedSlotNames: { type: Array, default: () => [] },
    permissionPath: { type: String, default: '' },
    allowAddOverride: { type: Boolean, default: null },
    allowEditOverride: { type: Boolean, default: null },
    allowDeleteOverride: { type: Boolean, default: null }
  },
  computed: {
    resolvedPermissionPath () {
      return this.permissionPath || this.defaultPermissionPath
    },
    allowAdd () {
      return typeof this.allowAddOverride === 'boolean'
        ? this.allowAddOverride
        : this.canAddPath(this.resolvedPermissionPath)
    },
    allowEdit () {
      return typeof this.allowEditOverride === 'boolean'
        ? this.allowEditOverride
        : this.canEditPath(this.resolvedPermissionPath)
    },
    allowDelete () {
      return typeof this.allowDeleteOverride === 'boolean'
        ? this.allowDeleteOverride
        : this.canDeletePath(this.resolvedPermissionPath)
    }
  }
}
</script>

<style scoped lang="scss">
@import "../security-page.shared";
</style>
