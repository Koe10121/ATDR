<template>
  <SecurityManagementTableBase
    :title="$t('security.permissionMatrix.tableTitle')"
    icon="cil-list-rich"
    :items="items"
    :fields="fields"
    :show-add="false"
    :small="true"
    :items-per-page="20"
    :scoped-slot-names="['source', 'all', 'view', 'edit', 'delete', 'action', 'owner', 'logs']"
  >
    <template #header-actions>
      <slot name="header-actions" />
    </template>

    <template #actions>
    </template>

    <template #source="{ item }">
      <td>
        <CBadge :color="item.source === 'mapped' ? 'info' : 'success'">
          {{ item.source === 'mapped' ? 'Mapped' : 'Manual' }}
        </CBadge>
      </td>
    </template>

    <template #all="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="primary" :checked="item.all" @update:checked="(val) => $emit('toggle', item, 'all', val)" />
      </td>
    </template>

    <template #view="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="info" :checked="item.view" @update:checked="(val) => $emit('toggle', item, 'view', val)" />
      </td>
    </template>

    <template #edit="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="warning" :checked="item.edit" @update:checked="(val) => $emit('toggle', item, 'edit', val)" />
      </td>
    </template>

    <template #delete="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="danger" :checked="item.delete" @update:checked="(val) => $emit('toggle', item, 'delete', val)" />
      </td>
    </template>

    <template #action="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="success" :checked="item.action" @update:checked="(val) => $emit('toggle', item, 'action', val)" />
      </td>
    </template>

    <template #owner="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="dark" :checked="item.owner" @update:checked="(val) => $emit('toggle', item, 'owner', val)" />
      </td>
    </template>

    <template #logs="{ item }">
      <td class="text-center">
        <CSwitch class="mb-0 d-inline-block" variant="3d" color="secondary" :checked="item.logs" @update:checked="(val) => $emit('toggle', item, 'logs', val)" />
      </td>
    </template>

  </SecurityManagementTableBase>
</template>

<script>
import SecurityManagementTableBase from '@/projects/views/security/components/SecurityManagementTableBase'

export default {
  name: 'PermissionMatrixTable',
  components: { SecurityManagementTableBase },
  props: {
    items: { type: Array, default: () => [] },
    fields: { type: Array, default: () => [] }
  }
}
</script>

<style scoped lang="scss">
@import "../security-page.shared";
</style>
