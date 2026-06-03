<template>
  <SecurityManagementTableBase
    :title="$t('security.createMenu.menusTitle')"
    icon="cil-list"
    :add-label="$t('security.createMenu.addMenu')"
    :empty-message="$t('security.createMenu.emptyMenus')"
    :items="items"
    :fields="fields"
    @add="$emit('add')"
    @edit="$emit('edit', $event)"
    @remove="$emit('remove', $event)"
  />
</template>

<script>
import SecurityManagementTableBase from '@/projects/views/security/components/SecurityManagementTableBase'

export default {
  name: 'MenuManagementTable',
  components: { SecurityManagementTableBase },
  props: {
    items: { type: Array, default: () => [] },
    fields: { type: Array, default: () => [] }
  }
}
</script>
