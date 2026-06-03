<template>
  <SecurityManagementTableBase
    :title="$t('security.createGroup.tableTitle')"
    icon="cil-people"
    :add-label="$t('security.createGroup.addGroup')"
    add-color="primary"
    :empty-message="$t('security.createGroup.empty')"
    pagination-align="center"
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
  name: 'GroupManagementTable',
  components: { SecurityManagementTableBase },
  props: {
    items: { type: Array, default: () => [] },
    fields: { type: Array, default: () => [] }
  }
}
</script>
