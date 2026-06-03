<template>
  <SecurityManagementTableBase
    :title="$t('security.createMenu.typesTitle')"
    icon="cil-layers"
    :add-label="$t('security.createMenu.addType')"
    add-color="secondary"
    :empty-message="$t('security.createMenu.emptyTypes')"
    :items="items"
    :fields="fields"
    :items-per-page="8"
    :items-per-page-select="false"
    :small="true"
    pagination-align="center"
    card-class="mb-3 mb-md-0"
    @add="$emit('add')"
    @edit="$emit('edit', $event)"
    @remove="$emit('remove', $event)"
  />
</template>

<script>
import SecurityManagementTableBase from '@/projects/views/security/components/SecurityManagementTableBase'

export default {
  name: 'TypeManagementTable',
  components: { SecurityManagementTableBase },
  props: {
    items: { type: Array, default: () => [] },
    fields: { type: Array, default: () => [] }
  }
}
</script>
