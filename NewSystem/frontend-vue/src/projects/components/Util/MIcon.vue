<template>
  <i :class="name" :style="{ fontSize: sizeMap[size] || size }" />
</template>

<script>
export default {
  name: 'MIcon',
  props: {
    name: { type: String, required: true }, // เช่น 'mfu-home'
    size: { type: String, default: 'md' }
  },
  data () {
    return {
      sizeMap: {
        sm: '16px',
        md: '24px',
        lg: '32px',
        xl: '48px'
      }
    }
  }
}
</script>
