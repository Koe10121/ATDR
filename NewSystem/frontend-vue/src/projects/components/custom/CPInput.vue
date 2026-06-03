<template>
  <div class="floating-group" :class="wrapperClass">
    <CInput
      :value="value"
      :type="type"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      :class="inputClass"
      @input="onInput"
      @update:value="onInput"
      @focus="onFocus"
      @blur="onBlur"
    />
    <label :class="{ active: isActive, required: required }">
      <CIcon v-if="icon" :name="icon" class="mr-1" />
      <slot name="label">{{ label }}</slot>
    </label>
  </div>
</template>

<script>
export default {
  name: 'CPInput',
  props: {
    value: { type: [String, Number], default: '' },
    label: { type: String, default: '' },
    icon: { type: String, default: '' },
    type: { type: String, default: 'text' },
    placeholder: { type: String, default: ' ' },
    required: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    readonly: { type: Boolean, default: false },
    wrapperClass: { type: [String, Array, Object], default: '' },
    inputClass: { type: [String, Array, Object], default: '' }
  },
  data () {
    return {
      focused: false
    }
  },
  computed: {
    hasValue () {
      return String(this.value === null || this.value === undefined ? '' : this.value).trim().length > 0
    },
    isActive () {
      return this.focused || this.hasValue
    }
  },
  methods: {
    onInput (value) {
      this.$emit('input', value)
      this.$emit('change', value)
    },
    onFocus (event) {
      this.focused = true
      this.$emit('focus', event)
    },
    onBlur (event) {
      this.focused = false
      this.$emit('blur', event)
    }
  }
}
</script>

<style scoped>
@import "./cp-input-shared.scss";

::v-deep input {
  height: 46px;
  font-size: 16px;
}
</style>
