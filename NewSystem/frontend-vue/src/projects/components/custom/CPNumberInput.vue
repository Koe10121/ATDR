<template>
  <div class="floating-group" :class="wrapperClass">
    <CInput
      :value="value"
      type="number"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      :min="min"
      :max="max"
      :step="step"
      :class="inputClass"
      @input="onInput"
      @update:value="onInput"
      @focus="onFocus"
      @blur="onBlur"
      @keypress="preventInvalidKey"
    />
    <label :class="{ active: isActive, required: required }">
      <slot name="label">{{ label }}</slot>
    </label>
  </div>
</template>

<script>
export default {
  name: 'CPNumberInput',
  props: {
    value: { type: [String, Number], default: '' },
    label: { type: String, default: '' },
    placeholder: { type: String, default: ' ' },
    required: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    readonly: { type: Boolean, default: false },
    min: { type: [String, Number], default: null },
    max: { type: [String, Number], default: null },
    step: { type: [String, Number], default: '1' },
    allowDecimal: { type: Boolean, default: true },
    allowNegative: { type: Boolean, default: false },
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
    },
    preventInvalidKey (e) {
      const allowedKeys = ['Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'Tab', 'Home', 'End']
      if (allowedKeys.includes(e.key)) return
      if (/^[0-9]$/.test(e.key)) return
      if (e.key === '.' && this.allowDecimal) {
        if ((e.target.value || '').includes('.')) e.preventDefault()
        return
      }
      if (e.key === '-' && this.allowNegative && (e.target.selectionStart === 0) && !(e.target.value || '').includes('-')) {
        return
      }
      e.preventDefault()
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
