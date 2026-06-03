<template>

  <div class="floating-group date-clean" :class="{ 'has-value': hasValue }">
    <CInput
      :class="['date-clean', { 'has-value': hasValue },inputClass]"
      :value="value"
      :type="type"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      @input="onInput"
      @update:value="onInput"
      @focus="onFocus"
      @blur="onBlur"
    />
    <label :class="{ active: isActive, required: required }">
      <slot name="label">{{ label }}</slot>
    </label>
  </div>
</template>

<script>
export default {
  name: 'CPDateInput',
  props: {
    value: { type: String, default: '' },
    label: { type: String, default: '' },
    type: {
      type: String,
      default: 'date',
      validator: v => ['date', 'datetime-local', 'time'].includes(v)
    },
    placeholder: { type: String, default: ' ' },
    required: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    readonly: { type: Boolean, default: false },
    inputClass: { type: [String, Array, Object], default: '' }
  },
  data () {
    return {
      focused: false
    }
  },
  computed: {
    hasValue () {
      return String(this.value || '').trim().length > 0
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
      if (event && event.target && typeof event.target.showPicker === 'function') {
        event.target.showPicker()
      }
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

::v-deep .date-clean input[type="date"]::-webkit-datetime-edit,
::v-deep .date-clean input[type="date"]::-webkit-datetime-edit-year-field,
::v-deep .date-clean input[type="date"]::-webkit-datetime-edit-month-field,
::v-deep .date-clean input[type="date"]::-webkit-datetime-edit-day-field,
::v-deep .date-clean input[type="date"]::-webkit-datetime-edit-text,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-year-field,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-month-field,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-day-field,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-hour-field,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-minute-field,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-text,
::v-deep .date-clean input[type="time"]::-webkit-datetime-edit,
::v-deep .date-clean input[type="time"]::-webkit-datetime-edit-hour-field,
::v-deep .date-clean input[type="time"]::-webkit-datetime-edit-minute-field,
::v-deep .date-clean input[type="time"]::-webkit-datetime-edit-ampm-field,
::v-deep .date-clean input[type="time"]::-webkit-datetime-edit-text {
  color: transparent;
}

::v-deep .date-clean.has-value input[type="date"]::-webkit-datetime-edit,
::v-deep .date-clean.has-value input[type="date"]::-webkit-datetime-edit-year-field,
::v-deep .date-clean.has-value input[type="date"]::-webkit-datetime-edit-month-field,
::v-deep .date-clean.has-value input[type="date"]::-webkit-datetime-edit-day-field,
::v-deep .date-clean.has-value input[type="date"]::-webkit-datetime-edit-text,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit-year-field,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit-month-field,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit-day-field,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit-hour-field,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit-minute-field,
::v-deep .date-clean.has-value input[type="datetime-local"]::-webkit-datetime-edit-text,
::v-deep .date-clean.has-value input[type="time"]::-webkit-datetime-edit,
::v-deep .date-clean.has-value input[type="time"]::-webkit-datetime-edit-hour-field,
::v-deep .date-clean.has-value input[type="time"]::-webkit-datetime-edit-minute-field,
::v-deep .date-clean.has-value input[type="time"]::-webkit-datetime-edit-ampm-field,
::v-deep .date-clean.has-value input[type="time"]::-webkit-datetime-edit-text,
::v-deep .date-clean input:focus::-webkit-datetime-edit,
::v-deep .date-clean input:focus::-webkit-datetime-edit-year-field,
::v-deep .date-clean input:focus::-webkit-datetime-edit-month-field,
::v-deep .date-clean input:focus::-webkit-datetime-edit-day-field,
::v-deep .date-clean input:focus::-webkit-datetime-edit-hour-field,
::v-deep .date-clean input:focus::-webkit-datetime-edit-minute-field,
::v-deep .date-clean input:focus::-webkit-datetime-edit-ampm-field,
::v-deep .date-clean input:focus::-webkit-datetime-edit-text {
  color: inherit;
}

::v-deep .date-clean input[type="date"]::-webkit-datetime-edit-fields-wrapper,
::v-deep .date-clean input[type="datetime-local"]::-webkit-datetime-edit-fields-wrapper,
::v-deep .date-clean input[type="time"]::-webkit-datetime-edit-fields-wrapper {
  color: inherit;
}

::v-deep .date-clean:not(.has-value) input[type="date"],
::v-deep .date-clean:not(.has-value) input[type="datetime-local"],
::v-deep .date-clean:not(.has-value) input[type="time"] {
  color: transparent;
  caret-color: transparent;
}

::v-deep .date-clean input:focus {
  color: inherit;
  caret-color: auto;
}
</style>
