<template>
  <div class="floating-multi mb-0">
    <Multiselect
      v-model="model"
      class="os"
      :options="options"
      :label="labelKey"
      :track-by="trackBy"
      :searchable="searchable"
      :multiple="multiple"
      :close-on-select="closeOnSelect"
      :show-labels="showLabels"
      :allow-empty="allowEmpty"
      :select-label="selectLabel"
      :deselect-label="deselectLabel"
      :placeholder="placeholder"
      @open="opened = true"
      @close="opened = false"
      @input="onChange"
    />
    <label :class="{ float: isActive, required: required }">
      <slot name="label">{{ label }}</slot>
    </label>
  </div>
</template>

<script>
import Multiselect from 'vue-multiselect'
import 'vue-multiselect/dist/vue-multiselect.min.css'

export default {
  name: 'CPSelect',
  components: { Multiselect },
  props: {
    value: { type: [Object, Array, String, Number, Boolean], default: null },
    options: { type: Array, default: () => [] },
    label: { type: String, default: '' },
    required: { type: Boolean, default: false },
    labelKey: { type: String, default: 'label' },
    trackBy: { type: String, default: 'value' },
    searchable: { type: Boolean, default: true },
    multiple: { type: Boolean, default: false },
    closeOnSelect: { type: Boolean, default: true },
    showLabels: { type: Boolean, default: false },
    allowEmpty: { type: Boolean, default: false },
    selectLabel: { type: String, default: '' },
    deselectLabel: { type: String, default: '' },
    placeholder: { type: String, default: '' }
  },
  data () {
    return {
      opened: false
    }
  },
  computed: {
    model: {
      get () {
        return this.value
      },
      set (value) {
        this.$emit('input', value)
      }
    },
    hasValue () {
      if (Array.isArray(this.value)) return this.value.length > 0
      if (this.value && typeof this.value === 'object') return true
      return String(this.value === null || this.value === undefined ? '' : this.value).trim().length > 0
    },
    isActive () {
      return this.opened || this.hasValue
    }
  },
  methods: {
    onChange (value) {
      this.$emit('change', value)
    }
  }
}
</script>

<style scoped>
.floating-multi {
  position: relative;
  margin-bottom: 20px;
}

.floating-multi label {
  position: absolute;
  left: 12px;
  top: 12px;
  color: #666;
  background: #fff;
  padding: 0 4px;
  transition: all 0.2s ease;
  pointer-events: none;
  font-size: 14px;
}

.floating-multi label.float {
  top: -8px;
  font-size: 12px;
  color: #007bff;
}

.required::after {
  content: " *";
  color: red;
}

::v-deep .os .multiselect {
  padding-top: 8px;
}

::v-deep .os > .multiselect__tags {
  min-width: 100px;
  min-height: 45px;
}

::v-deep .os > .multiselect__tags > .multiselect__single {
  padding-left: 5px;
  margin-bottom: 12px;
  margin-top: 5px;
  display: block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

::v-deep .os > .multiselect__tags > .multiselect__placeholder {
  padding-bottom: 20px;
}

::v-deep .multiselect.is-invalid,
::v-deep .is-invalid {
  border: 0.5px solid #fb4958;
  border-radius: 5px;
}
</style>
