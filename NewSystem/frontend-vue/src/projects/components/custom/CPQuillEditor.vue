<template>
  <div class="floating-group quill-floating" :class="wrapperClass">
    <quill-editor
      ref="editor"
      :content="value"
      :disabled="disabled"
      :options="editorOptions"
      :class="editorClass"
      @change="onEditorChange"
      @focus="onFocus"
      @blur="onBlur"
    />
    <label :class="{ active: isActive, required: required }">
      <slot name="label">{{ label }}</slot>
    </label>
  </div>
</template>

<script>
import Vue from 'vue'
import VueQuillEditor from 'vue-quill-editor'
import 'quill/dist/quill.snow.css'

Vue.use(VueQuillEditor)

export default {
  name: 'CPQuillEditor',
  props: {
    value: { type: String, default: '' },
    label: { type: String, default: '' },
    required: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    wrapperClass: { type: [String, Array, Object], default: '' },
    editorClass: { type: [String, Array, Object], default: '' }
  },
  data () {
    return {
      focused: false,
      editorOptions: {
        modules: {
          toolbar: {
            container: [
              ['bold', 'italic', 'underline', 'strike'],
              [{ header: [1, 2, 3, 4, 5, 6, false] }],
              [{ color: [] }, { background: [] }],
              [{ font: [] }],
              [{ align: [] }],
              ['clean'],
              ['link', 'image', 'video']
            ],
            handlers: {
              image: this.onToolbarImage
            }
          }
        },
        theme: 'snow'
      }
    }
  },
  computed: {
    hasValue () {
      const normalized = (this.value || '')
        .replace(/<p><br><\/p>/g, '')
        .replace(/<(.|\n)*?>/g, '')
        .replace(/&nbsp;/g, ' ')
        .trim()
      return normalized.length > 0
    },
    isActive () {
      return this.focused || this.hasValue
    }
  },
  methods: {
    onEditorChange ({ html }) {
      const value = html || ''
      this.$emit('input', value)
      this.$emit('change', value)
    },
    onFocus () {
      this.focused = true
      this.$emit('focus')
    },
    onBlur () {
      this.focused = false
      this.$emit('blur')
    },
    onToolbarImage () {
      const input = document.createElement('input')
      input.setAttribute('type', 'file')
      input.setAttribute('accept', 'image/*')
      input.click()

      input.onchange = () => {
        const file = input.files && input.files[0]
        if (!file) return

        const reader = new FileReader()
        reader.onload = (event) => {
          const quill = this.$refs.editor && this.$refs.editor.quill
          if (!quill) return

          const range = quill.getSelection(true)
          const index = range ? range.index : quill.getLength()
          quill.insertEmbed(index, 'image', event.target.result, 'user')
          quill.setSelection(index + 1)
        }
        reader.readAsDataURL(file)
      }
    }
  }
}
</script>

<style scoped>
@import "./cp-input-shared.scss";

.quill-floating {
  margin-bottom: 20px;
}

.quill-floating label {
  z-index: 2;
  left: 12px;
}

.quill-floating label.active {
  top: -8px;
}

::v-deep .ql-toolbar.ql-snow {
  border: 1px solid #d6dde6;
  border-top-left-radius: 5px;
  border-top-right-radius: 5px;
}

::v-deep .ql-container.ql-snow {
  border: 1px solid #d6dde6;
  border-top: 0;
  border-bottom-left-radius: 5px;
  border-bottom-right-radius: 5px;
  min-height: 160px;
}

::v-deep .ql-editor {
  min-height: 130px;
}
</style>
