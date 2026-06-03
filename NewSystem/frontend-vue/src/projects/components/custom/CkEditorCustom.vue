<template>
  <div class="floating-group ckeditor-floating" :class="wrapperClass">
    <div ref="editor" class="ckeditor-host"></div>
    <label v-if="!hideLabel" :class="{ active: isActive, required: required }">
      <CIcon v-if="icon" :name="icon" class="mr-1" />
      <slot name="label">{{ label }}</slot>
    </label>
  </div>
</template>

<script>
import ClassicEditor from '@ckeditor/ckeditor5-build-classic'

export default {
  name: 'CkEditorCustom',
  props: {
    value: { type: String, default: '' },
    label: { type: String, default: '' },
    icon: { type: String, default: '' },
    hideLabel: { type: Boolean, default: false },
    required: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    wrapperClass: { type: [String, Array, Object], default: '' }
  },
  data () {
    return {
      editorInstance: null,
      focused: false,
      updatingFromEditor: false
    }
  },
  computed: {
    hasValue () {
      return String(this.value || '')
        .replace(/<(.|\n)*?>/g, '')
        .replace(/&nbsp;/g, ' ')
        .trim().length > 0
    },
    isActive () {
      return this.focused || this.hasValue
    }
  },
  watch: {
    value (next) {
      if (!this.editorInstance || this.updatingFromEditor) return
      if (this.editorInstance.getData() !== String(next || '')) {
        this.editorInstance.setData(String(next || ''))
      }
    },
    disabled (next) {
      if (!this.editorInstance) return
      this.editorInstance.isReadOnly = !!next
    }
  },
  mounted () {
    ClassicEditor
      .create(this.$refs.editor, {
        toolbar: [
          'undo', 'redo',
          '|',
          'heading',
          '|',
          'bold', 'italic',
          '|',
          'bulletedList', 'numberedList',
          '|',
          'link', 'insertTable'
        ]
      })
      .then(editor => {
        this.editorInstance = editor
        editor.setData(String(this.value || ''))
        editor.isReadOnly = !!this.disabled

        editor.editing.view.document.on('focus', () => {
          this.focused = true
          this.$emit('focus')
        })
        editor.editing.view.document.on('blur', () => {
          this.focused = false
          this.$emit('blur')
        })
        editor.model.document.on('change:data', () => {
          const next = editor.getData()
          this.updatingFromEditor = true
          this.$emit('input', next)
          this.$emit('change', next)
          this.$nextTick(() => {
            this.updatingFromEditor = false
          })
        })
      })
      .catch(error => {
        console.error(error)
      })
  },
  beforeDestroy () {
    if (!this.editorInstance) return
    this.editorInstance.destroy()
    this.editorInstance = null
  }
}
</script>

<style scoped>
@import "./cp-input-shared.scss";

.ckeditor-floating {
  margin-bottom: 20px;
}

.ckeditor-floating label {
  z-index: 2;
  left: 12px;
}

.ckeditor-floating label.active {
  top: -8px;
}

::v-deep .ck-editor__editable {
  min-height: 160px;
}
</style>
