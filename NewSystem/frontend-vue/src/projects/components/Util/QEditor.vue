<template>
  <div>
    <quill-editor class=""
                  :content="content['value']"
                  @change="onEditor"
                  :disabled="disabled"
                  :options="editorOptions"
    />
  </div>
</template>

<script>
import Vue from 'vue'
import VueQuillEditor from 'vue-quill-editor'
import 'quill/dist/quill.snow.css'

Vue.use(VueQuillEditor)

export default {
  name: 'QEditor',
  props: {
    caption: {
      type: String,
      default: ' Campus '
    },
    content: Object,

    disabled: {
      type: Boolean,
      default: false
    },
  },

  data() {
    return {
      editorOptions: {
        modules: {
          toolbar: [
            ['bold', 'italic', 'underline', 'strike'],
            // ['blockquote', 'code-block'],
            // [{ 'header': 1 }, { 'header': 2 }],
            // [{ 'list': 'ordered' }, { 'list': 'bullet' }],
            // [{ 'script': 'sub' }, { 'script': 'super' }],
            // [{ 'indent': '-1' }, { 'indent': '+1' }],
            // [{ 'direction': 'rtl' }],
            // [{ 'size': ['small', false, 'large', 'huge'] }],
            [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
            [{ 'color': [] }, { 'background': [] }],
            [{ 'font': [] }],
            [{ 'align': [] }],
            ['clean'],
            ['link', 'image', 'video']
          ],
        },
        theme: "snow",
      },
    };
  },

  methods: {
    onEditor({ html }) {
      if (this.content) {
        this.content['value'] = html;
      }
    },
  },
};
</script>

<style scoped>
/* ปรับแต่งสไตล์เพิ่มได้ที่นี่ */
</style>
