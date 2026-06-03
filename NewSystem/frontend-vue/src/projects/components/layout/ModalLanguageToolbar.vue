<template>
  <div class="lang-toolbar d-flex flex-wrap align-items-center justify-content-between mb-3">
    <div class="language-tabs-wrap mb-2">
      <CTabs tabs :active-tab.sync="localActiveTab">
        <CTab v-for="lang in languages" :key="`lang-${lang}`">
          <template slot="title">{{ resolveLabel(lang) }}</template>
        </CTab>
      </CTabs>
    </div>
    <div class="d-flex flex-wrap align-items-center mb-2">
      <CBadge color="light" class="mr-2 mb-2 lang-editing">{{ $t('common.language.badge', { lang: activeLang }) }}</CBadge>
    </div>
  </div>
</template>

<script>
export default {
  name: 'ModalLanguageToolbar',
  props: {
    languages: { type: Array, default: () => [] },
    activeTab: { type: Number, default: 0 },
    activeLang: { type: String, default: 'th' },
    labelResolver: { type: Function, default: null }
  },
  computed: {
    localActiveTab: {
      get () {
        return this.activeTab
      },
      set (value) {
        this.$emit('update:activeTab', value)
      }
    }
  },
  methods: {
    resolveLabel (lang) {
      return this.labelResolver ? this.labelResolver(lang) : lang
    }
  }
}
</script>
