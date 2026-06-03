<template>
  <div class="security-page">
    <AppSectionHero
      :title="$t('security.createMenu.title')"
      :subtitle="$t('security.createMenu.subtitle')"
      :stats="heroStats"
      :meta-label="$t('common.lastUpdated')"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />
    <CRow>
      <CCol md="4" col="12">
        <TypeManagementTable
          :items="typesTableItems"
          :fields="typeFields"
          @add="openCreateTypeModal"
          @edit="openEditTypeModal"
          @remove="removeType"
        />
      </CCol>

      <CCol md="8" col="12">
        <MenuManagementTable
          :items="menuTableItems"
          :fields="menuFields"
          @add="openCreateMenuModal"
          @edit="openEditMenuModal"
          @remove="removeMenu"
        />
      </CCol>

      <MenuFormModal
        :show.sync="menuModal"
        :title="menuDraft._id ? $t('security.createMenu.editMenu') : $t('security.createMenu.title')"
        :value="menuDraft"
        :type-options="menuTypeOptions"
        @submit="saveMenu"
        @invalid="handleInvalid"
        @cancel="closeMenuModal"
      />

      <TypeFormModal
        :show.sync="typeModal"
        :title="typeDraft._id ? $t('security.createMenu.editType') : $t('security.createMenu.addType')"
        :value="typeDraft"
        @submit="saveType"
        @invalid="handleInvalid"
        @cancel="closeTypeModal"
      />
    </CRow>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import TypeManagementTable from '@/projects/views/security/components/TypeManagementTable'
import MenuManagementTable from '@/projects/views/security/components/MenuManagementTable'
import MenuFormModal from '@/projects/views/security/components/MenuFormModal'
import TypeFormModal from '@/projects/views/security/components/TypeFormModal'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import { formatDateTime24 } from '@/projects/utils/date-time'
import { notifyError, notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'
import { normalizeOrDefault } from '@/projects/views/security/components/security-multilang.shared'
import { getTextByLanguage } from '@/store/modules/Security/shared'

const createTypeDraft = () => ({
  _id: null,
  title: normalizeOrDefault([]),
  state: true
})

const createMenuDraft = (defaultTypeId = '') => ({
  _id: null,
  title: normalizeOrDefault([]),
  description: normalizeOrDefault([]),
  path: '',
  typeId: defaultTypeId,
  state: true
})

export default {
  name: 'CreateMenu',
  components: {
    AppSectionHero,
    TypeManagementTable,
    MenuManagementTable,
    MenuFormModal,
    TypeFormModal
  },
  data () {
    return {
      menuModal: false,
      typeModal: false,
      lastUpdatedAt: null,
      menuDraft: createMenuDraft(),
      typeDraft: createTypeDraft()
    }
  },
  computed: {
    ...mapGetters({
      types: 'security/menu/types',
      menus: 'security/menu/menus',
      currentLang: 'setting/lang'
    }),
    typeFields () {
      return [
        { key: 'name', label: this.$t('security.createMenu.fields.type') },
        { key: 'stateLabel', label: this.$t('common.status.label') },
        { key: 'actions', label: '', _style: 'width: 200px; text-align: center;' }
      ]
    },
    menuFields () {
      return [
        { key: 'name', label: this.$t('security.createMenu.fields.menuTitle') },
        { key: 'descriptionText', label: this.$t('common.description') },
        { key: 'path', label: this.$t('security.createMenu.fields.path') },
        { key: 'typeName', label: this.$t('security.createMenu.fields.type') },
        { key: 'stateLabel', label: this.$t('common.status.label') },
        { key: 'actions', label: '', _style: 'width: 200px; text-align: center;' }
      ]
    },
    heroStats () {
      return [
        { label: this.$t('security.createMenu.stats.types'), value: this.types.length, icon: 'cil-layers', iconClass: 'security-stat__icon--primary' },
        { label: this.$t('security.createMenu.stats.menus'), value: this.menus.length, icon: 'cil-list', iconClass: 'security-stat__icon--success' },
        { label: this.$t('security.createMenu.stats.mapped'), value: this.menus.filter(item => item && item.source === 'mapped').length, icon: 'cil-link', iconClass: 'security-stat__icon--warning' }
      ]
    },
    menuTypeOptions () {
      return this.types.map(type => ({
        value: type._id,
        label: getTextByLanguage(type.title, this.currentLang) || type.name
      }))
    },
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    typesTableItems () {
      return this.types.map(type => ({
        ...type,
        name: getTextByLanguage(type.title, this.currentLang) || type.name,
        stateLabel: type && type.state ? this.$t('common.status.active') : this.$t('common.status.inactive')
      }))
    },
    menuTableItems () {
      return this.menus.map(menu => ({
        ...menu,
        name: getTextByLanguage(menu.title, this.currentLang) || menu.name,
        descriptionText: getTextByLanguage(menu.description, this.currentLang) || menu.descriptionText,
        typeName: this.resolveTypeName(menu.typeId)
      }))
    }
  },
  async created () {
    await this.loadData()
  },
  methods: {
    resolveTypeName (typeId) {
      const type = this.types.find(item => item && item._id === typeId)
      return type ? (getTextByLanguage(type.title, this.currentLang) || type.name) : ''
    },
    handleInvalid (message) {
      notifyWarning(this.$store, message)
    },
    async loadData () {
      try {
        await this.$store.dispatch('security/menu/explorer')
        this.lastUpdatedAt = new Date()
      } catch (err) {
        notifyError(this.$store, this.$t('security.messages.loadError'))
      }
    },
    openCreateTypeModal () {
      this.typeDraft = createTypeDraft()
      this.typeModal = true
    },
    openEditTypeModal (type) {
      this.typeDraft = {
        _id: type._id,
        title: normalizeOrDefault(type && type.title),
        state: typeof type.state === 'boolean' ? type.state : true
      }
      this.typeModal = true
    },
    async saveType (payload) {
      try {
        if (payload._id) {
          await this.$store.dispatch('security/menu/updateType', payload)
          notifySuccess(this.$store, this.$t('security.createMenu.messages.typeUpdated'))
        } else {
          await this.$store.dispatch('security/menu/createType', payload)
          notifySuccess(this.$store, this.$t('security.createMenu.messages.typeCreated'))
        }
        this.closeTypeModal()
      } catch (err) {
        notifyError(this.$store, this.$t('security.createMenu.messages.cannotSaveType'))
      }
    },
    async removeType (type) {
      try {
        await this.$store.dispatch('security/menu/removeType', type)
        notifyInfo(this.$store, this.$t('security.createMenu.messages.typeRemoved'))
      } catch (err) {
        notifyWarning(this.$store, this.$t('security.createMenu.messages.typeInUse'))
      }
    },
    openCreateMenuModal () {
      this.menuDraft = createMenuDraft(this.types[0] ? this.types[0]._id : '')
      this.menuModal = true
    },
    openEditMenuModal (menu) {
      if (menu.source === 'mapped') {
        notifyWarning(this.$store, this.$t('security.createMenu.messages.mappedReadonly'))
        return
      }
      this.menuDraft = {
        _id: menu._id,
        title: normalizeOrDefault(menu && menu.title),
        description: normalizeOrDefault(menu && menu.description),
        path: menu.path,
        typeId: menu.typeId,
        state: typeof menu.state === 'boolean' ? menu.state : true
      }
      this.menuModal = true
    },
    async saveMenu (payload) {
      try {
        if (payload._id) {
          await this.$store.dispatch('security/menu/updateMenu', payload)
          notifySuccess(this.$store, this.$t('security.createMenu.messages.menuUpdated'))
        } else {
          await this.$store.dispatch('security/menu/createMenu', payload)
          notifySuccess(this.$store, this.$t('security.createMenu.messages.menuCreated'))
        }
        this.closeMenuModal()
      } catch (err) {
        notifyError(this.$store, this.$t('security.createMenu.messages.cannotSaveMenu'))
      }
    },
    async removeMenu (menu) {
      if (menu.source === 'mapped') {
        notifyWarning(this.$store, this.$t('security.createMenu.messages.mappedRemove'))
        return
      }
      try {
        await this.$store.dispatch('security/menu/removeMenu', menu)
        notifyInfo(this.$store, this.$t('security.createMenu.messages.menuRemoved'))
      } catch (err) {
        notifyError(this.$store, this.$t('security.createMenu.messages.cannotRemoveMenu'))
      }
    },
    closeMenuModal () {
      this.menuDraft = createMenuDraft(this.types[0] ? this.types[0]._id : '')
      this.menuModal = false
    },
    closeTypeModal () {
      this.typeDraft = createTypeDraft()
      this.typeModal = false
    }
  }
}
</script>

<style scoped lang="scss">
@import "./security-page.shared";
</style>
