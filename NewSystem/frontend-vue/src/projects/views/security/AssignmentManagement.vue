<template>
  <div class="security-page">
    <AppSectionHero
      title="Assignment Management"
      subtitle="Bind accounts to groups, define data scope, and control delegated access boundaries."
      :stats="heroStats"
      :meta-label="'Last updated'"
      :meta-value="lastUpdatedLabel"
      @refresh="loadData"
    />

    <CCard>
      <CCardBody>
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div class="small text-muted">Manage account-to-group assignments with explicit scope.</div>
          <CButton v-if="canAddAssignment" color="dark" @click="openCreate">Add Assignment</CButton>
        </div>
        <CDataTable
          :items="assignments"
          :fields="fields"
          hover
          striped
          :items-per-page="10"
          pagination
        >
          <template #scopeUnits="{ item }">
            <td>{{ item.scopeUnits.length ? item.scopeUnits.join(', ') : '-' }}</td>
          </template>
          <template #active="{ item }">
            <td>{{ item.active ? 'Active' : 'Inactive' }}</td>
          </template>
          <template #actions="{ item }">
            <td class="text-right">
              <CButton v-if="canEditAssignment" size="sm" color="dark" variant="outline" shape="pill" class="mr-2" @click="openEdit(item)">Edit</CButton>
              <CButton v-if="canDeleteAssignment" size="sm" color="danger" variant="outline" shape="pill" @click="remove(item)">Delete</CButton>
            </td>
          </template>
        </CDataTable>
      </CCardBody>
    </CCard>

    <CModal :show.sync="showModal" title="Assignment" size="lg">
      <CRow>
        <CCol md="6">
          <label class="small text-muted">Account</label>
          <CSelect v-model="draft.accountId" :options="accountOptions" />
        </CCol>
        <CCol md="6">
          <label class="small text-muted">Group</label>
          <CSelect v-model="draft.groupId" :options="groupOptions" />
        </CCol>
        <CCol md="6" class="mt-3">
          <label class="small text-muted">Data Scope</label>
          <CSelect v-model="draft.dataScope" :options="scopeOptions" />
        </CCol>
        <CCol md="6" class="mt-3">
          <label class="small text-muted">Active</label>
          <CSelect v-model="draft.activeValue" :options="activeOptions" />
        </CCol>
        <CCol col="12" class="mt-3">
          <label class="small text-muted">Scope Units</label>
          <CInput v-model.trim="draft.scopeUnitsText" placeholder="Comma-separated org unit codes/names" />
        </CCol>
      </CRow>
      <template #footer>
        <CButton color="light" @click="closeModal">Cancel</CButton>
        <CButton color="dark" @click="save">Save</CButton>
      </template>
    </CModal>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import SecurityAccess from '@/projects/mixins/securityAccess'
import { notifyError, notifyInfo, notifySuccess } from '@/projects/utils/notify'
import { formatDateTime24 } from '@/projects/utils/date-time'

function emptyDraft () {
  return {
    _id: '',
    accountId: '',
    groupId: '',
    dataScope: 'self',
    scopeUnitsText: '',
    activeValue: 'true'
  }
}

export default {
  name: 'AssignmentManagement',
  mixins: [SecurityAccess],
  components: { AppSectionHero },
  data () {
    return {
      showModal: false,
      lastUpdatedAt: null,
      draft: emptyDraft(),
      fields: [
        { key: 'accountLabel', label: 'Account' },
        { key: 'groupLabel', label: 'Group' },
        { key: 'dataScope', label: 'Data Scope' },
        { key: 'scopeUnits', label: 'Scope Units' },
        { key: 'active', label: 'Status' },
        { key: 'actions', label: '#', _style: 'width: 180px; text-align: right;' }
      ],
      scopeOptions: [
        { value: 'self', label: 'Self' },
        { value: 'unit', label: 'Unit' },
        { value: 'org', label: 'Org' }
      ],
      activeOptions: [
        { value: 'true', label: 'Active' },
        { value: 'false', label: 'Inactive' }
      ]
    }
  },
  computed: {
    ...mapGetters({
      assignments: 'security/assignment/assignments',
      groups: 'security/assignment/groups',
      accounts: 'security/assignment/accounts'
    }),
    lastUpdatedLabel () {
      return formatDateTime24(this.lastUpdatedAt)
    },
    heroStats () {
      return [
        { label: 'Assignments', value: this.assignments.length, icon: 'cil-link', iconClass: 'security-stat__icon--primary' },
        { label: 'Active', value: this.assignments.filter(item => item.active).length, icon: 'cil-check-circle', iconClass: 'security-stat__icon--success' },
        { label: 'Scoped', value: this.assignments.filter(item => item.dataScope !== 'self').length, icon: 'cil-filter', iconClass: 'security-stat__icon--warning' }
      ]
    },
    accountOptions () {
      return this.accounts.map(item => ({ value: item._id, label: item.label }))
    },
    groupOptions () {
      return this.groups.map(item => ({ value: item._id, label: item.name || item.label || item._id }))
    },
    canAddAssignment () {
      return this.canAddPath('/security/permission')
    },
    canEditAssignment () {
      return this.canEditPath('/security/permission')
    },
    canDeleteAssignment () {
      return this.canDeletePath('/security/permission')
    }
  },
  created () {
    this.loadData()
  },
  methods: {
    async loadData () {
      try {
        await this.$store.dispatch('security/assignment/explorer')
        this.lastUpdatedAt = new Date()
      } catch (error) {
        notifyError(this.$store, 'Cannot load assignments.')
      }
    },
    openCreate () {
      this.draft = emptyDraft()
      this.showModal = true
    },
    openEdit (item) {
      this.draft = {
        _id: item._id,
        accountId: item.accountId,
        groupId: item.groupId,
        dataScope: item.dataScope || 'self',
        scopeUnitsText: Array.isArray(item.scopeUnits) ? item.scopeUnits.join(', ') : '',
        activeValue: item.active ? 'true' : 'false'
      }
      this.showModal = true
    },
    closeModal () {
      this.showModal = false
      this.draft = emptyDraft()
    },
    async save () {
      const payload = {
        _id: this.draft._id,
        accountId: this.draft.accountId,
        groupId: this.draft.groupId,
        dataScope: this.draft.dataScope,
        scopeUnits: this.draft.scopeUnitsText
          ? this.draft.scopeUnitsText.split(',').map(item => item.trim()).filter(Boolean)
          : [],
        active: this.draft.activeValue === 'true'
      }
      try {
        if (payload._id) {
          await this.$store.dispatch('security/assignment/update', payload)
          notifySuccess(this.$store, 'Assignment updated.')
        } else {
          await this.$store.dispatch('security/assignment/create', payload)
          notifySuccess(this.$store, 'Assignment created.')
        }
        this.closeModal()
      } catch (error) {
        notifyError(this.$store, 'Cannot save assignment.')
      }
    },
    async remove (item) {
      try {
        await this.$store.dispatch('security/assignment/remove', item)
        notifyInfo(this.$store, 'Assignment removed.')
      } catch (error) {
        notifyError(this.$store, 'Cannot remove assignment.')
      }
    }
  }
}
</script>
