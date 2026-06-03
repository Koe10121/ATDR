<template>
  <CCard class="bg-style2 account-table-card">
    <CCardBody>
      <div class="account-table-card__header">
        <div class="account-table-card__copy">
          <h5 class="mb-1 d-flex align-items-center">
            <CIcon name="cil-contact" class="mr-2 account-heading-icon" />
            <span>{{ $t('accounts.directory.title') }}</span>
          </h5>
          <div class="text-muted small">{{ $t('accounts.directory.table.subtitle') }}</div>
        </div>
        <CButton
          v-if="allowAction"
          color="success"
          variant="outline"
          class="account-invite-btn"
          @click="$emit('invite')"
        >
          <CIcon name="cil-user-follow" class="mr-1" />
          {{ $t('accounts.directory.actions.invite') }}
        </CButton>
      </div>
      <CDataTable
        hover
        table-filter
        striped
        :items="items"
        :fields="fields"
        :items-per-page="items.length || 1"
        sorter
      >
        <template #fullName="{ item }">
          <td>
            <div class="account-identity">
              <div class="account-avatar">
                <img v-if="hasRenderableAccountImage(item)" :src="item.image" alt="Profile image" @error="onAccountImageError(item._id)">
                <span v-else>{{ initials(item.fullName) }}</span>
                <span
                  class="account-avatar__status"
                  :class="`account-avatar__status--${String(item.statusKey || '').toLowerCase()}`"
                  v-c-tooltip="{ content: item.statusLabel, placement: 'top' }"
                ></span>
              </div>
              <div>
                <div class="account-name">{{ item.fullName }}</div>
                <div class="account-subtext">{{ item.email }}</div>
              </div>
            </div>
          </td>
        </template>
        <template #code="{ item }">
          <td>
            <span class="account-code">{{ item.code }}</span>
          </td>
        </template>
        <template #groupLabel="{ item }">
          <td>
            <span class="account-chip">{{ item.groupLabel }}</span>
          </td>
        </template>
        <template #lastLogin="{ item }">
          <td>
            <div class="account-login-meta">{{ item.lastLoginLabel }}</div>
          </td>
        </template>
        <template #actions="{ item }">
          <td class="text-center">
            <CButton
              v-if="allowAction"
              size="sm"
              color="dark"
              variant="outline"
              shape="pill"
              class="mr-2 account-action-btn"
              v-c-tooltip="{ content: $t('accounts.directory.actions.access'), placement: 'top' }"
              :aria-label="$t('accounts.directory.actions.access')"
              @click="$emit('access', item)"
            >
              <CIcon name="cil-shield-alt" />
            </CButton>
            <CButton
              v-if="allowEdit"
              size="sm"
              color="info"
              variant="outline"
              shape="pill"
              class="mr-2 account-action-btn"
              v-c-tooltip="{ content: $t('accounts.directory.actions.edit'), placement: 'top' }"
              :aria-label="$t('accounts.directory.actions.edit')"
              @click="$emit('edit', item)"
            >
              <CIcon name="cil-pencil" />
            </CButton>
            <CButton
              v-if="allowAction"
              size="sm"
              color="danger"
              variant="outline"
              shape="pill"
              class="account-remove-btn"
              v-c-tooltip="{ content: $t('accounts.directory.actions.remove'), placement: 'top' }"
              :aria-label="$t('accounts.directory.actions.remove')"
              @click="$emit('remove-newSystem-access', item)"
            >
              <CIcon name="cil-trash" />
            </CButton>
          </td>
        </template>
      </CDataTable>
    </CCardBody>
  </CCard>
</template>

<script>
import SecurityAccess from '@/projects/mixins/securityAccess'

export default {
  name: 'AccountDirectoryTable',
  mixins: [SecurityAccess],
  props: {
    items: { type: Array, default: () => [] },
    permissionPath: { type: String, default: '' }
  },
  data () {
    return {
      brokenImageIds: {},
      fields: [
        { key: 'code', label: 'Code' },
        { key: 'fullName', label: 'Full Name' },
        { key: 'groupLabel', label: 'Group' },
        { key: 'lastLogin', label: 'Last Login' },
        { key: 'actions', label: '#', _style: 'width: 320px; text-align:center;' }
      ]
    }
  },
  watch: {
    items () {
      this.brokenImageIds = {}
    }
  },
  computed: {
    resolvedPermissionPath () {
      return this.permissionPath || this.defaultPermissionPath
    },
    allowEdit () {
      return this.canEditPath(this.resolvedPermissionPath)
    },
    allowAction () {
      return this.canActionPath(this.resolvedPermissionPath)
    }
  },
  methods: {
    initials (fullName) {
      const text = String(fullName || '').trim()
      if (!text || text === '-') return 'NA'
      return text
        .split(/\s+/)
        .slice(0, 2)
        .map(part => part.charAt(0).toUpperCase())
        .join('')
    },
    hasRenderableAccountImage (item) {
      const id = item && item._id ? String(item._id) : ''
      return !!(item && item.image && !this.brokenImageIds[id])
    },
    onAccountImageError (id) {
      const key = String(id || '')
      if (!key) return
      this.$set(this.brokenImageIds, key, true)
    }
  }
}
</script>

<style scoped lang="scss">
.account-table-card {
  animation: account-fade-up 0.65s ease-out both;
  animation-delay: 0.3s;
  overflow: hidden;
  border: 1px solid rgba(223, 230, 238, 0.78);
  border-radius: 1.5rem;
  box-shadow: 0 14px 30px rgba(44, 52, 71, 0.06);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(249, 250, 252, 0.98));
}

.account-table-card__header {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
  padding-bottom: 0.85rem;
  border-bottom: 1px solid rgba(221, 228, 236, 0.85);
}

.account-table-card__copy {
  min-width: 0;
}

.account-invite-btn {
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 700;
}

.account-table-card h5 {
  font-size: 1rem;
  font-weight: 700;
  color: #233247;
}

.account-heading-icon {
  color: #8c1515;
}

.account-table-card :deep(.table-responsive) {
  margin-bottom: 0;
}

.account-table-card :deep(.form-inline) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin: 0 0 1rem;
  color: #5f6f86;
  font-size: 0.84rem;
  font-weight: 600;
}

.account-table-card :deep(.form-inline label) {
  margin: 0;
  color: #5f6f86;
  font-size: 0.84rem;
  font-weight: 700;
}

.account-table-card :deep(.form-inline .form-control) {
  min-width: 320px;
  width: min(100%, 420px);
  height: 40px;
  border: 1px solid #dde4ec;
  border-radius: 1rem;
  background: linear-gradient(180deg, #ffffff, #fbfcfe);
  color: #243447;
  box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.55);
  padding: 0.6rem 0.9rem;
  transition: border-color 0.2s ease, box-shadow 0.2s ease, background-color 0.2s ease;
}

.account-table-card :deep(.form-inline .form-control::placeholder) {
  color: #97a3b6;
}

.account-table-card :deep(.form-inline .form-control:focus) {
  border-color: #8c1515;
  background: #fff;
  box-shadow: 0 0 0 0.2rem rgba(140, 21, 21, 0.12);
}

.account-table-card :deep(table) {
  margin-bottom: 0;
}

.account-table-card :deep(thead th) {
  border-top: 0;
  border-bottom: 1px solid #e6ebf1;
  color: #41536d;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: #fbfcfe;
  vertical-align: middle;
}

.account-table-card :deep(tbody td) {
  border-top: 1px solid #eef2f6;
  vertical-align: middle;
  padding-top: 0.74rem;
  padding-bottom: 0.74rem;
  background: #fff;
}

.account-table-card :deep(tbody tr:hover td) {
  background: #fcfdff;
}

.account-table-card :deep(.pagination) {
  margin-top: 1rem;
  margin-bottom: 0;
}

.account-table-card :deep(.page-link) {
  border-radius: 0.75rem;
  border-color: #d9e1ea;
  color: #4a5d78;
  margin: 0 0.15rem;
  box-shadow: none;
}

.account-table-card :deep(.page-item.active .page-link) {
  background: #8c1515;
  border-color: #8c1515;
  color: #fff;
}

.account-table-card :deep(.page-link:focus) {
  box-shadow: 0 0 0 0.2rem rgba(140, 21, 21, 0.12);
}

.account-identity {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  min-width: 220px;
  overflow: visible;
}

.account-avatar {
  position: relative;
  width: 2.3rem;
  height: 2.3rem;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #8c1515, #fec260);
  color: #fff;
  font-size: 0.72rem;
  font-weight: 700;
  flex: 0 0 2.3rem;
  box-shadow: 0 10px 18px rgba(140, 21, 21, 0.16);
}

.account-avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  border-radius: 999px;
}

.account-avatar__status {
  position: absolute;
  right: -0.12rem;
  bottom: -0.08rem;
  width: 0.66rem;
  height: 0.66rem;
  border-radius: 999px;
  border: 2px solid #fff;
  box-shadow: 0 4px 10px rgba(35, 50, 71, 0.16);
  background: #c1cad6;
  z-index: 2;
}

.account-avatar__status--active {
  background: #2eb85c;
}

.account-avatar__status--pending {
  background: #f9b115;
}

.account-avatar__status--locked,
.account-avatar__status--suspended,
.account-avatar__status--archived {
  background: #e55353;
}

.account-avatar__status--inactive {
  background: #768192;
}

.account-name {
  font-weight: 700;
  color: #223247;
  font-size: 0.9rem;
}

.account-subtext {
  color: #74839a;
  font-size: 0.72rem;
}

.account-chip {
  display: inline-flex;
  align-items: center;
  max-width: 22rem;
  padding: 0.24rem 0.52rem;
  border-radius: 999px;
  background: #f8fafc;
  border: 1px solid #e5ebf2;
  color: #41536d;
  font-size: 0.68rem;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.account-login-meta {
  color: #41536d;
  font-size: 0.72rem;
  font-weight: 600;
  line-height: 1.2;
  white-space: nowrap;
}

.account-code {
  display: inline-block;
  font-family: monospace;
  font-size: 0.74rem;
  font-weight: 700;
  background: linear-gradient(180deg, #f8fafc, #f1f5f9);
  color: #334a62;
  padding: 0.28rem 0.54rem;
  border-radius: 0.68rem;
  border: 1px solid #e2e8f0;
}

.account-action-btn,
.account-remove-btn {
  width: 2rem;
  height: 2rem;
  padding: 0;
  border-radius: 999px;
  transition: box-shadow 0.2s ease, transform 0.2s ease;
}

.account-action-btn:hover,
.account-action-btn:focus {
  box-shadow: 0 10px 18px rgba(57, 175, 209, 0.22);
  transform: translateY(-1px);
}

.account-remove-btn:hover,
.account-remove-btn:focus {
  box-shadow: 0 10px 18px rgba(229, 83, 83, 0.22);
  transform: translateY(-1px);
}

@keyframes account-fade-up {
  from {
    opacity: 0;
    transform: translateY(18px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (prefers-reduced-motion: reduce) {
  .account-table-card {
    animation: none;
  }

  .account-action-btn,
  .account-remove-btn {
    transition: none;
  }
}

@media (max-width: 767.98px) {
  .account-table-card__header {
    flex-direction: column;
  }

  .account-table-card :deep(.form-inline) {
    align-items: stretch;
    flex-direction: column;
    justify-content: flex-start;
  }

  .account-table-card :deep(.form-inline .form-control) {
    min-width: 100%;
    width: 100%;
  }
}
</style>
