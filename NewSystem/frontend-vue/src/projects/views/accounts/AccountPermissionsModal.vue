<template>
  <CModal
    :show="show"
    @update:show="onShowChange"
    size="xl"
    class="account-permissions-modal"
    add-content-classes="border-radius-1"
  >
    <template #header-wrapper><div></div></template>

    <div class="permissions-modal__hero">
      <div class="permissions-modal__title">{{ $t('accounts.permissions.title') }}</div>
      <div class="permissions-modal__subtitle">
        {{ $t('accounts.permissions.subtitle') }}
      </div>
    </div>

    <div class="permissions-modal__body">
      <div class="permissions-modal__summary mb-4">
        <div class="permissions-modal__summary-card">
          <div class="permissions-modal__summary-label">{{ $t('accounts.permissions.summary.assignedGroups') }}</div>
          <div class="permissions-modal__summary-value">{{ groupRows.length }}</div>
        </div>
        <div class="permissions-modal__summary-card">
          <div class="permissions-modal__summary-label">{{ $t('accounts.permissions.summary.permissionRows') }}</div>
          <div class="permissions-modal__summary-value">{{ permissionRows.length }}</div>
        </div>
        <div class="permissions-modal__summary-card">
          <div class="permissions-modal__summary-label">Active Sessions</div>
          <div class="permissions-modal__summary-value">{{ sessionRows.length }}</div>
        </div>
        <div class="permissions-modal__summary-card">
          <div class="permissions-modal__summary-label">Trusted Devices</div>
          <div class="permissions-modal__summary-value">{{ trustedDeviceRows.length }}</div>
        </div>
      </div>

      <CCard class="permissions-modal__section mb-4">
        <CCardBody>
          <div class="permissions-modal__section-title">
            <CIcon name="cil-people" class="mr-2" />
            {{ $t('accounts.permissions.sections.assignedGroups') }}
          </div>
          <div v-if="groupRows.length" class="permissions-group-grid">
            <div v-for="group in groupRows" :key="group.assignmentId || group.label" class="permissions-group-card">
              <div class="permissions-group-card__title">{{ group.label }}</div>
              <div class="permissions-group-card__meta">{{ $t('accounts.permissions.scope') }}: {{ group.scope }}</div>
            </div>
          </div>
          <div v-else class="permissions-empty">{{ $t('accounts.permissions.empty.assignedGroups') }}</div>
        </CCardBody>
      </CCard>

      <CCard class="permissions-modal__section">
        <CCardBody>
          <div class="permissions-modal__section-title">
            <CIcon name="cil-list-rich" class="mr-2" />
            {{ $t('accounts.permissions.sections.effectivePermissions') }}
          </div>
          <CDataTable
            v-if="permissionRows.length"
            :items="permissionRows"
            :fields="fields"
            hover
            striped
            :items-per-page="8"
            pagination
          >
            <template #path="{ item }">
              <td>
                <span class="permissions-path">{{ item.path }}</span>
              </td>
            </template>
            <template #grants="{ item }">
              <td>
                <div class="permissions-chip-row">
                  <span v-for="grant in grantLabels(item)" :key="`${item.path}-${grant}`" class="permissions-chip">
                    {{ grant }}
                  </span>
                </div>
              </td>
            </template>
          </CDataTable>
          <div v-else class="permissions-empty">{{ $t('accounts.permissions.empty.permissions') }}</div>
        </CCardBody>
      </CCard>

      <CCard class="permissions-modal__section mt-4">
        <CCardBody>
          <div class="permissions-modal__section-title">
            <CIcon name="cil-mobile" class="mr-2" />
            Active Sessions
          </div>
          <CDataTable
            v-if="sessionRows.length"
            :items="sessionRows"
            :fields="sessionFields"
            hover
            striped
            :items-per-page="5"
            pagination
          >
            <template #current="{ item }">
              <td>{{ item.current ? 'Current' : 'Other' }}</td>
            </template>
            <template #system="{ item }">
              <td>
                <span class="permissions-system-badge">{{ item.systemLabel }}</span>
              </td>
            </template>
            <template #actions="{ item }">
              <td class="text-right">
                <CButton size="sm" color="danger" variant="outline" shape="pill" :disabled="item.current" @click="$emit('revoke-session', item)">Revoke</CButton>
              </td>
            </template>
          </CDataTable>
          <div v-else class="permissions-empty">No active sessions.</div>
        </CCardBody>
      </CCard>

      <CCard class="permissions-modal__section mt-4">
        <CCardBody>
          <div class="permissions-modal__section-title">
            <CIcon name="cil-screen-smartphone" class="mr-2" />
            Trusted Devices
          </div>
          <CDataTable
            v-if="trustedDeviceRows.length"
            :items="trustedDeviceRows"
            :fields="trustedDeviceFields"
            hover
            striped
            :items-per-page="5"
            pagination
          >
            <template #system="{ item }">
              <td>
                <span class="permissions-system-badge">{{ item.systemLabel }}</span>
              </td>
            </template>
            <template #actions="{ item }">
              <td class="text-right">
                <CButton size="sm" color="danger" variant="outline" shape="pill" @click="$emit('revoke-trusted-device', item)">Revoke</CButton>
              </td>
            </template>
          </CDataTable>
          <div v-else class="permissions-empty">No trusted devices.</div>
        </CCardBody>
      </CCard>
    </div>

    <template #footer-wrapper>
      <div class="permissions-modal__footer">
        <CButton color="dark" variant="outline" class="permissions-modal__btn" @click="onClose">
          <CIcon name="cil-x" class="mr-1" />
          {{ $t('common.actions.cancel') }}
        </CButton>
      </div>
    </template>
  </CModal>
</template>

<script>
export default {
  name: 'AccountPermissionsModal',
  props: {
    show: { type: Boolean, default: false },
    account: { type: Object, default: null },
    groups: { type: Array, default: () => [] },
    permissions: { type: Array, default: () => [] },
    sessions: { type: Array, default: () => [] },
    trustedDevices: { type: Array, default: () => [] }
  },
  data () {
    return {
      fields: [
        { key: 'path', label: 'Path' },
        { key: 'grants', label: 'Permissions' }
      ],
      sessionFields: [
        { key: 'deviceId', label: 'Device' },
        { key: 'system', label: 'System' },
        { key: 'dateTime', label: 'Issued At' },
        { key: 'current', label: 'State' },
        { key: 'actions', label: '#', _style: 'width: 120px; text-align: right;' }
      ],
      trustedDeviceFields: [
        { key: 'deviceId', label: 'Device' },
        { key: 'system', label: 'System' },
        { key: 'trustedAt', label: 'Trusted At' },
        { key: 'expiresAt', label: 'Expires At' },
        { key: 'actions', label: '#', _style: 'width: 120px; text-align: right;' }
      ]
    }
  },
  computed: {
    groupRows () {
      return Array.isArray(this.groups) ? this.groups : []
    },
    permissionRows () {
      return Array.isArray(this.permissions) ? this.permissions : []
    },
    sessionRows () {
      return (Array.isArray(this.sessions) ? this.sessions : []).map(item => ({
        _id: item && item._id ? String(item._id) : '',
        id: item && item._id ? String(item._id) : `${item && item.deviceId ? item.deviceId : 'session'}-${item && item.dateTime ? item.dateTime : ''}`,
        deviceId: item && item.deviceId ? String(item.deviceId) : '-',
        userAgent: item && item.userAgent ? String(item.userAgent) : '-',
        lastIp: item && item.lastIp ? String(item.lastIp) : '-',
        system: item && item.system ? String(item.system) : 'newSystem',
        systemLabel: this.getSystemLabel(item && item.system),
        clientId: item && item.clientId ? String(item.clientId) : '-',
        audience: item && item.audience ? String(item.audience) : '-',
        dateTime: item && item.dateTime ? String(item.dateTime) : '-',
        current: !!(item && item.current)
      }))
    },
    trustedDeviceRows () {
      return (Array.isArray(this.trustedDevices) ? this.trustedDevices : []).map(item => ({
        _id: item && item._id ? String(item._id) : '',
        id: item && item._id ? String(item._id) : `${item && item.deviceId ? item.deviceId : 'device'}-${item && item.trustedAt ? item.trustedAt : ''}`,
        deviceId: item && item.deviceId ? String(item.deviceId) : '-',
        userAgent: item && item.userAgent ? String(item.userAgent) : '-',
        lastIp: item && item.lastIp ? String(item.lastIp) : '-',
        system: item && item.system ? String(item.system) : 'newSystem',
        systemLabel: this.getSystemLabel(item && item.system),
        clientId: item && item.clientId ? String(item.clientId) : '-',
        audience: item && item.audience ? String(item.audience) : '-',
        trustedAt: item && item.trustedAt ? String(item.trustedAt) : '-',
        expiresAt: item && item.expiresAt ? String(item.expiresAt) : '-'
      }))
    }
  },
  methods: {
    getSystemLabel (system) {
      const normalized = system ? String(system).trim() : 'newSystem'
      return normalized ? normalized.toUpperCase() : 'NewSystem'
    },
    grantLabels (item) {
      const labels = []
      if (item && item.all) labels.push('ALL')
      if (item && item.view) labels.push('VIEW')
      if (item && item.edit) labels.push('EDIT')
      if (item && item.delete) labels.push('DELETE')
      if (item && item.action) labels.push('ACTION')
      if (item && item.logs) labels.push('LOGS')
      return labels.length ? labels : ['NONE']
    },
    onShowChange (value) {
      this.$emit('update:show', value)
      if (!value) this.$emit('close')
    },
    onClose () {
      this.$emit('update:show', false)
      this.$emit('close')
    }
  }
}
</script>

<style scoped lang="scss">
.account-permissions-modal {
  ::v-deep .modal-content {
    border: 1px solid #dfe6ee;
    border-radius: 1.5rem;
    box-shadow: 0 18px 44px rgba(36, 52, 71, 0.14);
    overflow: hidden;
  }

  ::v-deep .modal-body {
    padding: 0;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
  }

  .permissions-modal__hero {
    padding: 1.1rem 1.25rem;
    background: linear-gradient(135deg, #5f0f12 0%, #8c1515 56%, #c7662d 100%);
    color: #fff;
  }

  .permissions-modal__eyebrow {
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: rgba(255, 235, 215, 0.78);
    font-weight: 700;
  }

  .permissions-modal__title {
    font-size: 1.2rem;
    font-weight: 700;
    margin-top: 0.2rem;
  }

  .permissions-modal__subtitle {
    color: rgba(255, 244, 232, 0.88);
    margin-top: 0.3rem;
    font-size: 0.78rem;
  }

  .permissions-modal__body {
    padding: 1.15rem;
  }

  .permissions-modal__summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 0.85rem;
  }

  .permissions-modal__summary-card {
    border: 1px solid #e8edf3;
    border-radius: 1rem;
    background: linear-gradient(180deg, #fffdfa 0%, #fff8ee 100%);
    padding: 0.72rem 0.85rem;
  }

  .permissions-modal__summary-label {
    color: #8a7042;
    font-size: 0.64rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    font-weight: 700;
  }

  .permissions-modal__summary-value {
    margin-top: 0.25rem;
    color: #7b1719;
    font-size: 1.08rem;
    font-weight: 700;
    line-height: 1.1;
  }

  .permissions-modal__section {
    border: 1px solid #e2e8f0;
    border-radius: 1rem;
    box-shadow: 0 6px 18px rgba(60, 75, 100, 0.05);
  }

  .permissions-modal__section :deep(thead th) {
    border-top: 0;
    border-bottom: 1px solid #e6ebf1;
    color: #41536d;
    font-size: 0.79rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    background: #fbfcfe;
  }

  .permissions-modal__section :deep(tbody td) {
    border-top: 1px solid #eef2f6;
    vertical-align: middle;
    background: #fff;
  }

  .permissions-modal__section-title {
    display: flex;
    align-items: center;
    color: #243447;
    font-weight: 700;
    margin-bottom: 1rem;
    font-size: 0.9rem;
  }

  .permissions-group-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.85rem;
  }

  .permissions-group-card {
    border: 1px solid #e5ebf2;
    border-radius: 0.9rem;
    background: #f8fafc;
    padding: 0.66rem 0.76rem;
  }

  .permissions-group-card__title {
    color: #233247;
    font-weight: 700;
    font-size: 0.88rem;
  }

  .permissions-group-card__meta {
    color: #74839a;
    font-size: 0.72rem;
    margin-top: 0.2rem;
  }

  .permissions-device-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 0.85rem;
  }

  .permissions-device-card {
    border: 1px solid #e5ebf2;
    border-radius: 0.9rem;
    background: #f8fafc;
    padding: 0.72rem 0.8rem;
  }

  .permissions-device-card__title {
    color: #233247;
    font-weight: 700;
    font-size: 0.84rem;
    word-break: break-word;
  }

  .permissions-device-card__meta {
    color: #74839a;
    font-size: 0.72rem;
    margin-top: 0.24rem;
    word-break: break-word;
  }

  .permissions-path {
    display: inline-block;
    color: #334a62;
    font-weight: 600;
    font-family: monospace;
    font-size: 0.78rem;
  }

  .permissions-chip-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
  }

  .permissions-chip {
    display: inline-flex;
    align-items: center;
    padding: 0.22rem 0.55rem;
    border-radius: 999px;
    background: #f6e6dd;
    color: #7b1719;
    font-size: 0.62rem;
    font-weight: 700;
  }

  .permissions-system-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.52rem;
    border-radius: 999px;
    background: #edf6ee;
    color: #1f6f43;
    font-size: 0.62rem;
    font-weight: 800;
    letter-spacing: 0.08em;
  }

  .permissions-empty {
    color: #74839a;
    font-size: 0.76rem;
  }

  .permissions-modal__footer {
    display: flex;
    justify-content: flex-end;
    padding: 0.9rem 1.15rem 1rem;
    border-top: 1px solid #e2e8f0;
    background: linear-gradient(180deg, rgba(255, 255, 255, 0.82) 0%, #f8fafc 100%);
  }

  .permissions-modal__btn {
    min-width: 112px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.76rem;
  }

  @media (max-width: 767px) {
    .permissions-modal__summary {
      grid-template-columns: 1fr;
    }
  }
}
</style>
