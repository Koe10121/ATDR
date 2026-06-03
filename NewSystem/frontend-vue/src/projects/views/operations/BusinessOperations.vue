<template>
  <div class="business-ops-page">
    <div class="ops-header">
      <div>
        <div class="ops-header__eyebrow">{{ profile.eyebrow }}</div>
        <h1>{{ profile.title }}</h1>
        <div class="ops-header__meta">{{ profile.period }} · {{ lastUpdatedLabel }}</div>
      </div>
      <div class="ops-header__actions">
        <CButton color="primary" variant="outline" @click="refresh">
          <CIcon name="cil-reload" class="mr-2" />
          Refresh
        </CButton>
        <router-link class="btn btn-outline-secondary" to="/security/permissions/matrix">
          <CIcon name="cil-lock-locked" class="mr-2" />
          Access Matrix
        </router-link>
      </div>
    </div>

    <CRow>
      <CCol v-for="metric in profile.metrics" :key="metric.label" xl="3" md="6" col="12" class="mb-3">
        <CCard class="ops-card ops-metric" :class="`ops-metric--${metric.accent}`">
          <CCardBody>
            <div class="ops-metric__top">
              <div class="ops-metric__label">{{ metric.label }}</div>
              <CIcon :name="metric.icon" />
            </div>
            <div class="ops-metric__value">{{ metric.value }}</div>
            <div class="ops-metric__hint">{{ metric.hint }}</div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

    <CRow>
      <CCol lg="8" class="mb-3">
        <CCard class="ops-card h-100">
          <CCardBody>
            <div class="ops-section-heading">
              <div>
                <h2>Operating Workstreams</h2>
                <span>{{ profile.workstreamMeta }}</span>
              </div>
            </div>

            <div class="ops-stream-tabs">
              <button
                v-for="stream in profile.workstreams"
                :key="stream.id"
                type="button"
                class="ops-stream-tab"
                :class="{ 'is-active': activeStreamId === stream.id }"
                :aria-pressed="activeStreamId === stream.id ? 'true' : 'false'"
                @click="setStream(stream.id)"
              >
                <span>{{ stream.name }}</span>
                <strong>{{ stream.count }}</strong>
              </button>
            </div>

            <div class="ops-active-stream">
              <div>
                <div class="ops-active-stream__label">Focus</div>
                <h3>{{ activeStream.name }}</h3>
                <p>{{ activeStream.focus }}</p>
              </div>
              <div class="ops-progress" :aria-label="`${activeStream.progress}% complete`">
                <div class="ops-progress__bar" :style="{ width: activeStream.progress + '%' }"></div>
              </div>
            </div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol lg="4" class="mb-3">
        <CCard class="ops-card h-100">
          <CCardBody>
            <div class="ops-section-heading">
              <div>
                <h2>Decision Queue</h2>
                <span>{{ profile.decisionMeta }}</span>
              </div>
            </div>
            <div class="ops-decision-list">
              <div v-for="item in profile.decisions" :key="item.title" class="ops-decision">
                <div>
                  <strong>{{ item.title }}</strong>
                  <span>{{ item.owner }}</span>
                </div>
                <CBadge :color="statusColor(item.status)">{{ item.status }}</CBadge>
              </div>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>

    <CRow>
      <CCol lg="7" class="mb-3">
        <CCard class="ops-card h-100">
          <CCardBody>
            <div class="ops-section-heading">
              <div>
                <h2>Operations Board</h2>
                <span>{{ profile.boardMeta }}</span>
              </div>
            </div>
            <div class="ops-table-wrap">
              <table class="ops-table">
                <thead>
                  <tr>
                    <th>Lane</th>
                    <th>Owner</th>
                    <th>Throughput</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="row in profile.board" :key="row.lane">
                    <td>
                      <strong>{{ row.lane }}</strong>
                      <span>{{ row.detail }}</span>
                    </td>
                    <td>{{ row.owner }}</td>
                    <td>{{ row.throughput }}</td>
                    <td><CBadge :color="statusColor(row.status)">{{ row.status }}</CBadge></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol lg="5" class="mb-3">
        <CCard class="ops-card h-100">
          <CCardBody>
            <div class="ops-section-heading">
              <div>
                <h2>Operating Timeline</h2>
                <span>{{ profile.timelineMeta }}</span>
              </div>
            </div>
            <div class="ops-timeline">
              <div v-for="item in profile.timeline" :key="item.time" class="ops-timeline__item">
                <div class="ops-timeline__time">{{ item.time }}</div>
                <div>
                  <strong>{{ item.title }}</strong>
                  <span>{{ item.note }}</span>
                </div>
              </div>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  </div>
</template>

<script>
const PROFILE = {

  eyebrow: 'New System Operations',
  title: 'NewSystem Operating Desk',
  period: 'Current agreement cycle',
  workstreamMeta: 'Drafting, legal review, approval, renewal',
  decisionMeta: 'Agreements waiting for action',
  boardMeta: 'NewSystem operation lanes',
  timelineMeta: 'NewSystem office rhythm',
  metrics: [
    { label: 'Review queue', value: '18', hint: '5 legal checks pending', icon: 'cil-list-rich', accent: 'amber' },
    { label: 'Active NewSystems', value: '126', hint: 'Across partner units', icon: 'cil-check-circle', accent: 'green' },
    { label: 'Expiring soon', value: '9', hint: 'Within the next 90 days', icon: 'cil-warning', accent: 'red' },
    { label: 'Renewal batches', value: '4', hint: 'Owner units preparing action', icon: 'cil-layers', accent: 'blue' }
  ],
  workstreams: [
    { id: 'drafting', name: 'Drafting', count: '12', progress: 58, focus: 'Prepare partner details, scope, owner unit, and document checklist before review.' },
    { id: 'review', name: 'Legal Review', count: '18', progress: 46, focus: 'Track legal comments, revision owners, and approval dependencies.' },
    { id: 'renewal', name: 'Renewal', count: '9', progress: 72, focus: 'Coordinate owner units before agreements enter the expiry window.' }
  ],
  decisions: [
    { title: 'Approve exchange agreement draft', owner: 'International Affairs', status: 'Ready' },
    { title: 'Resolve legal comment set', owner: 'Legal Office', status: 'Watch' },
    { title: 'Confirm renewal owner unit', owner: 'School Coordinator', status: 'In Review' }
  ],
  board: [
    { lane: 'Partner Intake', detail: 'Partner profile and scope validation', owner: 'International Affairs', throughput: '12 drafts', status: 'In Review' },
    { lane: 'Legal Review', detail: 'Contract language and risk checks', owner: 'Legal Office', throughput: '18 reviews', status: 'Watch' },
    { lane: 'Approval Routing', detail: 'Executive approval and signatory tracking', owner: 'NewSystem Secretariat', throughput: '7 approvals', status: 'On Track' },
    { lane: 'Renewal Control', detail: 'Expiry window and owner confirmation', owner: 'Owner Units', throughput: '9 renewals', status: 'Watch' }
  ],
  timeline: [
    { time: '09:30', title: 'Review queue triage', note: 'Prioritize expiring and executive-facing agreements.' },
    { time: '12:00', title: 'Partner data checkpoint', note: 'Confirm partner profile and owner unit details.' },
    { time: '15:30', title: 'Approval follow-up', note: 'Clear signatory, legal, and owner-unit actions.' },
    { time: '17:00', title: 'Renewal snapshot', note: 'Publish expiring agreements and next actions.' }
  ]
}

export default {
  name: 'BusinessOperations',
  data () {
    return {
      lastUpdated: new Date(),
      activeStreamId: PROFILE.workstreams[0].id
    }
  },
  computed: {
    profile () {
      return PROFILE
    },
    activeStream () {
      return this.profile.workstreams.find(item => item.id === this.activeStreamId) || this.profile.workstreams[0]
    },
    lastUpdatedLabel () {
      return new Intl.DateTimeFormat('en-GB', {
        day: '2-digit',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit'
      }).format(this.lastUpdated)
    }
  },
  methods: {
    refresh () {
      this.lastUpdated = new Date()
    },
    setStream (streamId) {
      this.activeStreamId = streamId
    },
    statusColor (status) {
      const normalized = String(status || '').toLowerCase()
      if (normalized.includes('ready') || normalized.includes('track')) return 'success'
      if (normalized.includes('watch') || normalized.includes('review')) return 'warning'
      if (normalized.includes('blocked') || normalized.includes('risk')) return 'danger'
      return 'info'
    }
  }
}
</script>

<style scoped>
.business-ops-page {
  padding: 0.25rem;
}

.ops-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
  padding: 1rem 1.1rem;
  border: 1px solid #d9e2ef;
  border-radius: 8px;
  background: #ffffff;
  box-shadow: 0 12px 28px rgba(34, 45, 70, 0.06);
}

.ops-header__eyebrow,
.ops-metric__label,
.ops-active-stream__label {
  color: #6b778c;
  font-size: 0.74rem;
  font-weight: 700;
  text-transform: uppercase;
}

.ops-header h1 {
  margin: 0.1rem 0;
  color: #172033;
  font-size: 1.55rem;
  font-weight: 700;
}

.ops-header__meta,
.ops-section-heading span,
.ops-metric__hint,
.ops-decision span,
.ops-table td span,
.ops-timeline__item span,
.ops-active-stream p {
  color: #667085;
  font-size: 0.86rem;
  line-height: 1.5;
}

.ops-header__actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 0.6rem;
}

.ops-card {
  border: 1px solid #dfe7f2;
  border-radius: 8px;
  box-shadow: 0 10px 24px rgba(34, 45, 70, 0.055);
}

.ops-metric {
  min-height: 142px;
  border-left-width: 5px;
}

.ops-metric--blue {
  border-left-color: #2563eb;
}

.ops-metric--green {
  border-left-color: #16a34a;
}

.ops-metric--amber {
  border-left-color: #d97706;
}

.ops-metric--red {
  border-left-color: #dc2626;
}

.ops-metric__top,
.ops-section-heading,
.ops-decision,
.ops-timeline__item {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
}

.ops-metric__top .c-icon {
  color: #5b6b82;
  font-size: 1.15rem;
}

.ops-metric__value {
  margin-top: 0.8rem;
  color: #111827;
  font-size: 1.75rem;
  font-weight: 700;
}

.ops-section-heading {
  margin-bottom: 1rem;
}

.ops-section-heading h2 {
  margin: 0;
  color: #172033;
  font-size: 1rem;
  font-weight: 700;
}

.ops-stream-tabs {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.65rem;
  margin-bottom: 1rem;
}

.ops-stream-tab {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 48px;
  padding: 0.7rem 0.8rem;
  border: 1px solid #d8e0eb;
  border-radius: 8px;
  background: #f8fafc;
  color: #243047;
  font-weight: 700;
}

.ops-stream-tab.is-active {
  border-color: #2563eb;
  background: #eef5ff;
  color: #1d4ed8;
}

.ops-active-stream {
  padding: 0.9rem;
  border: 1px solid #d8e0eb;
  border-radius: 8px;
  background: #fbfcfe;
}

.ops-active-stream h3 {
  margin: 0.15rem 0 0.35rem;
  color: #172033;
  font-size: 1.05rem;
  font-weight: 700;
}

.ops-progress {
  height: 8px;
  margin-top: 0.85rem;
  overflow: hidden;
  border-radius: 999px;
  background: #e6edf7;
}

.ops-progress__bar {
  height: 100%;
  border-radius: 999px;
  background: #2563eb;
}

.ops-decision-list {
  display: grid;
  gap: 0.75rem;
}

.ops-decision {
  align-items: center;
  padding: 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #fbfcfe;
}

.ops-decision strong,
.ops-timeline__item strong {
  display: block;
  color: #1f2937;
}

.ops-table-wrap {
  overflow-x: auto;
}

.ops-table {
  width: 100%;
  border-collapse: collapse;
}

.ops-table th,
.ops-table td {
  padding: 0.8rem 0.65rem;
  border-bottom: 1px solid #e5ebf3;
  vertical-align: top;
}

.ops-table th {
  color: #516072;
  font-size: 0.76rem;
  font-weight: 700;
  text-align: left;
  text-transform: uppercase;
}

.ops-table td {
  color: #273449;
}

.ops-table td strong,
.ops-table td span {
  display: block;
}

.ops-timeline {
  display: grid;
  gap: 0.9rem;
}

.ops-timeline__item {
  justify-content: flex-start;
  padding-bottom: 0.9rem;
  border-bottom: 1px solid #e5ebf3;
}

.ops-timeline__item:last-child {
  padding-bottom: 0;
  border-bottom: 0;
}

.ops-timeline__time {
  flex: 0 0 4.2rem;
  color: #1d4ed8;
  font-weight: 700;
}

@media (max-width: 991.98px) {
  .ops-header {
    align-items: flex-start;
    flex-direction: column;
  }

  .ops-header__actions {
    justify-content: flex-start;
  }

  .ops-stream-tabs {
    grid-template-columns: 1fr;
  }
}
</style>
