const OPTION_SETS = {
  provisioningStrategies: ['RULE_BASED', 'MANUAL_REVIEW', 'HR_SYNC'],
  affiliationStatuses: ['ACTIVE', 'INACTIVE', 'SABBATICAL', 'SUSPENDED'],
  positionTypes: ['POSITION', 'ACADEMIC_ROLE', 'ADMIN_ROLE', 'ACTING_ROLE'],
  movementTypes: ['TRANSFER', 'PROMOTION', 'POSITION_CHANGE', 'ROTATION', 'ACTING_ASSIGNMENT'],
  movementImpacts: ['INFO', 'ACCESS_REVIEW', 'POLICY_RECALCULATION'],
  movementStatuses: ['PLANNED', 'COMPLETED', 'CANCELLED'],
  leaveTypes: ['STUDY_LEAVE', 'TRAINING_LEAVE', 'MEDICAL_LEAVE', 'MATERNITY_LEAVE', 'SUSPENSION', 'SPECIAL_ASSIGNMENT'],
  leaveStatuses: ['REQUESTED', 'APPROVED', 'COMPLETED', 'CANCELLED'],
  accessImpacts: ['KEEP', 'LIMIT', 'SUSPEND'],
  developmentTypes: ['TRAINING', 'CERTIFICATION', 'STUDY', 'ONBOARDING', 'CAREER_PROGRESS'],
  developmentStatuses: ['PLANNED', 'IN_PROGRESS', 'COMPLETED', 'EXPIRED'],
  assignmentTypes: ['TEMPORARY_ROLE', 'ACTING_ROLE', 'COMMITTEE', 'DELEGATION'],
  assignmentStatuses: ['ACTIVE', 'PLANNED', 'COMPLETED', 'INACTIVE'],
  accessSources: ['MANUAL', 'POLICY', 'RULE', 'ASSIGNMENT', 'HR_IMPORT']
}

function toOptions (items) {
  return items.map(item => ({ value: item, label: item.replace(/_/g, ' ') }))
}

function findOption (options, value) {
  const normalized = String(value || '').trim()
  if (!normalized) return null
  return options.find(item => item.value === normalized) || { value: normalized, label: normalized.replace(/_/g, ' ') }
}

function splitOrgPathParts (value) {
  const parts = Array.isArray(value) ? value.filter(Boolean) : []
  return {
    orgGroupName: parts[0] || '',
    orgUnitName: parts[1] || '',
    orgSubUnitName: parts[2] || ''
  }
}

function composeOrgPath (item, prefix) {
  const source = prefix
    ? [
        item && item[`${prefix}OrgGroupName`],
        item && item[`${prefix}OrgUnitName`],
        item && item[`${prefix}OrgSubUnitName`]
      ]
    : [
        item && item.orgGroupName,
        item && item.orgUnitName,
        item && item.orgSubUnitName
      ]
  return source.map(part => String(part || '').trim()).filter(Boolean)
}

function toDateInput (value) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return date.toISOString().slice(0, 10)
}

function blankAffiliation () {
  return {
    typeId: '',
    typeSelected: null,
    title: '',
    orgCode: '',
    orgGroupSelected: null,
    orgGroupName: '',
    orgUnitSelected: null,
    orgUnitName: '',
    orgSubUnitSelected: null,
    orgSubUnitName: '',
    startDate: '',
    endDate: '',
    status: 'ACTIVE',
    statusSelected: findOption(toOptions(OPTION_SETS.affiliationStatuses), 'ACTIVE'),
    isPrimary: false
  }
}

function blankPosition () {
  return {
    title: '',
    type: 'POSITION',
    typeSelected: findOption(toOptions(OPTION_SETS.positionTypes), 'POSITION'),
    orgGroupSelected: null,
    orgGroupName: '',
    orgUnitSelected: null,
    orgUnitName: '',
    orgSubUnitSelected: null,
    orgSubUnitName: '',
    startDate: '',
    endDate: '',
    isActing: false
  }
}

function blankMovement () {
  return {
    type: 'TRANSFER',
    typeSelected: findOption(toOptions(OPTION_SETS.movementTypes), 'TRANSFER'),
    fromTitle: '',
    toTitle: '',
    fromOrgGroupSelected: null,
    fromOrgGroupName: '',
    fromOrgUnitSelected: null,
    fromOrgUnitName: '',
    fromOrgSubUnitSelected: null,
    fromOrgSubUnitName: '',
    toOrgGroupSelected: null,
    toOrgGroupName: '',
    toOrgUnitSelected: null,
    toOrgUnitName: '',
    toOrgSubUnitSelected: null,
    toOrgSubUnitName: '',
    effectiveDate: '',
    reason: '',
    referenceNo: '',
    approvedBy: '',
    impact: 'INFO',
    impactSelected: findOption(toOptions(OPTION_SETS.movementImpacts), 'INFO'),
    status: 'COMPLETED',
    statusSelected: findOption(toOptions(OPTION_SETS.movementStatuses), 'COMPLETED')
  }
}

function blankLeave () {
  return {
    type: 'STUDY_LEAVE',
    typeSelected: findOption(toOptions(OPTION_SETS.leaveTypes), 'STUDY_LEAVE'),
    startDate: '',
    endDate: '',
    status: 'APPROVED',
    statusSelected: findOption(toOptions(OPTION_SETS.leaveStatuses), 'APPROVED'),
    reason: '',
    referenceNo: '',
    approvedBy: '',
    accessImpact: 'KEEP',
    accessImpactSelected: findOption(toOptions(OPTION_SETS.accessImpacts), 'KEEP'),
    remarks: ''
  }
}

function blankDevelopment () {
  return {
    type: 'TRAINING',
    typeSelected: findOption(toOptions(OPTION_SETS.developmentTypes), 'TRAINING'),
    title: '',
    provider: '',
    startDate: '',
    endDate: '',
    status: 'PLANNED',
    statusSelected: findOption(toOptions(OPTION_SETS.developmentStatuses), 'PLANNED'),
    outcome: '',
    credential: '',
    hours: '',
    linkedLeaveType: '',
    linkedLeaveTypeSelected: null,
    remarks: ''
  }
}

function blankAssignment () {
  return {
    type: 'TEMPORARY_ROLE',
    typeSelected: findOption(toOptions(OPTION_SETS.assignmentTypes), 'TEMPORARY_ROLE'),
    title: '',
    orgGroupSelected: null,
    orgGroupName: '',
    orgUnitSelected: null,
    orgUnitName: '',
    orgSubUnitSelected: null,
    orgSubUnitName: '',
    startDate: '',
    endDate: '',
    status: 'ACTIVE',
    statusSelected: findOption(toOptions(OPTION_SETS.assignmentStatuses), 'ACTIVE'),
    scope: 'unit',
    scopeSelected: { value: 'unit', label: 'unit' },
    approvedBy: '',
    referenceNo: '',
    remarks: '',
    temporary: true,
    accessProfileIds: [],
    accessProfileSelections: []
  }
}

function blankAccessProfile () {
  return {
    profileId: '',
    profileSelected: null,
    scope: 'self',
    scopeSelected: { value: 'self', label: 'self' },
    source: 'MANUAL',
    sourceSelected: findOption(toOptions(OPTION_SETS.accessSources), 'MANUAL'),
    startDate: '',
    endDate: ''
  }
}

export {
  OPTION_SETS,
  blankAccessProfile,
  blankAffiliation,
  blankAssignment,
  blankDevelopment,
  blankLeave,
  blankMovement,
  blankPosition,
  composeOrgPath,
  findOption,
  splitOrgPathParts,
  toDateInput,
  toOptions
}
