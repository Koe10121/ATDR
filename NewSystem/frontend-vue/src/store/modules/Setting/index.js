import Service from '@/service/api'
import i18n from '@/i18n'
import { formatDateTime24 } from '@/projects/utils/date-time'

const LANG_STORAGE_KEY = 'app-lang'
const SUPPORTED_LANGS = ['en', 'th']

function normalizeLang (value) {
  const normalized = String(value || '').trim().toLowerCase().split(/-|_/)[0]
  return SUPPORTED_LANGS.includes(normalized) ? normalized : 'th'
}

function readStoredLang () {
  if (typeof window === 'undefined' || !window.localStorage) return ''
  return window.localStorage.getItem(LANG_STORAGE_KEY) || ''
}

function persistLang (lang) {
  if (typeof window === 'undefined' || !window.localStorage) return
  window.localStorage.setItem(LANG_STORAGE_KEY, lang)
}

const initialLang = normalizeLang(readStoredLang() || (i18n && i18n.locale) || 'th')
if (i18n && i18n.locale !== initialLang) {
  i18n.locale = initialLang
}

function normalizeLangArray (value) {
  if (Array.isArray(value)) {
    return value
      .map(item => ({
        key: item && item.key ? String(item.key).trim().toLowerCase() : '',
        value: item && item.value ? String(item.value) : ''
      }))
      .filter(item => item.key)
  }
  if (value && typeof value === 'object') {
    return Object.keys(value).map(key => ({
      key: String(key).trim().toLowerCase(),
      value: value[key] == null ? '' : String(value[key])
    }))
  }
  return []
}

function langText (items, lang = 'th') {
  const normalized = normalizeLangArray(items)
  const direct = normalized.find(item => item.key === lang && item.value)
  if (direct) return direct.value
  const fallbackEn = normalized.find(item => item.key === 'en' && item.value)
  if (fallbackEn) return fallbackEn.value
  const first = normalized.find(item => item.value)
  return first ? first.value : ''
}

function toStatusPayload (payload) {
  const title = normalizeLangArray(payload && (payload.title || payload.titleItems))
    .filter(item => item.value && String(item.value).trim())
  const description = normalizeLangArray(payload && (payload.description || payload.descriptionItems))
    .filter(item => item.value && String(item.value).trim())
  return {
    _id: payload && payload._id ? payload._id : null,
    group: payload && (payload.group || payload.groupId) ? String(payload.group || payload.groupId) : '',
    key: payload && payload.key ? String(payload.key).trim().toUpperCase() : '',
    title,
    description,
    state: !(payload && payload.state === false)
  }
}

function toGroupPayload (payload) {
  const title = normalizeLangArray(payload && (payload.title || payload.titleItems))
    .filter(item => item.value && String(item.value).trim())
  const description = normalizeLangArray(payload && (payload.description || payload.descriptionItems))
    .filter(item => item.value && String(item.value).trim())
  return {
    _id: payload && payload._id ? payload._id : null,
    key: payload && payload.key ? String(payload.key).trim().toUpperCase() : '',
    title,
    description,
    state: !(payload && payload.state === false)
  }
}

function mapGroup (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  const state = !(item && item.state === false)
  const createdAt = item && item.create && item.create.datetime ? String(item.create.datetime) : ''
  const createdByName = accountDisplayName(item && item.create && item.create.by)
  const updatedAt = item && item.update && item.update.datetime ? String(item.update.datetime) : ''
  const updatedByName = accountDisplayName(item && item.update && item.update.by)
  return {
    _id: item && item._id ? String(item._id) : '',
    key: item && item.key ? String(item.key) : '',
    title: titleItems,
    titleItems,
    descriptionItems,
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionTh: langText(descriptionItems, 'th'),
    descriptionEn: langText(descriptionItems, 'en'),
    name: langText(titleItems),
    state,
    createdAt,
    createdByName,
    updatedAt,
    updatedByName
  }
}

function mapStatusItem (item) {
  const groupObj = item && item.group && typeof item.group === 'object' ? item.group : null
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  const state = !(item && item.state === false)
  const createdAt = item && item.create && item.create.datetime ? String(item.create.datetime) : ''
  const createdByName = accountDisplayName(item && item.create && item.create.by)
  const updatedAt = item && item.update && item.update.datetime ? String(item.update.datetime) : ''
  const updatedByName = accountDisplayName(item && item.update && item.update.by)
  return {
    _id: item && item._id ? String(item._id) : '',
    groupId: groupObj && groupObj._id ? String(groupObj._id) : (item && item.group ? String(item.group) : ''),
    groupName: groupObj ? langText(groupObj.title) : '',
    key: item && item.key ? String(item.key) : '',
    titleItems,
    descriptionItems,
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionTh: langText(descriptionItems, 'th'),
    descriptionEn: langText(descriptionItems, 'en'),
    statusText: state ? 'Active' : 'Inactive',
    state,
    createdAt,
    createdByName,
    updatedAt,
    updatedByName
  }
}

function mapAuthMessageItem (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  const status = item && item.status && typeof item.status === 'object' ? item.status : null
  const statusKey = status && status.key ? String(status.key).toLowerCase() : ''
  const isDraft = statusKey.includes('draft')
  const isInactive = !isDraft && status && status.state === false
  const statusOption = isDraft ? 'draft' : (isInactive ? 'inactive' : 'active')
  const startDate = item && item.startDate ? String(item.startDate).slice(0, 10) : ''
  const endDate = item && item.endDate ? String(item.endDate).slice(0, 10) : ''
  const createdAt = item && item.create && item.create.datetime ? String(item.create.datetime) : ''
  const createdByName = accountDisplayName(item && item.create && item.create.by)
  const updatedAt = item && item.update && item.update.datetime ? String(item.update.datetime) : ''
  const updatedByName = accountDisplayName(item && item.update && item.update.by)
  return {
    _id: item && item._id ? String(item._id) : '',
    titleItems,
    descriptionItems,
    titleText: langText(titleItems),
    descriptionText: langText(descriptionItems),
    startDate,
    endDate,
    periodText: [startDate, endDate].filter(Boolean).join(' - ') || '-',
    showOnLogin: statusOption === 'active',
    statusOption,
    statusId: status && status._id ? String(status._id) : '',
    statusText: statusOption === 'draft' ? 'Draft' : (statusOption === 'inactive' ? 'Inactive' : 'Active'),
    isActive: statusOption === 'active',
    createdAt,
    createdByName,
    updatedAt,
    updatedByName
  }
}

function mapSettingMessageItem (item) {
  const messageItems = normalizeLangArray(item && item.message)
  const descriptionItems = normalizeLangArray(item && item.description)
  const createdAt = item && item.create && item.create.datetime ? String(item.create.datetime) : ''
  const createdByName = accountDisplayName(item && item.create && item.create.by)
  const updatedAt = item && item.update && item.update.datetime ? String(item.update.datetime) : ''
  const updatedByName = accountDisplayName(item && item.update && item.update.by)
  return {
    _id: item && item._id ? String(item._id) : '',
    number: item && item.number != null ? Number(item.number) : 0,
    code: item && item.code != null ? Number(item.code) : 0,
    messageItems,
    descriptionItems,
    messageTh: langText(messageItems, 'th'),
    messageEn: langText(messageItems, 'en'),
    descriptionTh: langText(descriptionItems, 'th'),
    descriptionEn: langText(descriptionItems, 'en'),
    createdAt,
    createdByName,
    updatedAt,
    updatedByName
  }
}

function toSettingMessagePayload (payload) {
  return {
    _id: payload && payload._id ? payload._id : null,
    number: payload && payload.number != null ? Number(payload.number) : 0,
    code: payload && payload.code != null ? Number(payload.code) : 0,
    message: normalizeLangArray(payload && (payload.message || payload.messageItems))
      .filter(item => item.value && String(item.value).trim()),
    description: normalizeLangArray(payload && (payload.description || payload.descriptionItems))
      .filter(item => item.value && String(item.value).trim())
  }
}

function mapVerificationItem (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  const groupObj = item && item.group && typeof item.group === 'object' ? item.group : null
  const statusObj = item && item.status && typeof item.status === 'object' ? item.status : null
  const createdAt = item && item.create && item.create.datetime ? String(item.create.datetime) : ''
  const createdByName = accountDisplayName(item && item.create && item.create.by)
  const updatedAt = item && item.update && item.update.datetime ? String(item.update.datetime) : ''
  const updatedByName = accountDisplayName(item && item.update && item.update.by)
  return {
    _id: item && item._id ? String(item._id) : '',
    titleItems,
    descriptionItems,
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionTh: langText(descriptionItems, 'th'),
    descriptionEn: langText(descriptionItems, 'en'),
    groupId: groupObj && groupObj._id ? String(groupObj._id) : (item && item.group ? String(item.group) : ''),
    groupName: groupObj ? langText(groupObj.title) : '',
    statusId: statusObj && statusObj._id ? String(statusObj._id) : (item && item.status ? String(item.status) : ''),
    statusName: statusObj ? langText(statusObj.title) : '',
    createdAt,
    createdByName,
    updatedAt,
    updatedByName
  }
}

function toVerificationPayload (payload) {
  return {
    _id: payload && payload._id ? payload._id : null,
    title: normalizeLangArray(payload && (payload.title || payload.titleItems))
      .filter(item => item.value && String(item.value).trim()),
    description: normalizeLangArray(payload && (payload.description || payload.descriptionItems))
      .filter(item => item.value && String(item.value).trim()),
    group: payload && payload.groupId ? String(payload.groupId) : '',
    status: payload && payload.statusId ? String(payload.statusId) : ''
  }
}

function mapLifecycleAffiliationType (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  return {
    _id: item && item._id ? String(item._id) : '',
    key: item && item.key ? String(item.key) : '',
    titleItems,
    descriptionItems,
    titleText: langText(titleItems),
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionText: langText(descriptionItems),
    descriptionTh: langText(descriptionItems, 'th'),
    descriptionEn: langText(descriptionItems, 'en'),
    source: item && item.source ? String(item.source) : 'MANUAL',
    version: item && item.version != null ? Number(item.version) : 1,
    isSystem: !!(item && item.isSystem),
    state: !(item && item.state === false)
  }
}

function toLifecycleAffiliationTypePayload (payload) {
  return {
    _id: payload && payload._id ? payload._id : null,
    key: payload && payload.key ? String(payload.key).trim().toUpperCase() : '',
    title: normalizeLangArray(payload && (payload.title || payload.titleItems)).filter(item => item.value && String(item.value).trim()),
    description: normalizeLangArray(payload && (payload.description || payload.descriptionItems)).filter(item => item.value && String(item.value).trim()),
    source: payload && payload.source ? String(payload.source) : 'MANUAL',
    version: payload && payload.version != null ? Number(payload.version) : 1,
    isSystem: !!(payload && payload.isSystem),
    state: !(payload && payload.state === false)
  }
}

function mapLifecycleAccessProfile (item) {
  const mapped = mapLifecycleAffiliationType(item)
  return Object.assign({}, mapped, {
    defaultScope: item && item.defaultScope ? String(item.defaultScope) : 'self'
  })
}

function toLifecycleAccessProfilePayload (payload) {
  return Object.assign({}, toLifecycleAffiliationTypePayload(payload), {
    defaultScope: payload && payload.defaultScope ? String(payload.defaultScope).trim().toLowerCase() : 'self'
  })
}

function mapLifecyclePositionRule (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  const affiliations = Array.isArray(item && item.affiliationTypes) ? item.affiliationTypes.map(mapLifecycleAffiliationType) : []
  const accessProfiles = Array.isArray(item && item.accessProfiles) ? item.accessProfiles.map(mapLifecycleAccessProfile) : []
  return {
    _id: item && item._id ? String(item._id) : '',
    key: item && item.key ? String(item.key) : '',
    titleItems,
    descriptionItems,
    titleText: langText(titleItems),
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionText: langText(descriptionItems),
    matchType: item && item.matchType ? String(item.matchType) : 'CONTAINS',
    matchValues: Array.isArray(item && item.matchValues) ? item.matchValues.map(value => String(value)) : [],
    matchValuesText: Array.isArray(item && item.matchValues) ? item.matchValues.join(', ') : '',
    orgScope: item && item.orgScope ? String(item.orgScope) : 'unit',
    priority: item && item.priority != null ? Number(item.priority) : 100,
    affiliationTypes: affiliations,
    affiliationTypeIds: affiliations.map(entry => entry._id),
    affiliationLabels: affiliations.map(entry => entry.titleText || entry.key).join(', '),
    accessProfiles,
    accessProfileIds: accessProfiles.map(entry => entry._id),
    accessProfileLabels: accessProfiles.map(entry => entry.titleText || entry.key).join(', '),
    source: item && item.source ? String(item.source) : 'MANUAL',
    version: item && item.version != null ? Number(item.version) : 1,
    isSystem: !!(item && item.isSystem),
    state: !(item && item.state === false)
  }
}

function toLifecyclePositionRulePayload (payload) {
  return {
    _id: payload && payload._id ? payload._id : null,
    key: payload && payload.key ? String(payload.key).trim().toUpperCase() : '',
    title: normalizeLangArray(payload && (payload.title || payload.titleItems)).filter(item => item.value && String(item.value).trim()),
    description: normalizeLangArray(payload && (payload.description || payload.descriptionItems)).filter(item => item.value && String(item.value).trim()),
    affiliationTypes: Array.isArray(payload && (payload.affiliationTypes || payload.affiliationTypeIds)) ? (payload.affiliationTypes || payload.affiliationTypeIds).map(String).filter(Boolean) : [],
    matchType: payload && payload.matchType ? String(payload.matchType).trim().toUpperCase() : 'CONTAINS',
    matchValues: Array.isArray(payload && payload.matchValues)
      ? payload.matchValues.map(String).filter(Boolean)
      : String(payload && payload.matchValuesText || '').split(',').map(item => item.trim()).filter(Boolean),
    orgScope: payload && payload.orgScope ? String(payload.orgScope).trim().toLowerCase() : 'unit',
    accessProfiles: Array.isArray(payload && (payload.accessProfiles || payload.accessProfileIds)) ? (payload.accessProfiles || payload.accessProfileIds).map(String).filter(Boolean) : [],
    priority: payload && payload.priority != null ? Number(payload.priority) : 100,
    source: payload && payload.source ? String(payload.source) : 'MANUAL',
    version: payload && payload.version != null ? Number(payload.version) : 1,
    isSystem: !!(payload && payload.isSystem),
    state: !(payload && payload.state === false)
  }
}

function mapLifecycleProvisioningPolicy (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  const affiliationType = item && item.affiliationType && typeof item.affiliationType === 'object' ? mapLifecycleAffiliationType(item.affiliationType) : null
  const defaultAccessProfiles = Array.isArray(item && item.defaultAccessProfiles) ? item.defaultAccessProfiles.map(mapLifecycleAccessProfile) : []
  const defaultTargetStatus = item && item.defaultTargetStatus ? mapStatusItem(item.defaultTargetStatus) : null
  return {
    _id: item && item._id ? String(item._id) : '',
    key: item && item.key ? String(item.key) : '',
    titleItems,
    descriptionItems,
    titleText: langText(titleItems),
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionText: langText(descriptionItems),
    affiliationType,
    affiliationTypeId: affiliationType && affiliationType._id ? affiliationType._id : '',
    affiliationLabel: affiliationType ? (affiliationType.titleText || affiliationType.key) : '',
    defaultAccessProfiles,
    defaultAccessProfileIds: defaultAccessProfiles.map(entry => entry._id),
    defaultAccessProfileLabels: defaultAccessProfiles.map(entry => entry.titleText || entry.key).join(', '),
    defaultTargetStatus,
    defaultTargetStatusId: defaultTargetStatus && defaultTargetStatus._id ? defaultTargetStatus._id : '',
    defaultTargetStatusLabel: defaultTargetStatus ? (defaultTargetStatus.titleTh || defaultTargetStatus.titleEn || defaultTargetStatus.key) : '',
    autoProvision: !(item && item.autoProvision === false),
    autoDeprovision: !(item && item.autoDeprovision === false),
    revokeSessionsOnDeprovision: !(item && item.revokeSessionsOnDeprovision === false),
    source: item && item.source ? String(item.source) : 'MANUAL',
    version: item && item.version != null ? Number(item.version) : 1,
    isSystem: !!(item && item.isSystem),
    state: !(item && item.state === false)
  }
}

function mapHrMasterItem (item) {
  const titleItems = normalizeLangArray(item && item.title)
  const descriptionItems = normalizeLangArray(item && item.description)
  return {
    _id: item && item._id ? String(item._id) : '',
    key: item && item.key ? String(item.key) : '',
    code: item && item.code ? String(item.code) : '',
    title: titleItems,
    description: descriptionItems,
    titleItems,
    descriptionItems,
    titleText: item && item.titleText ? String(item.titleText) : langText(titleItems),
    descriptionText: item && item.descriptionText ? String(item.descriptionText) : langText(descriptionItems),
    titleTh: langText(titleItems, 'th'),
    titleEn: langText(titleItems, 'en'),
    descriptionTh: langText(descriptionItems, 'th'),
    descriptionEn: langText(descriptionItems, 'en'),
    source: item && item.source ? String(item.source) : '',
    isActive: !(item && item.isActive === false),
    orgGroupId: item && item.orgGroup && typeof item.orgGroup === 'object' && item.orgGroup._id ? String(item.orgGroup._id) : (item && item.orgGroup ? String(item.orgGroup) : ''),
    orgUnitId: item && item.orgUnit && typeof item.orgUnit === 'object' && item.orgUnit._id ? String(item.orgUnit._id) : (item && item.orgUnit ? String(item.orgUnit) : ''),
    orgGroupLabel: item && item.orgGroup && typeof item.orgGroup === 'object' ? (item.orgGroup.titleText || langText(item.orgGroup.title)) : '',
    orgUnitLabel: item && item.orgUnit && typeof item.orgUnit === 'object' ? (item.orgUnit.titleText || langText(item.orgUnit.title)) : ''
  }
}

function accountName (account) {
  if (!account || typeof account !== 'object') return ''
  const prefix = langText(account.userinfo && account.userinfo.prefix)
  const firstName = langText(account.userinfo && account.userinfo.firstName)
  const lastName = langText(account.userinfo && account.userinfo.lastName)
  return [prefix, firstName, lastName].filter(Boolean).join(' ').trim()
}

function mapHrPositionItem (item) {
  return {
    _id: item && item._id ? String(item._id) : '',
    positionCode: item && item.positionCode ? String(item.positionCode) : '',
    positionTitle: item && item.positionTitle ? String(item.positionTitle) : '',
    orgPathLabel: Array.isArray(item && item.orgPath) ? item.orgPath.join(' / ') : '',
    workLineLabel: item && item.workLine && item.workLine.titleText ? item.workLine.titleText : (item && item.workLineName ? String(item.workLineName) : ''),
    personnelTypeLabel: item && item.personnelType && item.personnelType.titleText ? item.personnelType.titleText : (item && item.personnelTypeName ? String(item.personnelTypeName) : ''),
    employmentStatusLabel: item && item.employmentStatusMaster && item.employmentStatusMaster.titleText ? item.employmentStatusMaster.titleText : (item && item.employmentStatusName ? String(item.employmentStatusName) : ''),
    isOpen: !!(item && item.isOpen)
  }
}

function mapHrWorkforceItem (item) {
  return {
    _id: item && item._id ? String(item._id) : '',
    key: item && item.key ? String(item.key) : '',
    workLineLabel: item && item.workLine && item.workLine.titleText ? item.workLine.titleText : (item && item.workLineName ? String(item.workLineName) : ''),
    personnelTypeLabel: item && item.personnelType && item.personnelType.titleText ? item.personnelType.titleText : (item && item.personnelTypeName ? String(item.personnelTypeName) : ''),
    orgGroupLabel: item && item.orgGroup && item.orgGroup.titleText ? item.orgGroup.titleText : (item && item.orgGroupName ? String(item.orgGroupName) : ''),
    employmentStatusLabel: item && item.employmentStatusMaster && item.employmentStatusMaster.titleText ? item.employmentStatusMaster.titleText : (item && item.employmentStatus ? String(item.employmentStatus) : ''),
    source: item && item.source ? String(item.source) : '',
    isActive: !(item && item.isActive === false)
  }
}

function mapHrIdentityItem (item) {
  return {
    _id: item && item._id ? String(item._id) : '',
    personnelCode: item && item.personnelCode ? String(item.personnelCode) : '',
    fullName: item && item.fullName ? String(item.fullName) : '',
    positionTitle: item && item.positionTitle ? String(item.positionTitle) : '',
    orgPathLabel: Array.isArray(item && item.orgPath) ? item.orgPath.join(' / ') : '',
    employmentStatusLabel: item && item.employmentStatusMaster && item.employmentStatusMaster.titleText ? item.employmentStatusMaster.titleText : (item && item.employmentStatusName ? String(item.employmentStatusName) : ''),
    linkedAccountId: item && item.linkedAccount && item.linkedAccount._id ? String(item.linkedAccount._id) : '',
    linkedAccountCode: item && item.linkedAccount && item.linkedAccount.code ? String(item.linkedAccount.code) : '',
    linkedAccountName: accountName(item && item.linkedAccount),
    vacancy: !!(item && item.vacancy)
  }
}

function mapHrSyncRunItem (item) {
  const sourceFile = item && item.sourceFile ? String(item.sourceFile) : ''
  const sourceSheet = item && item.sourceSheet ? String(item.sourceSheet) : ''
  const createdAt = item && item.createdAt ? String(item.createdAt) : ''
  return {
    _id: item && item._id ? String(item._id) : '',
    sourceFile,
    sourceSheet,
    status: item && item.status ? String(item.status) : '',
    rowCount: item && item.rowCount != null ? Number(item.rowCount) : 0,
    matchedAccountCount: item && item.matchedAccountCount != null ? Number(item.matchedAccountCount) : 0,
    createdAccountCount: item && item.createdAccountCount != null ? Number(item.createdAccountCount) : 0,
    updatedAccountCount: item && item.updatedAccountCount != null ? Number(item.updatedAccountCount) : 0,
    unmatchedAccountCount: item && item.unmatchedAccountCount != null ? Number(item.unmatchedAccountCount) : 0,
    createdAt,
    createdAtLabel: createdAt ? formatDateTime24(createdAt) : '-',
    sourceFileLabel: [sourceFile.split('/').filter(Boolean).pop() || sourceFile, sourceSheet].filter(Boolean).join(' | ') || '-',
    warnings: Array.isArray(item && item.warnings) ? item.warnings : []
  }
}

function toHrMasterPayload (payload) {
  return {
    _id: payload && payload._id ? String(payload._id) : null,
    key: payload && payload.key ? String(payload.key).trim() : '',
    code: payload && payload.code ? String(payload.code).trim() : '',
    title: normalizeLangArray(payload && (payload.title || payload.titleItems)).filter(item => item.value && String(item.value).trim()),
    description: normalizeLangArray(payload && (payload.description || payload.descriptionItems)).filter(item => item.value && String(item.value).trim()),
    source: payload && payload.source ? String(payload.source) : 'MANUAL',
    isActive: !(payload && payload.isActive === false),
    orgGroupId: payload && (payload.orgGroupId || payload.orgGroup) ? String(payload.orgGroupId || payload.orgGroup) : '',
    orgUnitId: payload && (payload.orgUnitId || payload.orgUnit) ? String(payload.orgUnitId || payload.orgUnit) : '',
    orgGroupKey: payload && payload.orgGroupKey ? String(payload.orgGroupKey) : '',
    orgUnitKey: payload && payload.orgUnitKey ? String(payload.orgUnitKey) : ''
  }
}

function toLifecycleProvisioningPolicyPayload (payload) {
  return {
    _id: payload && payload._id ? payload._id : null,
    key: payload && payload.key ? String(payload.key).trim().toUpperCase() : '',
    title: normalizeLangArray(payload && (payload.title || payload.titleItems)).filter(item => item.value && String(item.value).trim()),
    description: normalizeLangArray(payload && (payload.description || payload.descriptionItems)).filter(item => item.value && String(item.value).trim()),
    affiliationType: payload && (payload.affiliationType || payload.affiliationTypeId) ? String(payload.affiliationType || payload.affiliationTypeId) : '',
    defaultAccessProfiles: Array.isArray(payload && (payload.defaultAccessProfiles || payload.defaultAccessProfileIds)) ? (payload.defaultAccessProfiles || payload.defaultAccessProfileIds).map(String).filter(Boolean) : [],
    defaultTargetStatus: payload && (payload.defaultTargetStatus || payload.defaultTargetStatusId) ? String(payload.defaultTargetStatus || payload.defaultTargetStatusId) : '',
    autoProvision: !(payload && payload.autoProvision === false),
    autoDeprovision: !(payload && payload.autoDeprovision === false),
    revokeSessionsOnDeprovision: !(payload && payload.revokeSessionsOnDeprovision === false),
    source: payload && payload.source ? String(payload.source) : 'MANUAL',
    version: payload && payload.version != null ? Number(payload.version) : 1,
    isSystem: !!(payload && payload.isSystem),
    state: !(payload && payload.state === false)
  }
}

function buildStatusCatalog (items) {
  const catalog = { active: '', inactive: '', draft: '' }
  ;(items || []).forEach(item => {
    const key = item && item.key ? String(item.key).toLowerCase() : ''
    const id = item && item._id ? String(item._id) : ''
    if (!id) return
    if (!catalog.draft && key.includes('draft')) {
      catalog.draft = id
      return
    }
    if (!catalog.inactive && item && item.state === false) {
      catalog.inactive = id
      return
    }
    if (!catalog.active && item && item.state !== false) {
      catalog.active = id
    }
  })
  return catalog
}

function accountDisplayName (account) {
  if (!account || typeof account !== 'object') return ''
  const prefix = langText(account.userinfo && account.userinfo.prefix)
  const firstName = langText(account.userinfo && account.userinfo.firstName)
  const lastName = langText(account.userinfo && account.userinfo.lastName)
  const fullName = [prefix, firstName, lastName].filter(Boolean).join(' ').trim()
  if (fullName) return fullName
  if (account.code) return String(account.code)
  if (account.email) return String(account.email)
  return ''
}

const settingStatus = {
  namespaced: true,
  state: {
    items: [],
    groups: []
  },
  mutations: {
    items (state, value) {
      state.items = Array.isArray(value) ? value : []
    },
    groups (state, value) {
      state.groups = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const [groupsRes, statusRes] = await Promise.all([
        Service.settings('groups', {}),
        Service.settings('status', {})
      ])
      const groups = (groupsRes && groupsRes.data && groupsRes.data.data) || []
      const statuses = (statusRes && statusRes.data && statusRes.data.data) || []
      commit('groups', groups.map(mapGroup))
      commit('items', statuses.map(mapStatusItem))
      return true
    },
    toDraft (_, item) {
      return Promise.resolve({
        _id: item && item._id ? String(item._id) : null,
        groupId: item && item.groupId ? String(item.groupId) : '',
        key: item && item.key ? String(item.key) : '',
        titleItems: normalizeLangArray(item && item.titleItems),
        descriptionItems: normalizeLangArray(item && item.descriptionItems),
        state: !(item && item.state === false),
        createdAt: item && item.createdAt ? String(item.createdAt) : '',
        createdByName: item && item.createdByName ? String(item.createdByName) : '',
        updatedAt: item && item.updatedAt ? String(item.updatedAt) : '',
        updatedByName: item && item.updatedByName ? String(item.updatedByName) : ''
      })
    },
    async create ({ dispatch }, payload) {
      const normalized = toStatusPayload(payload)
      if (!normalized.group || !normalized.key) {
        throw new Error('invalid_payload')
      }
      await Service.settings('create-status', {
        group: normalized.group,
        key: normalized.key,
        title: normalized.title,
        description: normalized.description,
        state: normalized.state
      })
      await dispatch('explorer')
      return true
    },
    async update ({ dispatch }, payload) {
      const normalized = toStatusPayload(payload)
      if (!normalized._id || !normalized.group || !normalized.key) {
        throw new Error('invalid_payload')
      }
      await Service.settings('update-status', {
        _id: normalized._id,
        group: normalized.group,
        key: normalized.key,
        title: normalized.title,
        description: normalized.description,
        state: normalized.state
      })
      await dispatch('explorer')
      return true
    },
    async remove ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-status', { id })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    items (state) {
      return state.items
    },
    groups (state) {
      return state.groups
    }
  }
}

const settingGroup = {
  namespaced: true,
  state: {
    items: []
  },
  mutations: {
    items (state, value) {
      state.items = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const response = await Service.settings('groups', {})
      const groups = (response && response.data && response.data.data) || []
      commit('items', groups.map(mapGroup))
      return true
    },
    toDraft (_, item) {
      return Promise.resolve({
        _id: item && item._id ? String(item._id) : null,
        key: item && item.key ? String(item.key) : '',
        titleItems: normalizeLangArray(item && item.titleItems),
        descriptionItems: normalizeLangArray(item && item.descriptionItems),
        state: !(item && item.state === false),
        createdAt: item && item.createdAt ? String(item.createdAt) : '',
        createdByName: item && item.createdByName ? String(item.createdByName) : '',
        updatedAt: item && item.updatedAt ? String(item.updatedAt) : '',
        updatedByName: item && item.updatedByName ? String(item.updatedByName) : ''
      })
    },
    async create ({ dispatch }, payload) {
      const normalized = toGroupPayload(payload)
      if (!normalized.title.length) {
        throw new Error('invalid_payload')
      }
      await Service.settings('create-group', {
        key: normalized.key,
        title: normalized.title,
        description: normalized.description,
        state: normalized.state
      })
      await dispatch('explorer')
      return true
    },
    async update ({ dispatch }, payload) {
      const normalized = toGroupPayload(payload)
      if (!normalized._id || !normalized.title.length) {
        throw new Error('invalid_payload')
      }
      await Service.settings('update-group', {
        _id: normalized._id,
        key: normalized.key,
        title: normalized.title,
        description: normalized.description,
        state: normalized.state
      })
      await dispatch('explorer')
      return true
    },
    async remove ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-group', { id })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    items (state) {
      return state.items
    }
  }
}

const settingMessageAuthen = {
  namespaced: true,
  state: {
    items: [],
    statusCatalog: { active: '', inactive: '', draft: '' }
  },
  mutations: {
    items (state, value) {
      state.items = Array.isArray(value) ? value : []
    },
    statusCatalog (state, value) {
      state.statusCatalog = Object.assign({ active: '', inactive: '', draft: '' }, value || {})
    }
  },
  actions: {
    async ensureStatusCatalog ({ state, commit }) {
      if (state.statusCatalog.active || state.statusCatalog.inactive || state.statusCatalog.draft) {
        return state.statusCatalog
      }
      const statusRes = await Service.settings('status', {})
      const statuses = (statusRes && statusRes.data && statusRes.data.data) || []
      const catalog = buildStatusCatalog(statuses)
      commit('statusCatalog', catalog)
      return catalog
    },
    async explorer ({ commit, dispatch }) {
      await dispatch('ensureStatusCatalog')
      const response = await Service.authenticated('message', {}, {})
      const items = (response && response.data && response.data.data) || []
      commit('items', items.map(mapAuthMessageItem))
      return true
    },
    toDraft (_, item) {
      return Promise.resolve({
        _id: item && item._id ? String(item._id) : null,
        titleItems: normalizeLangArray(item && item.titleItems),
        descriptionItems: normalizeLangArray(item && item.descriptionItems),
        startDate: item && item.startDate ? String(item.startDate) : '',
        endDate: item && item.endDate ? String(item.endDate) : '',
        showOnLogin: !!(item && item.showOnLogin),
        statusOption: item && item.statusOption ? String(item.statusOption) : 'active',
        createdAt: item && item.createdAt ? String(item.createdAt) : '',
        createdByName: item && item.createdByName ? String(item.createdByName) : '',
        updatedAt: item && item.updatedAt ? String(item.updatedAt) : '',
        updatedByName: item && item.updatedByName ? String(item.updatedByName) : ''
      })
    },
    async create ({ dispatch }, payload) {
      const catalog = await dispatch('ensureStatusCatalog')
      const statusOption = payload && payload.statusOption ? String(payload.statusOption) : 'active'
      const statusId = catalog[statusOption] || catalog.active || ''
      await Service.authenticated('create-message', {
        title: normalizeLangArray(payload && payload.titleItems),
        description: normalizeLangArray(payload && payload.descriptionItems),
        startDate: payload && payload.startDate ? payload.startDate : null,
        endDate: payload && payload.endDate ? payload.endDate : null,
        status: statusId || undefined
      }, {})
      await dispatch('explorer')
      return true
    },
    async update ({ dispatch }, payload) {
      const catalog = await dispatch('ensureStatusCatalog')
      const statusOption = payload && payload.statusOption ? String(payload.statusOption) : 'active'
      const statusId = catalog[statusOption] || catalog.active || ''
      await Service.authenticated('update-message', {
        _id: payload && payload._id ? payload._id : '',
        title: normalizeLangArray(payload && payload.titleItems),
        description: normalizeLangArray(payload && payload.descriptionItems),
        startDate: payload && payload.startDate ? payload.startDate : null,
        endDate: payload && payload.endDate ? payload.endDate : null,
        status: statusId || undefined
      }, {})
      await dispatch('explorer')
      return true
    },
    async remove ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.authenticated('remove-message', { id }, {})
      await dispatch('explorer')
      return true
    },
    async toggle ({ dispatch }, item) {
      const nextOption = item && item.isActive ? 'inactive' : 'active'
      await dispatch('update', {
        _id: item && item._id ? item._id : '',
        titleItems: normalizeLangArray(item && item.titleItems),
        descriptionItems: normalizeLangArray(item && item.descriptionItems),
        startDate: item && item.startDate ? item.startDate : null,
        endDate: item && item.endDate ? item.endDate : null,
        showOnLogin: nextOption === 'active',
        statusOption: nextOption
      })
      return true
    }
  },
  getters: {
    items (state) {
      return state.items
    }
  }
}

const settingMessage = {
  namespaced: true,
  state: {
    items: []
  },
  mutations: {
    items (state, value) {
      state.items = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const response = await Service.settings('messages', {})
      const items = (response && response.data && response.data.data) || []
      commit('items', items.map(mapSettingMessageItem))
      return true
    },
    toDraft (_, item) {
      return Promise.resolve({
        _id: item && item._id ? String(item._id) : null,
        number: item && item.number != null ? Number(item.number) : 0,
        code: item && item.code != null ? Number(item.code) : 0,
        messageItems: normalizeLangArray(item && item.messageItems),
        descriptionItems: normalizeLangArray(item && item.descriptionItems),
        createdAt: item && item.createdAt ? String(item.createdAt) : '',
        createdByName: item && item.createdByName ? String(item.createdByName) : '',
        updatedAt: item && item.updatedAt ? String(item.updatedAt) : '',
        updatedByName: item && item.updatedByName ? String(item.updatedByName) : ''
      })
    },
    async create ({ dispatch }, payload) {
      const normalized = toSettingMessagePayload(payload)
      if (!normalized.number || !normalized.code || !normalized.message.length) throw new Error('invalid_payload')
      await Service.settings('create-setting-message', normalized)
      await dispatch('explorer')
      return true
    },
    async update ({ dispatch }, payload) {
      const normalized = toSettingMessagePayload(payload)
      if (!normalized._id || !normalized.number || !normalized.code || !normalized.message.length) throw new Error('invalid_payload')
      await Service.settings('update-setting-message', normalized)
      await dispatch('explorer')
      return true
    },
    async remove ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-setting-message', { id })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    items (state) {
      return state.items
    }
  }
}

const settingVerification = {
  namespaced: true,
  state: {
    items: [],
    groups: [],
    statuses: []
  },
  mutations: {
    items (state, value) {
      state.items = Array.isArray(value) ? value : []
    },
    groups (state, value) {
      state.groups = Array.isArray(value) ? value : []
    },
    statuses (state, value) {
      state.statuses = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const [verificationRes, groupRes, statusRes] = await Promise.all([
        Service.settings('verification', {}),
        Service.settings('groups', {}),
        Service.settings('status', {})
      ])
      const items = (verificationRes && verificationRes.data && verificationRes.data.data) || []
      const groups = (groupRes && groupRes.data && groupRes.data.data) || []
      const statuses = (statusRes && statusRes.data && statusRes.data.data) || []
      commit('items', items.map(mapVerificationItem))
      commit('groups', groups.map(mapGroup))
      commit('statuses', statuses.map(mapStatusItem))
      return true
    },
    toDraft (_, item) {
      return Promise.resolve({
        _id: item && item._id ? String(item._id) : null,
        titleItems: normalizeLangArray(item && item.titleItems),
        descriptionItems: normalizeLangArray(item && item.descriptionItems),
        groupId: item && item.groupId ? String(item.groupId) : '',
        statusId: item && item.statusId ? String(item.statusId) : '',
        createdAt: item && item.createdAt ? String(item.createdAt) : '',
        createdByName: item && item.createdByName ? String(item.createdByName) : '',
        updatedAt: item && item.updatedAt ? String(item.updatedAt) : '',
        updatedByName: item && item.updatedByName ? String(item.updatedByName) : ''
      })
    },
    async create ({ dispatch }, payload) {
      const normalized = toVerificationPayload(payload)
      if (!normalized.title.length || !normalized.group || !normalized.status) throw new Error('invalid_payload')
      await Service.settings('create-verification', normalized)
      await dispatch('explorer')
      return true
    },
    async update ({ dispatch }, payload) {
      const normalized = toVerificationPayload(payload)
      if (!normalized._id || !normalized.title.length || !normalized.group || !normalized.status) throw new Error('invalid_payload')
      await Service.settings('update-verification', normalized)
      await dispatch('explorer')
      return true
    },
    async remove ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-verification', { id })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    items (state) {
      return state.items
    },
    groups (state) {
      return state.groups
    },
    statuses (state) {
      return state.statuses
    }
  }
}

const lifecycleMaster = {
  namespaced: true,
  state: {
    options: {
      affiliationTypes: [],
      accessProfiles: [],
      positionRules: [],
      provisioningPolicies: [],
      accountStatuses: [],
      matchTypes: [],
      orgScopes: []
    },
    affiliationTypes: [],
    accessProfiles: [],
    positionRules: [],
    provisioningPolicies: []
  },
  mutations: {
    options (state, value) {
      state.options = Object.assign({
        affiliationTypes: [],
        accessProfiles: [],
        positionRules: [],
        provisioningPolicies: [],
        accountStatuses: [],
        matchTypes: [],
        orgScopes: []
      }, value || {})
    },
    affiliationTypes (state, value) {
      state.affiliationTypes = Array.isArray(value) ? value : []
    },
    accessProfiles (state, value) {
      state.accessProfiles = Array.isArray(value) ? value : []
    },
    positionRules (state, value) {
      state.positionRules = Array.isArray(value) ? value : []
    },
    provisioningPolicies (state, value) {
      state.provisioningPolicies = Array.isArray(value) ? value : []
    }
  },
  actions: {
    async explorer ({ commit }) {
      const [optionsRes, affiliationRes, accessRes, ruleRes, policyRes] = await Promise.all([
        Service.settings('lifecycle-options', {}),
        Service.settings('lifecycle-affiliation-types', {}),
        Service.settings('lifecycle-access-profiles', {}),
        Service.settings('lifecycle-position-rules', {}),
        Service.settings('lifecycle-provisioning-policies', {})
      ])
      const options = optionsRes && optionsRes.data && optionsRes.data.data ? optionsRes.data.data : {}
      commit('options', {
        affiliationTypes: Array.isArray(options.affiliationTypes) ? options.affiliationTypes.map(mapLifecycleAffiliationType) : [],
        accessProfiles: Array.isArray(options.accessProfiles) ? options.accessProfiles.map(mapLifecycleAccessProfile) : [],
        positionRules: Array.isArray(options.positionRules) ? options.positionRules.map(mapLifecyclePositionRule) : [],
        provisioningPolicies: Array.isArray(options.provisioningPolicies) ? options.provisioningPolicies.map(mapLifecycleProvisioningPolicy) : [],
        accountStatuses: Array.isArray(options.accountStatuses) ? options.accountStatuses.map(mapStatusItem) : [],
        matchTypes: Array.isArray(options.matchTypes) ? options.matchTypes.map(String) : [],
        orgScopes: Array.isArray(options.orgScopes) ? options.orgScopes.map(String) : []
      })
      commit('affiliationTypes', ((affiliationRes && affiliationRes.data && affiliationRes.data.data) || []).map(mapLifecycleAffiliationType))
      commit('accessProfiles', ((accessRes && accessRes.data && accessRes.data.data) || []).map(mapLifecycleAccessProfile))
      commit('positionRules', ((ruleRes && ruleRes.data && ruleRes.data.data) || []).map(mapLifecyclePositionRule))
      commit('provisioningPolicies', ((policyRes && policyRes.data && policyRes.data.data) || []).map(mapLifecycleProvisioningPolicy))
      return true
    },
    toDraft (_, payload) {
      return Promise.resolve(Object.assign({}, payload || {}))
    },
    async createAffiliationType ({ dispatch }, payload) {
      const normalized = toLifecycleAffiliationTypePayload(payload)
      if (!normalized.key || !normalized.title.length) throw new Error('invalid_payload')
      await Service.settings('create-lifecycle-affiliation-type', normalized)
      await dispatch('explorer')
      return true
    },
    async updateAffiliationType ({ dispatch }, payload) {
      const normalized = toLifecycleAffiliationTypePayload(payload)
      if (!normalized._id || !normalized.key || !normalized.title.length) throw new Error('invalid_payload')
      await Service.settings('update-lifecycle-affiliation-type', normalized)
      await dispatch('explorer')
      return true
    },
    async removeAffiliationType ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-lifecycle-affiliation-type', { id })
      await dispatch('explorer')
      return true
    },
    async createAccessProfile ({ dispatch }, payload) {
      const normalized = toLifecycleAccessProfilePayload(payload)
      if (!normalized.key || !normalized.title.length) throw new Error('invalid_payload')
      await Service.settings('create-lifecycle-access-profile', normalized)
      await dispatch('explorer')
      return true
    },
    async updateAccessProfile ({ dispatch }, payload) {
      const normalized = toLifecycleAccessProfilePayload(payload)
      if (!normalized._id || !normalized.key || !normalized.title.length) throw new Error('invalid_payload')
      await Service.settings('update-lifecycle-access-profile', normalized)
      await dispatch('explorer')
      return true
    },
    async removeAccessProfile ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-lifecycle-access-profile', { id })
      await dispatch('explorer')
      return true
    },
    async createPositionRule ({ dispatch }, payload) {
      const normalized = toLifecyclePositionRulePayload(payload)
      if (!normalized.key || !normalized.affiliationTypes.length || !normalized.accessProfiles.length || !normalized.matchValues.length) throw new Error('invalid_payload')
      await Service.settings('create-lifecycle-position-rule', normalized)
      await dispatch('explorer')
      return true
    },
    async updatePositionRule ({ dispatch }, payload) {
      const normalized = toLifecyclePositionRulePayload(payload)
      if (!normalized._id || !normalized.key || !normalized.affiliationTypes.length || !normalized.accessProfiles.length || !normalized.matchValues.length) throw new Error('invalid_payload')
      await Service.settings('update-lifecycle-position-rule', normalized)
      await dispatch('explorer')
      return true
    },
    async removePositionRule ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-lifecycle-position-rule', { id })
      await dispatch('explorer')
      return true
    },
    async createProvisioningPolicy ({ dispatch }, payload) {
      const normalized = toLifecycleProvisioningPolicyPayload(payload)
      if (!normalized.key || !normalized.affiliationType || !normalized.defaultAccessProfiles.length || !normalized.defaultTargetStatus) throw new Error('invalid_payload')
      await Service.settings('create-lifecycle-provisioning-policy', normalized)
      await dispatch('explorer')
      return true
    },
    async updateProvisioningPolicy ({ dispatch }, payload) {
      const normalized = toLifecycleProvisioningPolicyPayload(payload)
      if (!normalized._id || !normalized.key || !normalized.affiliationType || !normalized.defaultAccessProfiles.length || !normalized.defaultTargetStatus) throw new Error('invalid_payload')
      await Service.settings('update-lifecycle-provisioning-policy', normalized)
      await dispatch('explorer')
      return true
    },
    async removeProvisioningPolicy ({ dispatch }, item) {
      const id = item && item._id ? String(item._id) : ''
      if (!id) throw new Error('invalid_id')
      await Service.settings('delete-lifecycle-provisioning-policy', { id })
      await dispatch('explorer')
      return true
    }
  },
  getters: {
    options: state => state.options,
    affiliationTypes: state => state.affiliationTypes,
    accessProfiles: state => state.accessProfiles,
    positionRules: state => state.positionRules,
    provisioningPolicies: state => state.provisioningPolicies,
    accountStatuses: state => state.options.accountStatuses || [],
    matchTypes: state => state.options.matchTypes || [],
    orgScopes: state => state.options.orgScopes || []
  }
}

const hrMaster = {
  namespaced: true,
  state: {
    overview: {},
    orgGroups: [],
    orgUnits: [],
    subUnits: [],
    degreeLevels: [],
    employmentStatuses: [],
    workLines: [],
    personnelTypes: [],
    academicRanks: [],
    positionTitles: [],
    positions: [],
    workforce: [],
    identities: [],
    syncRuns: []
  },
  mutations: {
    overview (state, value) {
      state.overview = value || {}
    },
    orgGroups (state, value) { state.orgGroups = Array.isArray(value) ? value : [] },
    orgUnits (state, value) { state.orgUnits = Array.isArray(value) ? value : [] },
    subUnits (state, value) { state.subUnits = Array.isArray(value) ? value : [] },
    degreeLevels (state, value) { state.degreeLevels = Array.isArray(value) ? value : [] },
    employmentStatuses (state, value) { state.employmentStatuses = Array.isArray(value) ? value : [] },
    workLines (state, value) { state.workLines = Array.isArray(value) ? value : [] },
    personnelTypes (state, value) { state.personnelTypes = Array.isArray(value) ? value : [] },
    academicRanks (state, value) { state.academicRanks = Array.isArray(value) ? value : [] },
    positionTitles (state, value) { state.positionTitles = Array.isArray(value) ? value : [] },
    positions (state, value) { state.positions = Array.isArray(value) ? value : [] },
    workforce (state, value) { state.workforce = Array.isArray(value) ? value : [] },
    identities (state, value) { state.identities = Array.isArray(value) ? value : [] },
    syncRuns (state, value) { state.syncRuns = Array.isArray(value) ? value : [] }
  },
  actions: {
    async explorer ({ commit }) {
      const [
        overviewRes,
        orgGroupRes,
        orgUnitRes,
        subUnitRes,
        degreeRes,
        employmentRes,
        workLineRes,
        personnelTypeRes,
        academicRankRes,
        positionTitleRes,
        positionRes,
        workforceRes,
        identityRes,
        syncRunRes
      ] = await Promise.all([
        Service.settings('hr-overview', {}),
        Service.settings('hr-org-groups', {}),
        Service.settings('hr-org-unit-masters', {}),
        Service.settings('hr-sub-units', {}),
        Service.settings('hr-degree-levels', {}),
        Service.settings('hr-employment-statuses', {}),
        Service.settings('hr-work-lines', {}),
        Service.settings('hr-personnel-types', {}),
        Service.settings('hr-academic-ranks', {}),
        Service.settings('hr-position-titles', {}),
        Service.settings('hr-positions', {}),
        Service.settings('hr-workforce', {}),
        Service.settings('hr-identities', {}),
        Service.settings('hr-sync-runs', {})
      ])
      commit('overview', overviewRes && overviewRes.data && overviewRes.data.data ? overviewRes.data.data : {})
      commit('orgGroups', ((orgGroupRes && orgGroupRes.data && orgGroupRes.data.data) || []).map(mapHrMasterItem))
      commit('orgUnits', ((orgUnitRes && orgUnitRes.data && orgUnitRes.data.data) || []).map(mapHrMasterItem))
      commit('subUnits', ((subUnitRes && subUnitRes.data && subUnitRes.data.data) || []).map(mapHrMasterItem))
      commit('degreeLevels', ((degreeRes && degreeRes.data && degreeRes.data.data) || []).map(mapHrMasterItem))
      commit('employmentStatuses', ((employmentRes && employmentRes.data && employmentRes.data.data) || []).map(mapHrMasterItem))
      commit('workLines', ((workLineRes && workLineRes.data && workLineRes.data.data) || []).map(mapHrMasterItem))
      commit('personnelTypes', ((personnelTypeRes && personnelTypeRes.data && personnelTypeRes.data.data) || []).map(mapHrMasterItem))
      commit('academicRanks', ((academicRankRes && academicRankRes.data && academicRankRes.data.data) || []).map(mapHrMasterItem))
      commit('positionTitles', ((positionTitleRes && positionTitleRes.data && positionTitleRes.data.data) || []).map(mapHrMasterItem))
      commit('positions', ((positionRes && positionRes.data && positionRes.data.data) || []).map(mapHrPositionItem))
      commit('workforce', ((workforceRes && workforceRes.data && workforceRes.data.data) || []).map(mapHrWorkforceItem))
      commit('identities', ((identityRes && identityRes.data && identityRes.data.data) || []).map(mapHrIdentityItem))
      commit('syncRuns', ((syncRunRes && syncRunRes.data && syncRunRes.data.data) || []).map(mapHrSyncRunItem))
      return true
    },
    async createMaster ({ dispatch }, { type, payload }) {
      const normalized = toHrMasterPayload(payload)
      const methodMap = {
        orgGroups: 'create-hr-org-group',
        orgUnits: 'create-hr-org-unit-master',
        subUnits: 'create-hr-sub-unit',
        degreeLevels: 'create-hr-degree-level',
        employmentStatuses: 'create-hr-employment-status',
        workLines: 'create-hr-work-line',
        personnelTypes: 'create-hr-personnel-type',
        academicRanks: 'create-hr-academic-rank',
        positionTitles: 'create-hr-position-title'
      }
      const method = methodMap[type]
      if (!method) throw new Error('invalid_hr_master_type')
      await Service.settings(method, normalized)
      await dispatch('explorer')
      return true
    },
    async updateMaster ({ dispatch }, { type, payload }) {
      const normalized = toHrMasterPayload(payload)
      const methodMap = {
        orgGroups: 'update-hr-org-group',
        orgUnits: 'update-hr-org-unit-master',
        subUnits: 'update-hr-sub-unit',
        degreeLevels: 'update-hr-degree-level',
        employmentStatuses: 'update-hr-employment-status',
        workLines: 'update-hr-work-line',
        personnelTypes: 'update-hr-personnel-type',
        academicRanks: 'update-hr-academic-rank',
        positionTitles: 'update-hr-position-title'
      }
      const method = methodMap[type]
      if (!method) throw new Error('invalid_hr_master_type')
      await Service.settings(method, normalized)
      await dispatch('explorer')
      return true
    },
    async removeMaster ({ dispatch }, { type, id }) {
      const methodMap = {
        orgGroups: 'delete-hr-org-group',
        orgUnits: 'delete-hr-org-unit-master',
        subUnits: 'delete-hr-sub-unit',
        degreeLevels: 'delete-hr-degree-level',
        employmentStatuses: 'delete-hr-employment-status',
        workLines: 'delete-hr-work-line',
        personnelTypes: 'delete-hr-personnel-type',
        academicRanks: 'delete-hr-academic-rank',
        positionTitles: 'delete-hr-position-title'
      }
      const method = methodMap[type]
      if (!method) throw new Error('invalid_hr_master_type')
      await Service.settings(method, { id })
      await dispatch('explorer')
      return true
    },
    async linkIdentityAccount ({ dispatch }, payload) {
      await Service.settings('link-hr-identity-account', payload)
      await dispatch('explorer')
      return true
    },
    async previewSync (context, payload) {
      const response = await Service.settings('hr-sync-preview', payload)
      return response && response.data ? response.data.data : {}
    },
    async runSync ({ dispatch }, payload) {
      const response = await Service.settings('hr-sync-run', payload)
      await dispatch('explorer')
      return response && response.data ? response.data.data : {}
    }
  },
  getters: {
    overview: state => state.overview,
    orgGroups: state => state.orgGroups,
    orgUnits: state => state.orgUnits,
    subUnits: state => state.subUnits,
    degreeLevels: state => state.degreeLevels,
    employmentStatuses: state => state.employmentStatuses,
    workLines: state => state.workLines,
    personnelTypes: state => state.personnelTypes,
    academicRanks: state => state.academicRanks,
    positionTitles: state => state.positionTitles,
    positions: state => state.positions,
    workforce: state => state.workforce,
    identities: state => state.identities,
    syncRuns: state => state.syncRuns
  }
}

const module = {
  namespaced: true,
  state: {
    lang: initialLang
  },
  mutations: {
    lang (state, obj) {
      const lang = normalizeLang(obj)
      state.lang = lang
      persistLang(lang)
      if (i18n && i18n.locale !== lang) {
        i18n.locale = lang
      }
    }
  },
  actions: {},
  getters: {
    lang (state) {
      return state.lang;
    }
  },
  modules: {
    settingMessage,
    settingVerification,
    settingGroup,
    settingStatus,
    settingMessageAuthen,
    lifecycleMaster,
    hrMaster
  }
};

export default module;
