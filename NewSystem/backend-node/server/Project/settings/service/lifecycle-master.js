'use strict';

const mongo = require('mongodb');
const AffiliationType = require('../controller/lifecycle_affiliation_type');
const AccessProfile = require('../controller/lifecycle_access_profile');
const PositionRule = require('../controller/lifecycle_position_rule');
const ProvisioningPolicy = require('../controller/lifecycle_provisioning_policy');
const {
    ensureAccountStatusMasterData,
    sanitizeStatus,
    toObjectId
} = require('../../accounts/service/account-status');

const MATCH_TYPES = ['EXACT', 'CONTAINS'];

const SEED_AFFILIATIONS = [
    { key: 'ACADEMIC', title: { th: 'สายวิชาการ', en: 'Academic Staff' }, description: { th: 'บุคลากรสายวิชาการ', en: 'Academic workforce affiliation' } },
    { key: 'OPERATIONAL', title: { th: 'สายปฏิบัติการ', en: 'Operational Staff' }, description: { th: 'บุคลากรสายปฏิบัติการ', en: 'Operational workforce affiliation' } },
    { key: 'EXECUTIVE', title: { th: 'สายบริหาร', en: 'Executive' }, description: { th: 'ผู้บริหารมหาวิทยาลัย', en: 'Executive affiliation' } },
    { key: 'STUDENT', title: { th: 'นักศึกษา', en: 'Student' }, description: { th: 'ผู้เรียนในมหาวิทยาลัย', en: 'Student affiliation' } },
    { key: 'CONTRACTOR', title: { th: 'ผู้รับจ้าง', en: 'Contractor' }, description: { th: 'บุคคลภายนอกตามสัญญา', en: 'Contractor affiliation' } },
    { key: 'ALUMNI', title: { th: 'ศิษย์เก่า', en: 'Alumni' }, description: { th: 'ผู้สำเร็จการศึกษา', en: 'Alumni affiliation' } },
    { key: 'EXTERNAL', title: { th: 'บุคคลภายนอก', en: 'External Party' }, description: { th: 'บุคคลภายนอกหรือผู้ประเมิน', en: 'External affiliation' } }
];

const SEED_ACCESS_PROFILES = [
    { key: 'EMAIL', defaultScope: 'self', title: { th: 'อีเมลองค์กร', en: 'Institutional Email' } },
    { key: 'SSO', defaultScope: 'self', title: { th: 'เข้าสู่ระบบกลาง', en: 'Single Sign-On' } },
    { key: 'LMS_STAFF', defaultScope: 'faculty', title: { th: 'ระบบการเรียนการสอนสำหรับบุคลากร', en: 'LMS Staff' } },
    { key: 'LMS_STUDENT', defaultScope: 'program', title: { th: 'ระบบการเรียนการสอนสำหรับนักศึกษา', en: 'LMS Student' } },
    { key: 'RESEARCH_PORTAL', defaultScope: 'faculty', title: { th: 'พอร์ทัลงานวิจัย', en: 'Research Portal' } },
    { key: 'ERP_STAFF', defaultScope: 'division', title: { th: 'ระบบ ERP สำหรับเจ้าหน้าที่', en: 'ERP Staff' } },
    { key: 'DOCUMENT_CENTER', defaultScope: 'unit', title: { th: 'ระบบเอกสารกลาง', en: 'Document Center' } },
    { key: 'EXEC_REPORTING', defaultScope: 'university', title: { th: 'รายงานผู้บริหาร', en: 'Executive Reporting' } },
    { key: 'ERP_APPROVAL', defaultScope: 'faculty', title: { th: 'อนุมัติในระบบ ERP', en: 'ERP Approval' } },
    { key: 'STUDENT_PORTAL', defaultScope: 'program', title: { th: 'พอร์ทัลนักศึกษา', en: 'Student Portal' } },
    { key: 'LIBRARY', defaultScope: 'self', title: { th: 'บริการห้องสมุด', en: 'Library Access' } },
    { key: 'LIMITED_PORTAL', defaultScope: 'unit', title: { th: 'พอร์ทัลจำกัดสิทธิ์', en: 'Limited Portal' } },
    { key: 'ALUMNI_PORTAL', defaultScope: 'self', title: { th: 'พอร์ทัลศิษย์เก่า', en: 'Alumni Portal' } },
    { key: 'GUEST_PORTAL', defaultScope: 'self', title: { th: 'พอร์ทัลผู้เยี่ยมชม', en: 'Guest Portal' } },
    { key: 'FACULTY_APPROVAL', defaultScope: 'faculty', title: { th: 'สิทธิ์อนุมัติระดับคณะ', en: 'Faculty Approval' } },
    { key: 'FACULTY_REPORTING', defaultScope: 'faculty', title: { th: 'สิทธิ์รายงานระดับคณะ', en: 'Faculty Reporting' } },
    { key: 'UNIT_APPROVAL', defaultScope: 'unit', title: { th: 'สิทธิ์อนุมัติระดับหน่วยงาน', en: 'Unit Approval' } },
    { key: 'UNIT_REPORTING', defaultScope: 'unit', title: { th: 'สิทธิ์รายงานระดับหน่วยงาน', en: 'Unit Reporting' } },
    { key: 'COURSE_MANAGEMENT', defaultScope: 'course', title: { th: 'บริหารรายวิชา', en: 'Course Management' } },
    { key: 'ADVISEE_MANAGEMENT', defaultScope: 'course', title: { th: 'ดูแลอาจารย์ที่ปรึกษา', en: 'Advisee Management' } },
    { key: 'NewSystem_OPERATIONS', defaultScope: 'division', title: { th: 'ปฏิบัติการการเงิน', en: 'New System Operations' } },
    { key: 'HR_OPERATIONS', defaultScope: 'division', title: { th: 'ปฏิบัติการทรัพยากรบุคคล', en: 'HR Operations' } },
    { key: 'LIBRARY_STAFF', defaultScope: 'library', title: { th: 'เจ้าหน้าที่ห้องสมุด', en: 'Library Staff' } }
];

const SEED_POSITION_RULES = [
    { key: 'RULE_EXECUTIVE_DEAN', title: { th: 'สิทธิ์คณบดี', en: 'Dean Position Rule' }, matchType: 'CONTAINS', matchValues: ['dean', 'คณบดี'], orgScope: 'faculty', priority: 10, affiliationKeys: ['ACADEMIC', 'EXECUTIVE'], profileKeys: ['FACULTY_APPROVAL', 'FACULTY_REPORTING'] },
    { key: 'RULE_UNIT_HEAD', title: { th: 'สิทธิ์หัวหน้าหน่วยงาน', en: 'Unit Head Rule' }, matchType: 'CONTAINS', matchValues: ['director', 'head', 'chair', 'ผู้อำนวยการ', 'หัวหน้า'], orgScope: 'unit', priority: 20, affiliationKeys: ['ACADEMIC', 'OPERATIONAL', 'EXECUTIVE'], profileKeys: ['UNIT_APPROVAL', 'UNIT_REPORTING'] },
    { key: 'RULE_LECTURER', title: { th: 'สิทธิ์อาจารย์', en: 'Lecturer Rule' }, matchType: 'CONTAINS', matchValues: ['lecturer', 'อาจารย์'], orgScope: 'course', priority: 30, affiliationKeys: ['ACADEMIC'], profileKeys: ['COURSE_MANAGEMENT', 'ADVISEE_MANAGEMENT'] },
    { key: 'RULE_NewSystem', title: { th: 'สิทธิ์การเงิน', en: 'New System Rule' }, matchType: 'CONTAINS', matchValues: ['newSystem', 'การเงิน'], orgScope: 'division', priority: 40, affiliationKeys: ['OPERATIONAL'], profileKeys: ['NewSystem_OPERATIONS'] },
    { key: 'RULE_HR', title: { th: 'สิทธิ์บุคคล', en: 'HR Rule' }, matchType: 'CONTAINS', matchValues: ['hr', 'บุคคล'], orgScope: 'division', priority: 50, affiliationKeys: ['OPERATIONAL'], profileKeys: ['HR_OPERATIONS'] },
    { key: 'RULE_LIBRARY', title: { th: 'สิทธิ์ห้องสมุด', en: 'Library Rule' }, matchType: 'CONTAINS', matchValues: ['library', 'บรรณารักษ์'], orgScope: 'library', priority: 60, affiliationKeys: ['OPERATIONAL'], profileKeys: ['LIBRARY_STAFF'] }
];

const SEED_POLICIES = [
    { key: 'POLICY_ACADEMIC', affiliationKey: 'ACADEMIC', profileKeys: ['EMAIL', 'SSO', 'LMS_STAFF', 'RESEARCH_PORTAL'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: true },
    { key: 'POLICY_OPERATIONAL', affiliationKey: 'OPERATIONAL', profileKeys: ['EMAIL', 'SSO', 'ERP_STAFF', 'DOCUMENT_CENTER'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: true },
    { key: 'POLICY_EXECUTIVE', affiliationKey: 'EXECUTIVE', profileKeys: ['EMAIL', 'SSO', 'ERP_APPROVAL', 'EXEC_REPORTING'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: true },
    { key: 'POLICY_STUDENT', affiliationKey: 'STUDENT', profileKeys: ['EMAIL', 'SSO', 'STUDENT_PORTAL', 'LMS_STUDENT', 'LIBRARY'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: true },
    { key: 'POLICY_CONTRACTOR', affiliationKey: 'CONTRACTOR', profileKeys: ['EMAIL', 'SSO', 'LIMITED_PORTAL'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: true },
    { key: 'POLICY_ALUMNI', affiliationKey: 'ALUMNI', profileKeys: ['ALUMNI_PORTAL'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: false },
    { key: 'POLICY_EXTERNAL', affiliationKey: 'EXTERNAL', profileKeys: ['GUEST_PORTAL'], targetStatusKey: 'ACTIVE', autoProvision: true, autoDeprovision: true, revokeSessionsOnDeprovision: true }
];

function normalizeKey(value) {
    return String(value || '').trim().toUpperCase();
}

function normalizeString(value) {
    if (value === null || value === undefined) return null;
    const normalized = String(value).trim();
    return normalized || null;
}

function toLangArray(value) {
    const source = value || {};
    return Object.keys(source).map(function (key) {
        return { key: String(key).trim().toLowerCase(), value: String(source[key] || '').trim() };
    }).filter(function (item) {
        return item.key && item.value;
    });
}

function toObjectIdString(value) {
    if (!value) return '';
    if (typeof value === 'string' && mongo.ObjectId.isValid(value)) return String(value);
    if (value instanceof mongo.ObjectId) return String(value);
    if (value && typeof value.toHexString === 'function') return String(value.toHexString());
    if (value && typeof value === 'object' && value._id && mongo.ObjectId.isValid(value._id)) return String(value._id);
    return '';
}

function ensureArray(value) {
    return Array.isArray(value) ? value : [];
}

async function ensureAffiliationTypes() {
    const docs = [];
    for (const item of SEED_AFFILIATIONS) {
        const query = { key: normalizeKey(item.key) };
        let doc = await AffiliationType.onQuery(query);
        const payload = {
            key: normalizeKey(item.key),
            title: toLangArray(item.title),
            description: toLangArray(item.description),
            source: 'SYSTEM',
            version: 1,
            isSystem: true,
            state: true
        };
        if (!doc) doc = await AffiliationType.onCreate(payload);
        else doc = await AffiliationType.onUpdate({ _id: new mongo.ObjectId(doc._id) }, Object.assign({}, payload, { update: doc.update }));
        docs.push(doc);
    }
    return docs;
}

async function ensureAccessProfiles() {
    const docs = [];
    for (const item of SEED_ACCESS_PROFILES) {
        const query = { key: normalizeKey(item.key) };
        let doc = await AccessProfile.onQuery(query);
        const payload = {
            key: normalizeKey(item.key),
            title: toLangArray(item.title),
            description: toLangArray(item.description || item.title),
            defaultScope: normalizeString(item.defaultScope) || 'self',
            source: 'SYSTEM',
            version: 1,
            isSystem: true,
            state: true
        };
        if (!doc) doc = await AccessProfile.onCreate(payload);
        else doc = await AccessProfile.onUpdate({ _id: new mongo.ObjectId(doc._id) }, Object.assign({}, payload, { update: doc.update }));
        docs.push(doc);
    }
    return docs;
}

async function ensurePositionRules(affiliationsByKey, profilesByKey) {
    const docs = [];
    for (const item of SEED_POSITION_RULES) {
        const affiliationTypes = ensureArray(item.affiliationKeys).map(function (key) {
            const doc = affiliationsByKey[normalizeKey(key)];
            return doc && doc._id ? new mongo.ObjectId(doc._id) : null;
        }).filter(Boolean);
        const accessProfiles = ensureArray(item.profileKeys).map(function (key) {
            const doc = profilesByKey[normalizeKey(key)];
            return doc && doc._id ? new mongo.ObjectId(doc._id) : null;
        }).filter(Boolean);
        let doc = await PositionRule.onQuery({ key: normalizeKey(item.key) });
        const payload = {
            key: normalizeKey(item.key),
            title: toLangArray(item.title),
            description: toLangArray(item.description || item.title),
            affiliationTypes: affiliationTypes,
            matchType: normalizeKey(item.matchType),
            matchValues: ensureArray(item.matchValues).map(normalizeString).filter(Boolean),
            orgScope: normalizeString(item.orgScope) || 'unit',
            accessProfiles: accessProfiles,
            priority: Number(item.priority || 100),
            source: 'SYSTEM',
            version: 1,
            isSystem: true,
            state: true
        };
        if (!doc) doc = await PositionRule.onCreate(payload);
        else doc = await PositionRule.onUpdate({ _id: new mongo.ObjectId(doc._id) }, Object.assign({}, payload, { update: doc.update }));
        docs.push(doc);
    }
    return docs;
}

async function ensureProvisioningPolicies(affiliationsByKey, profilesByKey, statusesByKey) {
    const docs = [];
    for (const item of SEED_POLICIES) {
        const affiliationType = affiliationsByKey[normalizeKey(item.affiliationKey)];
        const defaultTargetStatus = statusesByKey[normalizeKey(item.targetStatusKey)];
        const defaultAccessProfiles = ensureArray(item.profileKeys).map(function (key) {
            const doc = profilesByKey[normalizeKey(key)];
            return doc && doc._id ? new mongo.ObjectId(doc._id) : null;
        }).filter(Boolean);
        let doc = await ProvisioningPolicy.onQuery({ key: normalizeKey(item.key) });
        const payload = {
            key: normalizeKey(item.key),
            title: toLangArray({ th: item.affiliationKey, en: item.affiliationKey }),
            description: toLangArray({ th: 'Lifecycle policy for ' + item.affiliationKey, en: 'Lifecycle policy for ' + item.affiliationKey }),
            affiliationType: affiliationType && affiliationType._id ? new mongo.ObjectId(affiliationType._id) : null,
            defaultAccessProfiles: defaultAccessProfiles,
            defaultTargetStatus: defaultTargetStatus && defaultTargetStatus._id ? new mongo.ObjectId(defaultTargetStatus._id) : null,
            autoProvision: item.autoProvision !== false,
            autoDeprovision: item.autoDeprovision !== false,
            revokeSessionsOnDeprovision: item.revokeSessionsOnDeprovision !== false,
            source: 'SYSTEM',
            version: 1,
            isSystem: true,
            state: true
        };
        if (!doc) doc = await ProvisioningPolicy.onCreate(payload);
        else doc = await ProvisioningPolicy.onUpdate({ _id: new mongo.ObjectId(doc._id) }, Object.assign({}, payload, { update: doc.update }));
        docs.push(doc);
    }
    return docs;
}

async function ensureLifecycleMasterData() {
    const affiliationDocs = await ensureAffiliationTypes();
    const accessProfileDocs = await ensureAccessProfiles();
    const affiliationsByKey = {};
    const profilesByKey = {};
    affiliationDocs.forEach(function (item) {
        affiliationsByKey[normalizeKey(item && item.key)] = item;
    });
    accessProfileDocs.forEach(function (item) {
        profilesByKey[normalizeKey(item && item.key)] = item;
    });
    const accountStatus = await ensureAccountStatusMasterData();
    await ensurePositionRules(affiliationsByKey, profilesByKey);
    await ensureProvisioningPolicies(affiliationsByKey, profilesByKey, accountStatus.statuses || {});
    return true;
}

async function loadLifecycleCatalog() {
    await ensureLifecycleMasterData();
    const [affiliationTypes, accessProfiles, positionRules, provisioningPolicies, accountStatus] = await Promise.all([
        AffiliationType.onQuerys({}),
        AccessProfile.onQuerys({}),
        PositionRule.onQuerys({}),
        ProvisioningPolicy.onQuerys({}),
        ensureAccountStatusMasterData()
    ]);
    return {
        affiliationTypes: affiliationTypes || [],
        accessProfiles: accessProfiles || [],
        positionRules: positionRules || [],
        provisioningPolicies: provisioningPolicies || [],
        accountStatuses: Object.values((accountStatus && accountStatus.statuses) || {}).map(sanitizeStatus).filter(Boolean)
    };
}

function buildCatalogIndex(catalog) {
    const affiliationById = {};
    const affiliationByKey = {};
    const accessProfileById = {};
    const accessProfileByKey = {};
    const policyByAffiliationId = {};
    const statusById = {};

    ensureArray(catalog && catalog.affiliationTypes).forEach(function (item) {
        const id = toObjectIdString(item);
        const key = normalizeKey(item && item.key);
        if (id) affiliationById[id] = item;
        if (key) affiliationByKey[key] = item;
    });

    ensureArray(catalog && catalog.accessProfiles).forEach(function (item) {
        const id = toObjectIdString(item);
        const key = normalizeKey(item && item.key);
        if (id) accessProfileById[id] = item;
        if (key) accessProfileByKey[key] = item;
    });

    ensureArray(catalog && catalog.provisioningPolicies).forEach(function (item) {
        const affiliationTypeId = toObjectIdString(item && item.affiliationType);
        if (affiliationTypeId) policyByAffiliationId[affiliationTypeId] = item;
    });

    ensureArray(catalog && catalog.accountStatuses).forEach(function (item) {
        const id = toObjectIdString(item);
        if (id) statusById[id] = item;
    });

    return {
        affiliationById,
        affiliationByKey,
        accessProfileById,
        accessProfileByKey,
        policyByAffiliationId,
        statusById
    };
}

function getEntityId(value, byId, byKey) {
    const directId = toObjectIdString(value);
    if (directId && byId[directId]) return directId;
    const key = normalizeKey(value && value.key ? value.key : value);
    const found = key ? byKey[key] : null;
    return found && found._id ? String(found._id) : '';
}

function normalizeDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function normalizeOrgPath(value) {
    if (!Array.isArray(value)) return [];
    return value.map(normalizeString).filter(Boolean);
}

function normalizePosition(item) {
    return {
        code: normalizeString(item && item.code),
        title: normalizeString(item && item.title),
        type: normalizeKey(item && item.type) || 'POSITION',
        orgPath: normalizeOrgPath(item && item.orgPath),
        startDate: normalizeDate(item && item.startDate),
        endDate: normalizeDate(item && item.endDate),
        isActing: !!(item && item.isActing)
    };
}

function normalizeMovement(item) {
    return {
        type: normalizeKey(item && item.type) || 'TRANSFER',
        fromTitle: normalizeString(item && item.fromTitle),
        toTitle: normalizeString(item && item.toTitle),
        fromOrgPath: normalizeOrgPath(item && item.fromOrgPath),
        toOrgPath: normalizeOrgPath(item && item.toOrgPath),
        effectiveDate: normalizeDate(item && item.effectiveDate),
        reason: normalizeString(item && item.reason),
        referenceNo: normalizeString(item && item.referenceNo),
        approvedBy: normalizeString(item && item.approvedBy),
        impact: normalizeKey(item && item.impact) || 'INFO',
        status: normalizeKey(item && item.status) || 'COMPLETED'
    };
}

function normalizeLeave(item) {
    return {
        type: normalizeKey(item && item.type) || 'LEAVE',
        startDate: normalizeDate(item && item.startDate),
        endDate: normalizeDate(item && item.endDate),
        status: normalizeKey(item && item.status) || 'APPROVED',
        reason: normalizeString(item && item.reason),
        referenceNo: normalizeString(item && item.referenceNo),
        approvedBy: normalizeString(item && item.approvedBy),
        accessImpact: normalizeKey(item && item.accessImpact) || 'KEEP',
        remarks: normalizeString(item && item.remarks)
    };
}

function normalizeDevelopment(item) {
    return {
        type: normalizeKey(item && item.type) || 'TRAINING',
        title: normalizeString(item && item.title),
        provider: normalizeString(item && item.provider),
        startDate: normalizeDate(item && item.startDate),
        endDate: normalizeDate(item && item.endDate),
        status: normalizeKey(item && item.status) || 'PLANNED',
        outcome: normalizeString(item && item.outcome),
        credential: normalizeString(item && item.credential),
        hours: item && item.hours != null && item.hours !== '' ? Number(item.hours) : null,
        linkedLeaveType: normalizeKey(item && item.linkedLeaveType),
        remarks: normalizeString(item && item.remarks)
    };
}

function normalizeAssignment(item, index) {
    return {
        type: normalizeKey(item && item.type) || 'TEMPORARY_ROLE',
        title: normalizeString(item && item.title),
        orgPath: normalizeOrgPath(item && item.orgPath),
        startDate: normalizeDate(item && item.startDate),
        endDate: normalizeDate(item && item.endDate),
        status: normalizeKey(item && item.status) || 'ACTIVE',
        scope: normalizeString(item && item.scope) || 'unit',
        approvedBy: normalizeString(item && item.approvedBy),
        referenceNo: normalizeString(item && item.referenceNo),
        remarks: normalizeString(item && item.remarks),
        temporary: !(item && item.temporary === false),
        accessProfiles: [],
        order: index
    };
}

function normalizeLifecyclePayload(payload, currentLifecycle, catalogIndex) {
    const index = catalogIndex || {};
    const migration = {
        legacyPrimaryAffiliation: null,
        unmappedAffiliations: [],
        unmappedAccessProfiles: [],
        lastMigratedAt: new Date()
    };
    const primaryAffiliationId = getEntityId(payload && (payload.primaryAffiliation || payload.primaryAffiliationId), index.affiliationById || {}, index.affiliationByKey || {});
    if (!primaryAffiliationId && payload && (payload.primaryAffiliation || payload.primaryAffiliationId)) {
        migration.legacyPrimaryAffiliation = normalizeString(payload.primaryAffiliation || payload.primaryAffiliationId);
    }
    const affiliationsSrc = Array.isArray(payload && payload.affiliations) ? payload.affiliations : ensureArray(currentLifecycle && currentLifecycle.affiliations);
    const accessProfilesSrc = Array.isArray(payload && payload.accessProfiles) ? payload.accessProfiles : ensureArray(currentLifecycle && currentLifecycle.accessProfiles);
    const positionsSrc = Array.isArray(payload && payload.positions) ? payload.positions : ensureArray(currentLifecycle && currentLifecycle.positions);
    const movementsSrc = Array.isArray(payload && payload.movements) ? payload.movements : ensureArray(currentLifecycle && currentLifecycle.movements);
    const leavesSrc = Array.isArray(payload && payload.leaves) ? payload.leaves : ensureArray(currentLifecycle && currentLifecycle.leaves);
    const developmentsSrc = Array.isArray(payload && payload.developments) ? payload.developments : ensureArray(currentLifecycle && currentLifecycle.developments);
    const assignmentsSrc = Array.isArray(payload && payload.assignments) ? payload.assignments : ensureArray(currentLifecycle && currentLifecycle.assignments);

    const affiliations = affiliationsSrc.map(function (item, indexAff) {
        const typeId = getEntityId(item && (item.type || item.typeId), index.affiliationById || {}, index.affiliationByKey || {});
        if (!typeId && item && (item.type || item.typeId)) {
            migration.unmappedAffiliations.push(String(item.type || item.typeId));
        }
        return {
            type: typeId ? new mongo.ObjectId(typeId) : null,
            category: normalizeString(item && item.category),
            orgPath: normalizeOrgPath(item && item.orgPath),
            orgCode: normalizeString(item && item.orgCode),
            title: normalizeString(item && item.title),
            startDate: normalizeDate(item && item.startDate),
            endDate: normalizeDate(item && item.endDate),
            source: normalizeString(item && item.source) || 'MANUAL',
            status: normalizeKey(item && item.status) || 'ACTIVE',
            isPrimary: !!(item && item.isPrimary) || indexAff === 0
        };
    }).filter(function (item) {
        return !!item.type;
    });

    const accessProfiles = accessProfilesSrc.map(function (item) {
        const profileId = getEntityId(item && (item.profile || item.profileId || item.key), index.accessProfileById || {}, index.accessProfileByKey || {});
        if (!profileId && item && (item.profile || item.profileId || item.key)) {
            migration.unmappedAccessProfiles.push(String(item.profile || item.profileId || item.key));
        }
        const source = normalizeString(item && item.source) || 'MANUAL';
        return {
            profile: profileId ? new mongo.ObjectId(profileId) : null,
            scope: normalizeString(item && item.scope) || 'self',
            source: source,
            startDate: normalizeDate(item && item.startDate),
            endDate: normalizeDate(item && item.endDate),
            isManual: source === 'MANUAL' || !!(item && item.isManual)
        };
    }).filter(function (item) {
        return !!item.profile;
    });

    const assignments = assignmentsSrc.map(function (item, indexAssignment) {
        const normalized = normalizeAssignment(item, indexAssignment);
        normalized.accessProfiles = ensureArray(item && item.accessProfiles).map(function (profileItem) {
            const profileId = getEntityId(profileItem && (profileItem.profile || profileItem.profileId || profileItem.key || profileItem), index.accessProfileById || {}, index.accessProfileByKey || {});
            if (!profileId && profileItem) {
                migration.unmappedAccessProfiles.push(String(profileItem.profile || profileItem.profileId || profileItem.key || profileItem));
            }
            return profileId ? new mongo.ObjectId(profileId) : null;
        }).filter(Boolean);
        return normalized;
    }).filter(function (item) {
        return !!item.title;
    });

    const provisioning = Object.assign({}, currentLifecycle && currentLifecycle.provisioning ? currentLifecycle.provisioning : {}, payload && payload.provisioning ? payload.provisioning : {});

    return {
        primaryAffiliation: primaryAffiliationId ? new mongo.ObjectId(primaryAffiliationId) : null,
        affiliations: affiliations,
        positions: positionsSrc.map(normalizePosition).filter(function (item) { return !!item.title; }),
        movements: movementsSrc.map(normalizeMovement).filter(function (item) { return !!(item.fromTitle || item.toTitle || item.fromOrgPath.length || item.toOrgPath.length); }),
        leaves: leavesSrc.map(normalizeLeave).filter(function (item) { return !!item.type; }),
        developments: developmentsSrc.map(normalizeDevelopment).filter(function (item) { return !!item.title; }),
        assignments: assignments,
        accessProfiles: accessProfiles,
        provisioning: {
            state: normalizeKey(provisioning.state) || 'UNPROVISIONED',
            strategy: normalizeKey(provisioning.strategy) || 'RULE_BASED',
            joinerDate: normalizeDate(provisioning.joinerDate),
            moverDate: normalizeDate(provisioning.moverDate),
            deprovisionDate: normalizeDate(provisioning.deprovisionDate),
            deprovisionReason: normalizeString(provisioning.deprovisionReason),
            lastEvaluatedAt: normalizeDate(provisioning.lastEvaluatedAt),
            lastProvisionedAt: normalizeDate(provisioning.lastProvisionedAt),
            lastDeprovisionedAt: normalizeDate(provisioning.lastDeprovisionedAt),
            lastSyncSource: normalizeString(provisioning.lastSyncSource) || 'MANUAL'
        },
        migration: migration
    };
}

function isEntryActive(item, now) {
    const current = now || new Date();
    if (!item) return false;
    if (normalizeKey(item.status) === 'INACTIVE') return false;
    const start = normalizeDate(item.startDate);
    const end = normalizeDate(item.endDate);
    if (start && start.getTime() > current.getTime()) return false;
    if (end && end.getTime() < current.getTime()) return false;
    return true;
}

function pickLangValue(items) {
    const rows = ensureArray(items);
    const foundEn = rows.find(function (item) { return item && item.key === 'en' && item.value; });
    if (foundEn) return String(foundEn.value);
    const found = rows.find(function (item) { return item && item.value; });
    return found ? String(found.value) : '';
}

function resolveProfileLabel(profile) {
    return pickLangValue(profile && profile.title) || normalizeKey(profile && profile.key);
}

function dedupeRecommendations(items) {
    const result = [];
    const seen = {};
    ensureArray(items).forEach(function (item) {
        const profileId = toObjectIdString(item && item.profile);
        const scope = normalizeString(item && item.scope) || 'self';
        const key = profileId + ':' + scope + ':' + normalizeKey(item && item.source);
        if (!profileId || seen[key]) return;
        seen[key] = true;
        result.push(item);
    });
    return result;
}

function matchRule(matchType, matchValues, title) {
    const normalizedTitle = String(title || '').trim().toLowerCase();
    const values = ensureArray(matchValues).map(function (item) {
        return String(item || '').trim().toLowerCase();
    }).filter(Boolean);
    if (!normalizedTitle || !values.length) return false;
    if (matchType === 'EXACT') {
        return values.includes(normalizedTitle);
    }
    return values.some(function (item) {
        return normalizedTitle.indexOf(item) !== -1;
    });
}

function resolveLifecycle(lifecycle, catalogIndex) {
    const index = catalogIndex || {};
    const resolved = Object.assign({}, lifecycle || {});
    resolved.primaryAffiliation = resolved.primaryAffiliation ? (index.affiliationById[toObjectIdString(resolved.primaryAffiliation)] || null) : null;
    resolved.affiliations = ensureArray(lifecycle && lifecycle.affiliations).map(function (item) {
        return Object.assign({}, item, {
            type: index.affiliationById[toObjectIdString(item && item.type)] || null
        });
    });
    resolved.accessProfiles = ensureArray(lifecycle && lifecycle.accessProfiles).map(function (item) {
        return Object.assign({}, item, {
            profile: index.accessProfileById[toObjectIdString(item && item.profile)] || null
        });
    });
    resolved.assignments = ensureArray(lifecycle && lifecycle.assignments).map(function (item) {
        return Object.assign({}, item, {
            accessProfiles: ensureArray(item && item.accessProfiles).map(function (profile) {
                return index.accessProfileById[toObjectIdString(profile)] || null;
            }).filter(Boolean)
        });
    });
    return resolved;
}

function evaluateLifecycle(lifecycle, catalog, account) {
    const index = buildCatalogIndex(catalog);
    const resolvedLifecycle = resolveLifecycle(lifecycle, index);
    const now = new Date();
    const activeAffiliations = ensureArray(resolvedLifecycle.affiliations).filter(function (item) {
        return !!(item && item.type && isEntryActive(item, now));
    });
    const activeAffiliationIds = activeAffiliations.map(function (item) {
        return toObjectIdString(item.type);
    });
    const configurationErrors = [];
    const warnings = [];
    const matchedRules = [];
    let targetStatusKey = null;
    const recommendations = [];
    const activeLeaves = ensureArray(resolvedLifecycle.leaves).filter(function (item) {
        return !!(item && normalizeKey(item.status) === 'APPROVED' && isEntryActive(item, now));
    });

    activeAffiliations.forEach(function (item) {
        const affiliationId = toObjectIdString(item.type);
        const policy = index.policyByAffiliationId[affiliationId];
        if (!policy) {
            configurationErrors.push('Missing provisioning policy for affiliation ' + (item.type && item.type.key ? item.type.key : affiliationId));
            return;
        }
        ensureArray(policy.defaultAccessProfiles).forEach(function (profile) {
            recommendations.push({
                profile: profile,
                scope: normalizeString(profile && profile.defaultScope) || 'self',
                source: 'POLICY'
            });
        });
    });

    ensureArray(resolvedLifecycle.positions).forEach(function (position) {
        ensureArray(catalog && catalog.positionRules)
            .filter(function (rule) { return rule && rule.state !== false; })
            .sort(function (left, right) { return Number(left.priority || 100) - Number(right.priority || 100); })
            .forEach(function (rule) {
                const ruleAffiliationIds = ensureArray(rule.affiliationTypes).map(toObjectIdString).filter(Boolean);
                const hasAffiliation = !ruleAffiliationIds.length || ruleAffiliationIds.some(function (id) {
                    return activeAffiliationIds.includes(id);
                });
                if (!hasAffiliation) return;
                const matchType = normalizeKey(rule.matchType);
                if (!MATCH_TYPES.includes(matchType)) return;
                if (!matchRule(matchType, rule.matchValues, position && position.title)) return;
                matchedRules.push({
                    _id: rule._id,
                    key: rule.key,
                    matchType: rule.matchType,
                    matchValues: rule.matchValues,
                    orgScope: rule.orgScope,
                    priority: rule.priority
                });
                ensureArray(rule.accessProfiles).forEach(function (profile) {
                    recommendations.push({
                        profile: profile,
                        scope: normalizeString(rule.orgScope) || normalizeString(profile && profile.defaultScope) || 'self',
                        source: 'RULE',
                        ruleKey: rule.key
                    });
                });
            });
    });

    ensureArray(resolvedLifecycle.accessProfiles).forEach(function (item) {
        if (!(item && item.profile)) {
            warnings.push('Manual exception access contains an unmapped access profile.');
            return;
        }
        recommendations.push({
            profile: item.profile,
            scope: normalizeString(item.scope) || normalizeString(item.profile && item.profile.defaultScope) || 'self',
            source: item.isManual ? 'MANUAL' : normalizeKey(item.source) || 'MANUAL',
            startDate: item.startDate || null,
            endDate: item.endDate || null
        });
    });

    ensureArray(resolvedLifecycle.assignments).forEach(function (item) {
        if (!item || normalizeKey(item.status) === 'INACTIVE' || !isEntryActive(item, now)) return;
        ensureArray(item.accessProfiles).forEach(function (profile) {
            recommendations.push({
                profile: profile,
                scope: normalizeString(item.scope) || normalizeString(profile && profile.defaultScope) || 'unit',
                source: 'ASSIGNMENT',
                assignmentTitle: item.title || ''
            });
        });
    });

    const primaryAffiliationId = toObjectIdString(resolvedLifecycle.primaryAffiliation) || (activeAffiliations[0] && toObjectIdString(activeAffiliations[0].type)) || '';
    const primaryPolicy = primaryAffiliationId ? index.policyByAffiliationId[primaryAffiliationId] : null;
    if (!activeAffiliations.length) {
        warnings.push('No active affiliations. Provisioning target status cannot be resolved until affiliation data is provided.');
    } else if (!primaryPolicy) {
        configurationErrors.push('Primary affiliation does not have a provisioning policy.');
    } else if (!(primaryPolicy.defaultTargetStatus && primaryPolicy.defaultTargetStatus.key)) {
        configurationErrors.push('Primary affiliation policy does not define a target status.');
    } else {
        targetStatusKey = primaryPolicy.defaultTargetStatus.key;
    }

    activeLeaves.forEach(function (item) {
        if (normalizeKey(item.accessImpact) === 'SUSPEND') {
            targetStatusKey = 'SUSPENDED';
            warnings.push('Active leave "' + item.type + '" requires suspended access handling.');
        } else if (normalizeKey(item.accessImpact) === 'LIMIT') {
            warnings.push('Active leave "' + item.type + '" requires temporary access reduction review.');
        }
    });

    const deduped = dedupeRecommendations(recommendations).map(function (item) {
        return Object.assign({}, item, {
            key: item.profile && item.profile.key ? item.profile.key : '',
            label: resolveProfileLabel(item.profile)
        });
    });

    return {
        lifecycle: resolvedLifecycle,
        matchedRules: matchedRules,
        recommendedProfiles: deduped,
        targetStatusKey: targetStatusKey,
        configurationErrors: configurationErrors,
        warnings: warnings,
        activeLeaves: activeLeaves
    };
}

function buildLifecycleOptions(catalog) {
    return {
        affiliationTypes: ensureArray(catalog && catalog.affiliationTypes),
        accessProfiles: ensureArray(catalog && catalog.accessProfiles),
        positionRules: ensureArray(catalog && catalog.positionRules),
        provisioningPolicies: ensureArray(catalog && catalog.provisioningPolicies),
        accountStatuses: ensureArray(catalog && catalog.accountStatuses),
        matchTypes: MATCH_TYPES,
        orgScopes: ['self', 'unit', 'faculty', 'division', 'program', 'course', 'library', 'university']
    };
}

module.exports = {
    buildCatalogIndex,
    buildLifecycleOptions,
    ensureLifecycleMasterData,
    evaluateLifecycle,
    loadLifecycleCatalog,
    normalizeLifecyclePayload
};
