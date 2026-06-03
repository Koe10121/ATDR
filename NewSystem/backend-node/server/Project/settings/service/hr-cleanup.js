'use strict';

const HrOrgGroupMaster = require('../models/hr_org_group_master.model');
const HrOrgUnitMaster = require('../models/hr_org_unit_master.model');
const HrSubUnitMaster = require('../models/hr_sub_unit_master.model');
const HrDegreeLevelMaster = require('../models/hr_degree_level_master.model');
const HrEmploymentStatusMaster = require('../models/hr_employment_status_master.model');
const HrWorkLineMaster = require('../models/hr_work_line_master.model');
const HrPersonnelTypeMaster = require('../models/hr_personnel_type_master.model');
const HrAcademicRankMaster = require('../models/hr_academic_rank_master.model');
const HrPositionTitleMaster = require('../models/hr_position_title_master.model');
const HrWorkforceMaster = require('../models/hr_workforce_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { normalizeString, slugify, compactStringArray, normalizeLangArray, pickLangValue, toLangArray } = require('./hr_shared');

function updateSummary(summary, key, changed) {
    if (changed) summary[key] += 1;
}

async function buildLookupMap(Model) {
    const docs = await Model.find({}).select('_id key title code description').lean();
    return docs.reduce(function (result, item) {
        if (item && item.key) result[item.key] = item;
        return result;
    }, {});
}

async function loadMasterMaps() {
    const [
        orgGroups,
        orgUnits,
        subUnits,
        degreeLevels,
        employmentStatuses,
        workLines,
        personnelTypes,
        academicRanks,
        positionTitles
    ] = await Promise.all([
        buildLookupMap(HrOrgGroupMaster),
        buildLookupMap(HrOrgUnitMaster),
        buildLookupMap(HrSubUnitMaster),
        buildLookupMap(HrDegreeLevelMaster),
        buildLookupMap(HrEmploymentStatusMaster),
        buildLookupMap(HrWorkLineMaster),
        buildLookupMap(HrPersonnelTypeMaster),
        buildLookupMap(HrAcademicRankMaster),
        buildLookupMap(HrPositionTitleMaster)
    ]);

    return {
        orgGroups,
        orgUnits,
        subUnits,
        degreeLevels,
        employmentStatuses,
        workLines,
        personnelTypes,
        academicRanks,
        positionTitles
    };
}

function resolveMasterId(map, key) {
    const normalizedKey = normalizeString(key);
    if (!normalizedKey) return null;
    return map[normalizedKey] ? map[normalizedKey]._id : null;
}

function normalizeOrgUnitKey(orgGroupName, orgUnitName) {
    return [normalizeString(orgGroupName), normalizeString(orgUnitName)].filter(Boolean).map(slugify).join(':');
}

function normalizeSubUnitKey(orgGroupName, orgUnitName, subUnitName) {
    return [normalizeString(orgGroupName), normalizeString(orgUnitName), normalizeString(subUnitName)].filter(Boolean).map(slugify).join(':');
}

function buildWorkforceKey(payload) {
    return [
        normalizeString(payload && payload.workLineCode),
        normalizeString(payload && payload.personnelTypeCode),
        normalizeString(payload && payload.orgGroupName)
    ].filter(Boolean).map(slugify).join(':');
}

function buildWorkforceFallbackKey(payload) {
    return [
        normalizeString(payload && payload.workLineCode),
        normalizeString(payload && payload.orgGroupName)
    ].filter(Boolean).map(slugify).join(':');
}

function workforceCompletenessScore(doc) {
    let score = 0;
    if (normalizeString(doc && doc.workLineCode)) score += 2;
    if (normalizeString(doc && doc.personnelTypeCode)) score += 4;
    if (normalizeString(doc && doc.orgGroupName)) score += 3;
    if (normalizeString(doc && doc.employmentStatus)) score += 1;
    if (doc && doc.isActive !== false) score += 1;
    return score;
}

function applyCanonicalText(payload, field, refMap, refId) {
    if (!refId) {
        payload[field] = normalizeString(payload[field]) || null;
        return;
    }
    const found = Object.values(refMap).find(function (item) {
        return String(item._id) === String(refId);
    });
    payload[field] = found ? (pickLangValue(found.title) || normalizeString(payload[field]) || null) : (normalizeString(payload[field]) || null);
}

async function dedupeCodedMasters(Model, references, buildExpectedKey) {
    const summary = { merged: 0, removed: 0 };
    const docs = await Model.find({ code: { $nin: [null, ''] } }).sort({ updatedAt: -1, createdAt: -1 });
    const groups = new Map();

    docs.forEach(function (doc) {
        const titleText = pickLangValue(doc.title) || '';
        const key = [normalizeString(doc.code), normalizeString(titleText)].filter(Boolean).join('|');
        if (!key) return;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(doc);
    });

    for (const entries of groups.values()) {
        if (!entries || entries.length < 2) continue;
        const canonical = entries.reduce(function (best, current) {
            const expected = buildExpectedKey(current.code, pickLangValue(current.title));
            if (!best) return current;
            if (current.key === expected && best.key !== expected) return current;
            return best;
        }, null);
        const duplicates = entries.filter(function (doc) {
            return String(doc._id) !== String(canonical._id);
        });

        for (const duplicate of duplicates) {
            for (const reference of references) {
                const result = await reference.Model.updateMany(
                    { [reference.field]: duplicate._id },
                    { $set: { [reference.field]: canonical._id } }
                );
                summary.merged += Number(result && result.nModified ? result.nModified : result && result.modifiedCount ? result.modifiedCount : 0);
            }
            await Model.deleteOne({ _id: duplicate._id });
            summary.removed += 1;
        }
    }

    return summary;
}

async function backfillMasterDescriptions() {
    const summary = {
        orgGroupUpdated: 0,
        orgUnitUpdated: 0,
        subUnitUpdated: 0,
        degreeLevelUpdated: 0,
        employmentStatusUpdated: 0,
        workLineUpdated: 0,
        personnelTypeUpdated: 0,
        academicRankUpdated: 0,
        positionTitleUpdated: 0
    };

    const orgGroups = await HrOrgGroupMaster.find({});
    for (const doc of orgGroups) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: 'HR org group imported from workforce source data', en: 'HR org group imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.orgGroupUpdated += 1;
        }
    }

    const orgUnits = await HrOrgUnitMaster.find({}).populate({ path: 'orgGroup', select: 'title' });
    for (const doc of orgUnits) {
        const nextTitle = toLangArray(doc.title);
        const groupTitle = doc.orgGroup ? pickLangValue(doc.orgGroup.title) : null;
        const nextDescription = toLangArray({ th: [groupTitle, doc.code ? ('HR code ' + doc.code) : null].filter(Boolean).join(' | ') || null });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.orgUnitUpdated += 1;
        }
    }

    const subUnits = await HrSubUnitMaster.find({})
        .populate({ path: 'orgGroup', select: 'title' })
        .populate({ path: 'orgUnit', select: 'title' });
    for (const doc of subUnits) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = [
            doc.orgGroup ? pickLangValue(doc.orgGroup.title) : null,
            doc.orgUnit ? pickLangValue(doc.orgUnit.title) : null
        ].filter(Boolean).join(' | ') || null;
        const nextDescriptionItems = toLangArray({ th: nextDescription });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescriptionItems)) {
            doc.title = nextTitle;
            doc.description = nextDescriptionItems;
            await doc.save();
            summary.subUnitUpdated += 1;
        }
    }

    const degreeLevels = await HrDegreeLevelMaster.find({});
    for (const doc of degreeLevels) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: doc.code ? ('HR degree level code ' + doc.code) : 'HR degree level imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.degreeLevelUpdated += 1;
        }
    }

    const employmentStatuses = await HrEmploymentStatusMaster.find({});
    for (const doc of employmentStatuses) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: doc.code ? ('HR employment status code ' + doc.code) : 'HR employment status imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.employmentStatusUpdated += 1;
        }
    }

    const workLines = await HrWorkLineMaster.find({});
    for (const doc of workLines) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: doc.code ? ('HR work line code ' + doc.code) : 'HR work line imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.workLineUpdated += 1;
        }
    }

    const personnelTypes = await HrPersonnelTypeMaster.find({});
    for (const doc of personnelTypes) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: doc.code ? ('HR personnel type code ' + doc.code) : 'HR personnel type imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.personnelTypeUpdated += 1;
        }
    }

    const academicRanks = await HrAcademicRankMaster.find({});
    for (const doc of academicRanks) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: 'HR academic rank imported from workforce source data', en: 'HR academic rank imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.academicRankUpdated += 1;
        }
    }

    const positionTitles = await HrPositionTitleMaster.find({});
    for (const doc of positionTitles) {
        const nextTitle = toLangArray(doc.title);
        const nextDescription = toLangArray({ th: 'HR position title imported from workforce source data', en: 'HR position title imported from workforce source data' });
        if (JSON.stringify(normalizeLangArray(doc.title)) !== JSON.stringify(nextTitle) || JSON.stringify(normalizeLangArray(doc.description)) !== JSON.stringify(nextDescription)) {
            doc.title = nextTitle;
            doc.description = nextDescription;
            await doc.save();
            summary.positionTitleUpdated += 1;
        }
    }

    return summary;
}

async function cleanupHrDatabase() {
    const summary = {
        masters: await backfillMasterDescriptions(),
        dedupe: {},
        workforceUpdated: 0,
        workforceReassigned: 0,
        workforceDeactivated: 0,
        positionUpdated: 0,
        identityUpdated: 0
    };
    summary.dedupe.degreeLevels = await dedupeCodedMasters(HrDegreeLevelMaster, [
        { Model: HrPositionMaster, field: 'degreeLevelMaster' },
        { Model: HrIdentityMaster, field: 'degreeLevelMaster' }
    ], function (code, title) {
        return [normalizeString(code), slugify(title)].filter(Boolean).join(':');
    });
    summary.dedupe.employmentStatuses = await dedupeCodedMasters(HrEmploymentStatusMaster, [
        { Model: HrWorkforceMaster, field: 'employmentStatusMaster' },
        { Model: HrPositionMaster, field: 'employmentStatusMaster' },
        { Model: HrIdentityMaster, field: 'employmentStatusMaster' }
    ], function (code, title) {
        return [normalizeString(code), slugify(title)].filter(Boolean).join(':');
    });
    summary.dedupe.workLines = await dedupeCodedMasters(HrWorkLineMaster, [
        { Model: HrWorkforceMaster, field: 'workLine' },
        { Model: HrPositionMaster, field: 'workLine' },
        { Model: HrIdentityMaster, field: 'workLine' }
    ], function (code, title) {
        return [normalizeString(code), slugify(title)].filter(Boolean).join(':');
    });
    summary.dedupe.personnelTypes = await dedupeCodedMasters(HrPersonnelTypeMaster, [
        { Model: HrWorkforceMaster, field: 'personnelType' },
        { Model: HrPositionMaster, field: 'personnelType' },
        { Model: HrIdentityMaster, field: 'personnelType' }
    ], function (code, title) {
        return [normalizeString(code), slugify(title)].filter(Boolean).join(':');
    });
    const maps = await loadMasterMaps();
    const workforceDocs = await HrWorkforceMaster.find({});
    const workforceMap = new Map();
    const workforceFallbackMap = new Map();
    workforceDocs.forEach(function (doc) {
        const exactKey = buildWorkforceKey(doc);
        if (exactKey) {
            const current = workforceMap.get(exactKey);
            if (!current || workforceCompletenessScore(doc) > workforceCompletenessScore(current)) {
                workforceMap.set(exactKey, doc);
            }
        }
        const fallbackKey = buildWorkforceFallbackKey(doc);
        if (fallbackKey) {
            const current = workforceFallbackMap.get(fallbackKey);
            if (!current || workforceCompletenessScore(doc) > workforceCompletenessScore(current)) {
                workforceFallbackMap.set(fallbackKey, doc);
            }
        }
    });
    for (const doc of workforceDocs) {
        let changed = false;
        const orgGroupId = doc.orgGroup || resolveMasterId(maps.orgGroups, slugify(doc.orgGroupName));
        const workLineId = doc.workLine || resolveMasterId(maps.workLines, slugify(doc.workLineName));
        const personnelTypeId = doc.personnelType || resolveMasterId(maps.personnelTypes, slugify(doc.personnelTypeName));
        const employmentStatusId = doc.employmentStatusMaster || resolveMasterId(maps.employmentStatuses, slugify(doc.employmentStatus));

        if (String(doc.orgGroup || '') !== String(orgGroupId || '')) { doc.orgGroup = orgGroupId; changed = true; }
        if (String(doc.workLine || '') !== String(workLineId || '')) { doc.workLine = workLineId; changed = true; }
        if (String(doc.personnelType || '') !== String(personnelTypeId || '')) { doc.personnelType = personnelTypeId; changed = true; }
        if (String(doc.employmentStatusMaster || '') !== String(employmentStatusId || '')) { doc.employmentStatusMaster = employmentStatusId; changed = true; }

        const nextKey = [normalizeString(doc.workLineCode || ''), normalizeString(doc.personnelTypeCode || ''), normalizeString(doc.orgGroupName || '')].filter(Boolean).map(slugify).join(':');
        if (nextKey && doc.key !== nextKey) {
            const conflict = await HrWorkforceMaster.findOne({ key: nextKey, _id: { $ne: doc._id } }).select('_id').lean();
            if (!conflict) {
                doc.key = nextKey;
                changed = true;
            }
        }

        applyCanonicalText(doc, 'workLineName', maps.workLines, workLineId);
        applyCanonicalText(doc, 'personnelTypeName', maps.personnelTypes, personnelTypeId);
        applyCanonicalText(doc, 'orgGroupName', maps.orgGroups, orgGroupId);
        applyCanonicalText(doc, 'employmentStatus', maps.employmentStatuses, employmentStatusId);

        if (changed) {
            await doc.save();
            updateSummary(summary, 'workforceUpdated', true);
        }
    }

    const positionDocs = await HrPositionMaster.find({});
    for (const doc of positionDocs) {
        let changed = false;
        const orgGroupId = doc.orgGroup || resolveMasterId(maps.orgGroups, slugify(doc.orgGroupName));
        const orgUnitId = doc.orgUnitMaster || resolveMasterId(maps.orgUnits, normalizeOrgUnitKey(doc.orgGroupName, doc.orgUnitName));
        const subUnitId = doc.subUnitMaster || resolveMasterId(maps.subUnits, normalizeSubUnitKey(doc.orgGroupName, doc.orgUnitName, doc.orgSubUnitName));
        const degreeLevelId = doc.degreeLevelMaster || resolveMasterId(maps.degreeLevels, slugify(doc.degreeLevelName));
        const employmentStatusId = doc.employmentStatusMaster || resolveMasterId(maps.employmentStatuses, slugify(doc.employmentStatusName));
        const workLineId = doc.workLine || resolveMasterId(maps.workLines, slugify(doc.workLineName));
        const personnelTypeId = doc.personnelType || resolveMasterId(maps.personnelTypes, slugify(doc.personnelTypeName));
        const academicRankId = doc.academicRank || resolveMasterId(maps.academicRanks, slugify(doc.academicTitle));
        const positionTitleId = doc.positionTitleMaster || resolveMasterId(maps.positionTitles, slugify(doc.positionTitle));

        const nextOrgPath = compactStringArray(doc.orgPath);

        if (String(doc.orgGroup || '') !== String(orgGroupId || '')) { doc.orgGroup = orgGroupId; changed = true; }
        if (String(doc.orgUnitMaster || '') !== String(orgUnitId || '')) { doc.orgUnitMaster = orgUnitId; changed = true; }
        if (String(doc.subUnitMaster || '') !== String(subUnitId || '')) { doc.subUnitMaster = subUnitId; changed = true; }
        if (String(doc.degreeLevelMaster || '') !== String(degreeLevelId || '')) { doc.degreeLevelMaster = degreeLevelId; changed = true; }
        if (String(doc.employmentStatusMaster || '') !== String(employmentStatusId || '')) { doc.employmentStatusMaster = employmentStatusId; changed = true; }
        if (String(doc.workLine || '') !== String(workLineId || '')) { doc.workLine = workLineId; changed = true; }
        if (String(doc.personnelType || '') !== String(personnelTypeId || '')) { doc.personnelType = personnelTypeId; changed = true; }
        if (String(doc.academicRank || '') !== String(academicRankId || '')) { doc.academicRank = academicRankId; changed = true; }
        if (String(doc.positionTitleMaster || '') !== String(positionTitleId || '')) { doc.positionTitleMaster = positionTitleId; changed = true; }
        if (JSON.stringify(doc.orgPath || []) !== JSON.stringify(nextOrgPath)) { doc.orgPath = nextOrgPath; changed = true; }

        const exactWorkforceKey = buildWorkforceKey(doc);
        const fallbackWorkforceKey = buildWorkforceFallbackKey(doc);
        const canonicalWorkforce = (exactWorkforceKey && workforceMap.get(exactWorkforceKey))
            || (fallbackWorkforceKey && workforceFallbackMap.get(fallbackWorkforceKey))
            || null;
        if (canonicalWorkforce && String(doc.workforceProfile || '') !== String(canonicalWorkforce._id || '')) {
            doc.workforceProfile = canonicalWorkforce._id;
            summary.workforceReassigned += 1;
            changed = true;
        }

        applyCanonicalText(doc, 'workLineName', maps.workLines, workLineId);
        applyCanonicalText(doc, 'personnelTypeName', maps.personnelTypes, personnelTypeId);
        applyCanonicalText(doc, 'orgGroupName', maps.orgGroups, orgGroupId);
        applyCanonicalText(doc, 'orgUnitName', maps.orgUnits, orgUnitId);
        applyCanonicalText(doc, 'orgSubUnitName', maps.subUnits, subUnitId);
        applyCanonicalText(doc, 'degreeLevelName', maps.degreeLevels, degreeLevelId);
        applyCanonicalText(doc, 'employmentStatusName', maps.employmentStatuses, employmentStatusId);
        applyCanonicalText(doc, 'academicTitle', maps.academicRanks, academicRankId);
        applyCanonicalText(doc, 'positionTitle', maps.positionTitles, positionTitleId);

        if (changed) {
            await doc.save();
            updateSummary(summary, 'positionUpdated', true);
        }
    }

    const identityDocs = await HrIdentityMaster.find({});
    for (const doc of identityDocs) {
        let changed = false;
        const orgGroupId = doc.orgGroup || resolveMasterId(maps.orgGroups, slugify(doc.orgGroupName));
        const orgUnitId = doc.orgUnitMaster || resolveMasterId(maps.orgUnits, normalizeOrgUnitKey(doc.orgGroupName, doc.orgUnitName));
        const subUnitId = doc.subUnitMaster || resolveMasterId(maps.subUnits, normalizeSubUnitKey(doc.orgGroupName, doc.orgUnitName, doc.subUnitName));
        const degreeLevelId = doc.degreeLevelMaster || resolveMasterId(maps.degreeLevels, slugify(doc.degreeLevelName));
        const employmentStatusId = doc.employmentStatusMaster || resolveMasterId(maps.employmentStatuses, slugify(doc.employmentStatusName));
        const workLineId = doc.workLine || resolveMasterId(maps.workLines, slugify(doc.workLineName));
        const personnelTypeId = doc.personnelType || resolveMasterId(maps.personnelTypes, slugify(doc.personnelTypeName));
        const academicRankId = doc.academicRank || resolveMasterId(maps.academicRanks, slugify(doc.academicTitle));
        const positionTitleId = doc.positionTitleMaster || resolveMasterId(maps.positionTitles, slugify(doc.positionTitle));
        const nextOrgPath = compactStringArray(doc.orgPath);

        if (String(doc.orgGroup || '') !== String(orgGroupId || '')) { doc.orgGroup = orgGroupId; changed = true; }
        if (String(doc.orgUnitMaster || '') !== String(orgUnitId || '')) { doc.orgUnitMaster = orgUnitId; changed = true; }
        if (String(doc.subUnitMaster || '') !== String(subUnitId || '')) { doc.subUnitMaster = subUnitId; changed = true; }
        if (String(doc.degreeLevelMaster || '') !== String(degreeLevelId || '')) { doc.degreeLevelMaster = degreeLevelId; changed = true; }
        if (String(doc.employmentStatusMaster || '') !== String(employmentStatusId || '')) { doc.employmentStatusMaster = employmentStatusId; changed = true; }
        if (String(doc.workLine || '') !== String(workLineId || '')) { doc.workLine = workLineId; changed = true; }
        if (String(doc.personnelType || '') !== String(personnelTypeId || '')) { doc.personnelType = personnelTypeId; changed = true; }
        if (String(doc.academicRank || '') !== String(academicRankId || '')) { doc.academicRank = academicRankId; changed = true; }
        if (String(doc.positionTitleMaster || '') !== String(positionTitleId || '')) { doc.positionTitleMaster = positionTitleId; changed = true; }
        if (JSON.stringify(doc.orgPath || []) !== JSON.stringify(nextOrgPath)) { doc.orgPath = nextOrgPath; changed = true; }

        const exactWorkforceKey = buildWorkforceKey(doc);
        const fallbackWorkforceKey = buildWorkforceFallbackKey(doc);
        const canonicalWorkforce = (exactWorkforceKey && workforceMap.get(exactWorkforceKey))
            || (fallbackWorkforceKey && workforceFallbackMap.get(fallbackWorkforceKey))
            || null;
        if (canonicalWorkforce && String(doc.workforceProfile || '') !== String(canonicalWorkforce._id || '')) {
            doc.workforceProfile = canonicalWorkforce._id;
            summary.workforceReassigned += 1;
            changed = true;
        }

        applyCanonicalText(doc, 'degreeLevelName', maps.degreeLevels, degreeLevelId);
        applyCanonicalText(doc, 'employmentStatusName', maps.employmentStatuses, employmentStatusId);
        applyCanonicalText(doc, 'workLineName', maps.workLines, workLineId);
        applyCanonicalText(doc, 'personnelTypeName', maps.personnelTypes, personnelTypeId);
        applyCanonicalText(doc, 'academicTitle', maps.academicRanks, academicRankId);
        applyCanonicalText(doc, 'positionTitle', maps.positionTitles, positionTitleId);
        applyCanonicalText(doc, 'orgGroupName', maps.orgGroups, orgGroupId);
        applyCanonicalText(doc, 'orgUnitName', maps.orgUnits, orgUnitId);
        applyCanonicalText(doc, 'subUnitName', maps.subUnits, subUnitId);

        const nextFullName = [normalizeString(doc.prefix), normalizeString(doc.firstName), normalizeString(doc.lastName)].filter(Boolean).join(' ').trim() || null;
        if (doc.fullName !== nextFullName) { doc.fullName = nextFullName; changed = true; }

        if (changed) {
            await doc.save();
            updateSummary(summary, 'identityUpdated', true);
        }
    }

    const legacyWorkforceDocs = await HrWorkforceMaster.find({
        $or: [
            { personnelTypeCode: null },
            { personnelTypeCode: '' },
            { orgGroupName: null },
            { orgGroupName: '' }
        ]
    });
    for (const doc of legacyWorkforceDocs) {
        const positionRefs = await HrPositionMaster.countDocuments({ workforceProfile: doc._id });
        const identityRefs = await HrIdentityMaster.countDocuments({ workforceProfile: doc._id });
        if (!positionRefs && !identityRefs && doc.isActive !== false) {
            doc.isActive = false;
            await doc.save();
            summary.workforceDeactivated += 1;
        }
    }

    return summary;
}

module.exports = {
    cleanupHrDatabase
};
