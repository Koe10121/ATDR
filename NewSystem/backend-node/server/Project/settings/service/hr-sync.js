'use strict';

const HrOrgUnit = require('../models/hr_org_unit.model');
const HrOrgGroupMaster = require('../models/hr_org_group_master.model');
const HrOrgUnitMaster = require('../models/hr_org_unit_master.model');
const HrSubUnitMaster = require('../models/hr_sub_unit_master.model');
const HrDegreeLevelMaster = require('../models/hr_degree_level_master.model');
const HrEmploymentStatusMaster = require('../models/hr_employment_status_master.model');
const HrWorkLineMaster = require('../models/hr_work_line_master.model');
const HrPersonnelTypeMaster = require('../models/hr_personnel_type_master.model');
const HrAcademicRankMaster = require('../models/hr_academic_rank_master.model');
const HrPositionTitleMaster = require('../models/hr_position_title_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrWorkforceMaster = require('../models/hr_workforce_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const HrSyncRun = require('../models/hr_sync_run.model');
const Account = require('../../accounts/models/account.model');
const { splitLifecycleStorage } = require('../../accounts/service/lifecycle-boundary');
const { ensureLifecycleMasterData, loadLifecycleCatalog, buildCatalogIndex } = require('./lifecycle-master');
const { buildOrgPath, normalizeString, parseDate, slugify, toLangArray } = require('./hr_shared');
const { ensureAccountStatusMasterData, toObjectId } = require('../../accounts/service/account-status');

function toArrayTitle(thValue, enValue) {
    return toLangArray({
        th: normalizeString(thValue) || null,
        en: normalizeString(enValue) || null
    });
}

function buildMasterKey(code, title) {
    return [normalizeString(code), slugify(title)].filter(Boolean).join(':');
}

function buildMasterLookup(code, title, key) {
    const conditions = [];
    if (key) conditions.push({ key: key });
    if (normalizeString(code)) conditions.push({ code: normalizeString(code) });
    if (normalizeString(title)) conditions.push({ 'title.value': normalizeString(title) });
    return conditions.length > 1 ? { $or: conditions } : (conditions[0] || { key: key });
}

function isOpenStatus(status) {
    const value = normalizeString(status).toUpperCase();
    return value.startsWith('O') || value.indexOf('OPEN') !== -1 || value.indexOf('เปิด') !== -1;
}

function normalizeHrRow(row) {
    const values = Array.isArray(row) ? row : [];
    return {
        positionCode: normalizeString(values[0]),
        positionStatus: normalizeString(values[1]),
        personnelCode: normalizeString(values[2]),
        positionTitle: normalizeString(values[3]),
        academicTitle: normalizeString(values[4]),
        workLineCode: normalizeString(values[5]),
        workLineName: normalizeString(values[6]),
        personnelTypeCode: normalizeString(values[7]),
        personnelTypeName: normalizeString(values[8]),
        orgGroupName: normalizeString(values[9]),
        orgUnitCode: normalizeString(values[10]),
        orgUnitName: normalizeString(values[11]),
        hireDate: parseDate(values[12]),
        contractEndDate: parseDate(values[13]),
        gender: normalizeString(values[14]),
        age: normalizeString(values[15]),
        degreeLevelCode: normalizeString(values[16]),
        degreeLevelName: normalizeString(values[17]),
        generation: normalizeString(values[18]),
        tenureGroup: normalizeString(values[19]),
        province: normalizeString(values[20]),
        tenureYears: normalizeString(values[21]),
        employmentStatusCode: normalizeString(values[22]),
        employmentStatusName: normalizeString(values[23]),
        subUnitName: normalizeString(values[24]),
        remarks: normalizeString(values[25]),
        budgetYear: normalizeString(values[26]),
        sourceTimestamp: parseDate(values[27]),
        previousHolder: normalizeString(values[28]),
        prefix: normalizeString(values[29]),
        firstName: normalizeString(values[30]),
        lastName: normalizeString(values[31])
    };
}

function deriveAffiliationKey(row) {
    const joined = [
        row.positionTitle,
        row.academicTitle,
        row.workLineName,
        row.personnelTypeName,
        row.orgGroupName,
        row.orgUnitName,
        row.employmentStatusName
    ].join(' ').toLowerCase();

    if (joined.indexOf('student') !== -1 || joined.indexOf('นักศึกษา') !== -1) return 'STUDENT';
    if (joined.indexOf('alumni') !== -1 || joined.indexOf('ศิษย์เก่า') !== -1) return 'ALUMNI';
    if (joined.indexOf('contractor') !== -1 || joined.indexOf('vendor') !== -1 || joined.indexOf('ผู้รับจ้าง') !== -1) return 'CONTRACTOR';
    if (
        joined.indexOf('รองอธิการ') !== -1 ||
        joined.indexOf('ผู้ช่วยอธิการ') !== -1 ||
        joined.indexOf('คณบดี') !== -1 ||
        joined.indexOf('director') !== -1 ||
        joined.indexOf('executive') !== -1 ||
        joined.indexOf('บริหาร') !== -1
    ) return 'EXECUTIVE';
    if (
        normalizeString(row.academicTitle) ||
        joined.indexOf('วิชาการ') !== -1 ||
        joined.indexOf('lecturer') !== -1 ||
        joined.indexOf('อาจารย์') !== -1 ||
        joined.indexOf('research') !== -1 ||
        joined.indexOf('นักวิจัย') !== -1
    ) return 'ACADEMIC';
    if (joined.indexOf('external') !== -1 || joined.indexOf('ภายนอก') !== -1) return 'EXTERNAL';
    return 'OPERATIONAL';
}

function buildWorkforceKey(row) {
    return [
        row.workLineCode || slugify(row.workLineName),
        row.personnelTypeCode || slugify(row.personnelTypeName),
        slugify(row.orgGroupName || 'general')
    ].filter(Boolean).join(':');
}

function buildAccountCreatePayload(row, statusId, lifecycle, hrContext) {
    return {
        dateTime: new Date(),
        code: row.personnelCode || null,
        email: null,
        authen: row.personnelCode ? [{
            username: row.personnelCode,
            password: null,
            email: null,
            oAtuhToken: null
        }] : [],
        userinfo: {
            prefix: row.prefix ? toLangArray({ th: row.prefix }) : [],
            firstName: row.firstName ? toLangArray({ th: row.firstName }) : [],
            lastName: row.lastName ? toLangArray({ th: row.lastName }) : [],
            image: null,
            cardId: null,
            birthday: null,
            msisdn: null,
            lineId: null,
            religion: null
        },
        control: {
            sso: false,
            limit: 4,
            trustedDevices: [],
            device: []
        },
        verification: [],
        lifecycle: lifecycle || {},
        hrContext: hrContext || {},
        status: statusId || null
    };
}

async function ensureSeparatedMasters(row) {
    const orgGroupTitle = normalizeString(row.orgGroupName);
    const orgUnitTitle = normalizeString(row.orgUnitName);
    const subUnitTitle = normalizeString(row.subUnitName);
    const degreeTitle = normalizeString(row.degreeLevelName);
    const employmentTitle = normalizeString(row.employmentStatusName);
    const workLineTitle = normalizeString(row.workLineName);
    const personnelTypeTitle = normalizeString(row.personnelTypeName);
    const academicRankTitle = normalizeString(row.academicTitle);
    const positionTitle = normalizeString(row.positionTitle);

    const orgGroup = orgGroupTitle
        ? await HrOrgGroupMaster.findOneAndUpdate(
            { key: slugify(orgGroupTitle) },
            {
                key: slugify(orgGroupTitle),
                title: toLangArray({ th: orgGroupTitle }),
                description: toLangArray({ th: 'HR org group imported from workforce source data', en: 'HR org group imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const orgUnit = orgUnitTitle
        ? await HrOrgUnitMaster.findOneAndUpdate(
            { key: [orgGroupTitle ? slugify(orgGroupTitle) : '', slugify(orgUnitTitle)].filter(Boolean).join(':') },
            {
                key: [orgGroupTitle ? slugify(orgGroupTitle) : '', slugify(orgUnitTitle)].filter(Boolean).join(':'),
                code: row.orgUnitCode || null,
                title: toLangArray({ th: orgUnitTitle }),
                description: toLangArray({ th: [orgGroupTitle || null, row.orgUnitCode ? ('HR code ' + row.orgUnitCode) : null].filter(Boolean).join(' | ') || null }),
                orgGroup: orgGroup ? orgGroup._id : null,
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const subUnit = subUnitTitle
        ? await HrSubUnitMaster.findOneAndUpdate(
            { key: [orgGroupTitle ? slugify(orgGroupTitle) : '', orgUnitTitle ? slugify(orgUnitTitle) : '', slugify(subUnitTitle)].filter(Boolean).join(':') },
            {
                key: [orgGroupTitle ? slugify(orgGroupTitle) : '', orgUnitTitle ? slugify(orgUnitTitle) : '', slugify(subUnitTitle)].filter(Boolean).join(':'),
                title: toLangArray({ th: subUnitTitle }),
                description: toLangArray({ th: [orgGroupTitle || null, orgUnitTitle || null].filter(Boolean).join(' | ') || null }),
                orgGroup: orgGroup ? orgGroup._id : null,
                orgUnit: orgUnit ? orgUnit._id : null,
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const degreeLevel = degreeTitle
        ? await HrDegreeLevelMaster.findOneAndUpdate(
            buildMasterLookup(row.degreeLevelCode, degreeTitle, buildMasterKey(row.degreeLevelCode, degreeTitle) || slugify(degreeTitle)),
            {
                key: buildMasterKey(row.degreeLevelCode, degreeTitle) || slugify(degreeTitle),
                code: row.degreeLevelCode || null,
                title: toLangArray({ th: degreeTitle }),
                description: toLangArray({ th: row.degreeLevelCode ? ('HR degree level code ' + row.degreeLevelCode) : 'HR degree level imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const employmentStatus = employmentTitle
        ? await HrEmploymentStatusMaster.findOneAndUpdate(
            buildMasterLookup(row.employmentStatusCode, employmentTitle, buildMasterKey(row.employmentStatusCode, employmentTitle) || slugify(employmentTitle)),
            {
                key: buildMasterKey(row.employmentStatusCode, employmentTitle) || slugify(employmentTitle),
                code: row.employmentStatusCode || null,
                title: toLangArray({ th: employmentTitle }),
                description: toLangArray({ th: row.employmentStatusCode ? ('HR employment status code ' + row.employmentStatusCode) : 'HR employment status imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const workLine = workLineTitle
        ? await HrWorkLineMaster.findOneAndUpdate(
            buildMasterLookup(row.workLineCode, workLineTitle, buildMasterKey(row.workLineCode, workLineTitle) || slugify(workLineTitle)),
            {
                key: buildMasterKey(row.workLineCode, workLineTitle) || slugify(workLineTitle),
                code: row.workLineCode || null,
                title: toLangArray({ th: workLineTitle }),
                description: toLangArray({ th: row.workLineCode ? ('HR work line code ' + row.workLineCode) : 'HR work line imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const personnelType = personnelTypeTitle
        ? await HrPersonnelTypeMaster.findOneAndUpdate(
            buildMasterLookup(row.personnelTypeCode, personnelTypeTitle, buildMasterKey(row.personnelTypeCode, personnelTypeTitle) || slugify(personnelTypeTitle)),
            {
                key: buildMasterKey(row.personnelTypeCode, personnelTypeTitle) || slugify(personnelTypeTitle),
                code: row.personnelTypeCode || null,
                title: toLangArray({ th: personnelTypeTitle }),
                description: toLangArray({ th: row.personnelTypeCode ? ('HR personnel type code ' + row.personnelTypeCode) : 'HR personnel type imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const academicRank = academicRankTitle
        ? await HrAcademicRankMaster.findOneAndUpdate(
            { key: slugify(academicRankTitle) },
            {
                key: slugify(academicRankTitle),
                title: toLangArray({ th: academicRankTitle }),
                description: toLangArray({ th: 'HR academic rank imported from workforce source data', en: 'HR academic rank imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    const positionTitleMaster = positionTitle
        ? await HrPositionTitleMaster.findOneAndUpdate(
            { key: slugify(positionTitle) },
            {
                key: slugify(positionTitle),
                title: toLangArray({ th: positionTitle }),
                description: toLangArray({ th: row.positionCode ? ('HR position title mapped from position code ' + row.positionCode) : 'HR position title imported from workforce source data' }),
                source: 'HR_IMPORT',
                isActive: true
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        )
        : null;

    return { orgGroup, orgUnit, subUnit, degreeLevel, employmentStatus, workLine, personnelType, academicRank, positionTitleMaster };
}

function buildLifecycleFromHrRow(row, affiliationId, currentLifecycle) {
    const orgPath = buildOrgPath(row);
    const lifecycle = Object.assign({}, currentLifecycle || {});
    const currentAffiliations = Array.isArray(lifecycle.affiliations) ? lifecycle.affiliations.slice() : [];
    const currentPositions = Array.isArray(lifecycle.positions) ? lifecycle.positions.slice() : [];
    const currentMovements = Array.isArray(lifecycle.movements) ? lifecycle.movements.slice() : [];
    const currentDevelopments = Array.isArray(lifecycle.developments) ? lifecycle.developments.slice() : [];

    const nextPosition = {
        code: row.positionCode || null,
        title: row.positionTitle || null,
        type: 'POSITION',
        orgPath: orgPath,
        startDate: row.hireDate || null,
        endDate: row.contractEndDate || null,
        isActing: false
    };

    const nextAffiliation = {
        type: affiliationId || null,
        category: row.personnelTypeName || null,
        orgPath: orgPath,
        orgCode: row.orgUnitCode || null,
        title: row.positionTitle || null,
        startDate: row.hireDate || null,
        endDate: row.contractEndDate || null,
        source: 'HR_IMPORT',
        status: isOpenStatus(row.positionStatus) ? 'ACTIVE' : 'INACTIVE',
        isPrimary: true
    };

    const previousPosition = currentPositions[0] || null;
    const previousPath = Array.isArray(previousPosition && previousPosition.orgPath) ? previousPosition.orgPath.join('|') : '';
    const nextPath = orgPath.join('|');
    if (previousPosition && ((previousPosition.title || '') !== (nextPosition.title || '') || previousPath !== nextPath)) {
        const duplicateMovement = currentMovements.some(function (item) {
            return normalizeString(item && item.toTitle) === normalizeString(nextPosition.title)
                && normalizeString((item && item.toOrgPath || []).join('|')) === nextPath;
        });
        if (!duplicateMovement) {
            currentMovements.unshift({
                type: previousPath !== nextPath ? 'TRANSFER' : 'POSITION_CHANGE',
                fromTitle: previousPosition.title || null,
                toTitle: nextPosition.title || null,
                fromOrgPath: previousPosition.orgPath || [],
                toOrgPath: orgPath,
                effectiveDate: row.sourceTimestamp || row.hireDate || new Date(),
                reason: 'HR_SYNC',
                referenceNo: row.positionCode || null,
                approvedBy: 'HR_IMPORT',
                impact: 'ACCESS_REVIEW',
                status: 'COMPLETED'
            });
        }
    }

    if (row.hireDate) {
        const onboardingExists = currentDevelopments.some(function (item) {
            return normalizeString(item && item.type) === 'ONBOARDING' && normalizeString(item && item.title) === 'HR Baseline';
        });
        if (!onboardingExists) {
            currentDevelopments.unshift({
                type: 'ONBOARDING',
                title: 'HR Baseline',
                provider: 'HR_IMPORT',
                startDate: row.hireDate,
                endDate: row.hireDate,
                status: 'COMPLETED',
                outcome: row.employmentStatusName || null,
                credential: null,
                hours: null,
                linkedLeaveType: null,
                remarks: 'Auto-generated from HR sync'
            });
        }
    }

    lifecycle.primaryAffiliation = affiliationId || null;
    lifecycle.affiliations = [nextAffiliation].concat(currentAffiliations.filter(function (item) {
        return normalizeString(item && item.source) !== 'HR_IMPORT';
    }));
    lifecycle.positions = [nextPosition].concat(currentPositions.filter(function (item) {
        return normalizeString(item && item.code) !== normalizeString(nextPosition.code);
    }));
    lifecycle.movements = currentMovements.slice(0, 25);
    lifecycle.developments = currentDevelopments.slice(0, 25);
    lifecycle.provisioning = Object.assign({}, lifecycle.provisioning || {}, {
        joinerDate: lifecycle.provisioning && lifecycle.provisioning.joinerDate ? lifecycle.provisioning.joinerDate : (row.hireDate || null),
        moverDate: currentMovements.length ? currentMovements[0].effectiveDate : (lifecycle.provisioning && lifecycle.provisioning.moverDate ? lifecycle.provisioning.moverDate : null),
        lastSyncSource: 'HR_IMPORT',
        lastEvaluatedAt: new Date()
    });
    lifecycle.hrSnapshot = {
        positionCode: row.positionCode || null,
        personnelCode: row.personnelCode || null,
        positionStatus: row.positionStatus || null,
        employmentStatus: row.employmentStatusName || null,
        workLineCode: row.workLineCode || null,
        workLineName: row.workLineName || null,
        personnelTypeName: row.personnelTypeName || null,
        orgGroupName: row.orgGroupName || null,
        orgUnitCode: row.orgUnitCode || null,
        orgUnitName: row.orgUnitName || null,
        subUnitName: row.subUnitName || null,
        hireDate: row.hireDate || null,
        contractEndDate: row.contractEndDate || null,
        sourceTimestamp: row.sourceTimestamp || null,
        lastSyncedAt: new Date()
    };
    return lifecycle;
}

async function ensureOrgUnits(row) {
    const titles = [row.orgGroupName, row.orgUnitName, row.subUnitName].map(normalizeString).filter(Boolean);
    const typeByLevel = ['group', 'unit', 'subunit'];
    const docs = [];
    let parent = null;
    let pathKeys = [];
    let pathTitles = [];

    for (let index = 0; index < titles.length; index += 1) {
        const title = titles[index];
        const key = pathKeys.concat(slugify(title)).filter(Boolean).join('/');
        pathKeys = pathKeys.concat(slugify(title));
        pathTitles = pathTitles.concat(title);
        const payload = {
            key: key,
            code: index === 1 ? (row.orgUnitCode || null) : null,
            title: toArrayTitle(title, ''),
            type: typeByLevel[index] || 'unit',
            level: index,
            parent: parent ? parent._id : null,
            pathKeys: pathKeys,
            pathTitles: pathTitles,
            source: 'HR_IMPORT',
            isActive: true
        };
        const doc = await HrOrgUnit.findOneAndUpdate({ key: key }, payload, { new: true, upsert: true, setDefaultsOnInsert: true });
        docs.push(doc);
        parent = doc;
    }

    return docs;
}

async function syncHrRows(rows, options) {
    const sourceFile = options && options.sourceFile ? String(options.sourceFile) : null;
    const sourceSheet = options && options.sourceSheet ? String(options.sourceSheet) : 'HRAutoUpdate';
    const autoCreateAccounts = !!(options && options.autoCreateAccounts);
    await ensureLifecycleMasterData();
    const catalog = await loadLifecycleCatalog();
    const index = buildCatalogIndex(catalog);
    const statusMaster = await ensureAccountStatusMasterData();
    const activeStatus = statusMaster && statusMaster.statuses ? statusMaster.statuses.ACTIVE : null;
    const summary = {
        rowCount: 0,
        orgUnitCount: 0,
        workforceCount: 0,
        positionCount: 0,
        identityCount: 0,
        createdAccountCount: 0,
        updatedAccountCount: 0,
        linkedIdentityCount: 0,
        matchedAccountCount: 0,
        unmatchedAccountCount: 0,
        warnings: []
    };

    for (const rawRow of rows || []) {
        const row = normalizeHrRow(rawRow);
        if (!row.positionCode && !row.personnelCode && !row.positionTitle) continue;
        summary.rowCount += 1;

        const orgDocs = await ensureOrgUnits(row);
        const separatedMasters = await ensureSeparatedMasters(row);
        summary.orgUnitCount += orgDocs.length ? 0 : 0;

        const affiliationKey = deriveAffiliationKey(row);
        const affiliation = index.affiliationByKey[affiliationKey];
        if (!affiliation) {
            summary.warnings.push('Missing lifecycle affiliation master for ' + affiliationKey + ' at row ' + summary.rowCount);
            continue;
        }

        const workforcePayload = {
            key: buildWorkforceKey(row),
            workLineCode: row.workLineCode || null,
            workLineName: row.workLineName || null,
            workLine: separatedMasters.workLine ? separatedMasters.workLine._id : null,
            personnelTypeCode: row.personnelTypeCode || null,
            personnelTypeName: row.personnelTypeName || null,
            personnelType: separatedMasters.personnelType ? separatedMasters.personnelType._id : null,
            orgGroupName: row.orgGroupName || null,
            orgGroup: separatedMasters.orgGroup ? separatedMasters.orgGroup._id : null,
            employmentStatus: row.employmentStatusName || null,
            employmentStatusMaster: separatedMasters.employmentStatus ? separatedMasters.employmentStatus._id : null,
            suggestedAffiliation: affiliation._id,
            source: 'HR_IMPORT',
            isActive: true
        };
        const workforce = await HrWorkforceMaster.findOneAndUpdate(
            { key: workforcePayload.key },
            workforcePayload,
            { new: true, upsert: true, setDefaultsOnInsert: true }
        );

        const positionPayload = {
            positionCode: row.positionCode || null,
            positionStatus: row.positionStatus || null,
            positionTitle: row.positionTitle || null,
            academicTitle: row.academicTitle || null,
            workLineCode: row.workLineCode || null,
            workLineName: row.workLineName || null,
            workLine: separatedMasters.workLine ? separatedMasters.workLine._id : null,
            personnelTypeCode: row.personnelTypeCode || null,
            personnelTypeName: row.personnelTypeName || null,
            personnelType: separatedMasters.personnelType ? separatedMasters.personnelType._id : null,
            orgGroupName: row.orgGroupName || null,
            orgGroup: separatedMasters.orgGroup ? separatedMasters.orgGroup._id : null,
            orgUnitCode: row.orgUnitCode || null,
            orgUnitName: row.orgUnitName || null,
            orgUnitMaster: separatedMasters.orgUnit ? separatedMasters.orgUnit._id : null,
            orgSubUnitName: row.subUnitName || null,
            subUnitMaster: separatedMasters.subUnit ? separatedMasters.subUnit._id : null,
            orgPath: buildOrgPath(row),
            degreeLevelName: row.degreeLevelName || null,
            degreeLevelMaster: separatedMasters.degreeLevel ? separatedMasters.degreeLevel._id : null,
            employmentStatusName: row.employmentStatusName || null,
            employmentStatusMaster: separatedMasters.employmentStatus ? separatedMasters.employmentStatus._id : null,
            academicRank: separatedMasters.academicRank ? separatedMasters.academicRank._id : null,
            positionTitleMaster: separatedMasters.positionTitleMaster ? separatedMasters.positionTitleMaster._id : null,
            workforceProfile: workforce ? workforce._id : null,
            orgUnit: orgDocs.length ? orgDocs[orgDocs.length - 1]._id : null,
            suggestedAffiliation: affiliation._id,
            isOpen: isOpenStatus(row.positionStatus),
            source: 'HR_IMPORT'
        };
        const positionMaster = await HrPositionMaster.findOneAndUpdate(
            { positionCode: positionPayload.positionCode },
            positionPayload,
            { new: true, upsert: true, setDefaultsOnInsert: true }
        );

        const identityKey = row.personnelCode || ('VACANCY:' + (row.positionCode || summary.rowCount));
        const identityMaster = await HrIdentityMaster.findOneAndUpdate(
            { identityKey: identityKey },
            {
                identityKey: identityKey,
                personnelCode: row.personnelCode || null,
                positionCode: row.positionCode || null,
                prefix: row.prefix || null,
                firstName: row.firstName || null,
                lastName: row.lastName || null,
                fullName: [row.prefix, row.firstName, row.lastName].filter(Boolean).join(' ').trim() || null,
                gender: row.gender || null,
                age: row.age || null,
                degreeLevelName: row.degreeLevelName || null,
                degreeLevelMaster: separatedMasters.degreeLevel ? separatedMasters.degreeLevel._id : null,
                province: row.province || null,
                generation: row.generation || null,
                tenureGroup: row.tenureGroup || null,
                tenureYears: row.tenureYears || null,
                employmentStatusName: row.employmentStatusName || null,
                employmentStatusMaster: separatedMasters.employmentStatus ? separatedMasters.employmentStatus._id : null,
                workLineName: row.workLineName || null,
                workLine: separatedMasters.workLine ? separatedMasters.workLine._id : null,
                personnelTypeName: row.personnelTypeName || null,
                personnelType: separatedMasters.personnelType ? separatedMasters.personnelType._id : null,
                positionTitle: row.positionTitle || null,
                positionTitleMaster: separatedMasters.positionTitleMaster ? separatedMasters.positionTitleMaster._id : null,
                academicTitle: row.academicTitle || null,
                academicRank: separatedMasters.academicRank ? separatedMasters.academicRank._id : null,
                orgGroupName: row.orgGroupName || null,
                orgGroup: separatedMasters.orgGroup ? separatedMasters.orgGroup._id : null,
                orgUnitName: row.orgUnitName || null,
                orgUnitMaster: separatedMasters.orgUnit ? separatedMasters.orgUnit._id : null,
                subUnitName: row.subUnitName || null,
                subUnitMaster: separatedMasters.subUnit ? separatedMasters.subUnit._id : null,
                orgPath: buildOrgPath(row),
                workforceProfile: workforce ? workforce._id : null,
                positionMaster: positionMaster ? positionMaster._id : null,
                suggestedAffiliation: affiliation._id,
                linkedAccount: null,
                vacancy: !row.personnelCode,
                source: 'HR_IMPORT'
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        );

        const accountQuery = row.personnelCode ? { code: row.personnelCode } : null;
        let account = accountQuery ? await Account.findOne(accountQuery) : null;
        let createdAccount = false;
        if (!account && autoCreateAccounts && row.personnelCode) {
            const lifecycle = buildLifecycleFromHrRow(row, affiliation._id, {});
            const persisted = splitLifecycleStorage(lifecycle, {});
            const createPayload = buildAccountCreatePayload(row, activeStatus ? toObjectId(activeStatus._id) : null, persisted.lifecycle, persisted.hrContext);
            account = await Account.create(createPayload);
            summary.createdAccountCount += 1;
            createdAccount = true;
        }

        if (!account) {
            summary.unmatchedAccountCount += 1;
            continue;
        }

        account.code = row.personnelCode || account.code;
        account.userinfo = Object.assign({}, account.userinfo || {}, {
            prefix: row.prefix ? [{ key: 'th', value: row.prefix }] : (account.userinfo && account.userinfo.prefix) || [],
            firstName: row.firstName ? [{ key: 'th', value: row.firstName }] : (account.userinfo && account.userinfo.firstName) || [],
            lastName: row.lastName ? [{ key: 'th', value: row.lastName }] : (account.userinfo && account.userinfo.lastName) || [],
            birthday: account.userinfo && account.userinfo.birthday ? account.userinfo.birthday : null
        });
        const mergedLifecycle = buildLifecycleFromHrRow(row, affiliation._id, account.lifecycle || {});
        const persisted = splitLifecycleStorage(mergedLifecycle, account.hrContext || {});
        account.lifecycle = persisted.lifecycle;
        account.hrContext = persisted.hrContext;
        if (!account.status && activeStatus && activeStatus._id) {
            account.status = toObjectId(activeStatus._id);
        }
        await account.save();
        if (!createdAccount) {
            summary.updatedAccountCount += 1;
        }
        if (identityMaster && identityMaster._id) {
            await HrIdentityMaster.updateOne({ _id: identityMaster._id }, { linkedAccount: account._id });
            summary.linkedIdentityCount += 1;
        }
        summary.matchedAccountCount += 1;
    }

    summary.orgUnitCount = await HrOrgUnit.countDocuments({});
    summary.workforceCount = await HrWorkforceMaster.countDocuments({});
    summary.positionCount = await HrPositionMaster.countDocuments({});
    summary.identityCount = await HrIdentityMaster.countDocuments({});
    summary.orgGroupCount = await HrOrgGroupMaster.countDocuments({});
    summary.orgUnitMasterCount = await HrOrgUnitMaster.countDocuments({});
    summary.subUnitCount = await HrSubUnitMaster.countDocuments({});
    summary.degreeLevelCount = await HrDegreeLevelMaster.countDocuments({});
    summary.employmentStatusCount = await HrEmploymentStatusMaster.countDocuments({});
    summary.workLineCount = await HrWorkLineMaster.countDocuments({});
    summary.personnelTypeCount = await HrPersonnelTypeMaster.countDocuments({});
    summary.academicRankCount = await HrAcademicRankMaster.countDocuments({});
    summary.positionTitleCount = await HrPositionTitleMaster.countDocuments({});

    const syncRun = await HrSyncRun.create({
        sourceFile: sourceFile,
        sourceSheet: sourceSheet,
        sourceTimestamp: new Date(),
        status: 'COMPLETED',
        rowCount: summary.rowCount,
        orgUnitCount: summary.orgUnitCount,
        positionCount: summary.positionCount,
        workforceCount: summary.workforceCount,
        identityCount: summary.identityCount,
        orgGroupCount: summary.orgGroupCount,
        orgUnitMasterCount: summary.orgUnitMasterCount,
        subUnitCount: summary.subUnitCount,
        degreeLevelCount: summary.degreeLevelCount,
        employmentStatusCount: summary.employmentStatusCount,
        workLineCount: summary.workLineCount,
        personnelTypeCount: summary.personnelTypeCount,
        academicRankCount: summary.academicRankCount,
        positionTitleCount: summary.positionTitleCount,
        matchedAccountCount: summary.matchedAccountCount,
        unmatchedAccountCount: summary.unmatchedAccountCount,
        warnings: summary.warnings.slice(0, 200),
        summary: summary
    });

    summary.syncRunId = syncRun && syncRun._id ? String(syncRun._id) : null;
    return summary;
}

module.exports = {
    buildAccountCreatePayload,
    buildLifecycleFromHrRow,
    buildOrgPath,
    deriveAffiliationKey,
    normalizeHrRow,
    syncHrRows
};
