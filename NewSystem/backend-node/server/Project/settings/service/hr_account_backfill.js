'use strict';

const Account = require('../../accounts/models/account.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { ensureAccountStatusMasterData, toObjectId } = require('../../accounts/service/account-status');
const { buildAccountCreatePayload, buildLifecycleFromHrRow } = require('./hr-sync');
const { splitLifecycleStorage } = require('../../accounts/service/lifecycle-boundary');

function buildRowFromIdentity(identity) {
    const position = identity && identity.positionMaster && typeof identity.positionMaster === 'object' ? identity.positionMaster : null;
    const orgPath = Array.isArray(identity && identity.orgPath) ? identity.orgPath : (Array.isArray(position && position.orgPath) ? position.orgPath : []);
    return {
        positionCode: identity && identity.positionCode ? String(identity.positionCode) : (position && position.positionCode ? String(position.positionCode) : null),
        positionStatus: position && position.positionStatus ? String(position.positionStatus) : 'O : เปิด',
        personnelCode: identity && identity.personnelCode ? String(identity.personnelCode) : null,
        positionTitle: identity && identity.positionTitle ? String(identity.positionTitle) : (position && position.positionTitle ? String(position.positionTitle) : null),
        academicTitle: identity && identity.academicTitle ? String(identity.academicTitle) : '',
        workLineCode: identity && identity.workLine && identity.workLine.code ? String(identity.workLine.code) : null,
        workLineName: identity && identity.workLineName ? String(identity.workLineName) : (identity && identity.workLine && identity.workLine.titleText ? String(identity.workLine.titleText) : null),
        personnelTypeCode: identity && identity.personnelType && identity.personnelType.code ? String(identity.personnelType.code) : null,
        personnelTypeName: identity && identity.personnelTypeName ? String(identity.personnelTypeName) : (identity && identity.personnelType && identity.personnelType.titleText ? String(identity.personnelType.titleText) : null),
        orgGroupName: identity && identity.orgGroupName ? String(identity.orgGroupName) : (identity && identity.orgGroup && identity.orgGroup.titleText ? String(identity.orgGroup.titleText) : null),
        orgUnitCode: identity && identity.orgUnitMaster && identity.orgUnitMaster.code ? String(identity.orgUnitMaster.code) : null,
        orgUnitName: identity && identity.orgUnitName ? String(identity.orgUnitName) : (identity && identity.orgUnitMaster && identity.orgUnitMaster.titleText ? String(identity.orgUnitMaster.titleText) : null),
        hireDate: null,
        contractEndDate: null,
        gender: identity && identity.gender ? String(identity.gender) : null,
        age: identity && identity.age ? String(identity.age) : null,
        degreeLevelCode: identity && identity.degreeLevelMaster && identity.degreeLevelMaster.code ? String(identity.degreeLevelMaster.code) : null,
        degreeLevelName: identity && identity.degreeLevelName ? String(identity.degreeLevelName) : (identity && identity.degreeLevelMaster && identity.degreeLevelMaster.titleText ? String(identity.degreeLevelMaster.titleText) : null),
        generation: identity && identity.generation ? String(identity.generation) : null,
        tenureGroup: identity && identity.tenureGroup ? String(identity.tenureGroup) : null,
        province: identity && identity.province ? String(identity.province) : null,
        tenureYears: identity && identity.tenureYears ? String(identity.tenureYears) : null,
        employmentStatusCode: identity && identity.employmentStatusMaster && identity.employmentStatusMaster.code ? String(identity.employmentStatusMaster.code) : null,
        employmentStatusName: identity && identity.employmentStatusName ? String(identity.employmentStatusName) : (identity && identity.employmentStatusMaster && identity.employmentStatusMaster.titleText ? String(identity.employmentStatusMaster.titleText) : null),
        subUnitName: identity && identity.subUnitName ? String(identity.subUnitName) : (orgPath[2] || null),
        remarks: 'HR_ACCOUNT_BACKFILL',
        budgetYear: null,
        sourceTimestamp: new Date(),
        previousHolder: null,
        prefix: identity && identity.prefix ? String(identity.prefix) : null,
        firstName: identity && identity.firstName ? String(identity.firstName) : null,
        lastName: identity && identity.lastName ? String(identity.lastName) : null
    };
}

async function backfillAccountsFromHrIdentities(options) {
    const limit = options && options.limit ? Number(options.limit) : 0;
    const statusMaster = await ensureAccountStatusMasterData();
    const activeStatus = statusMaster && statusMaster.statuses ? statusMaster.statuses.ACTIVE : null;
    const query = {
        vacancy: false,
        personnelCode: { $nin: [null, ''] }
    };

    const identitiesQuery = HrIdentityMaster.find(query)
        .populate('degreeLevelMaster', 'code title titleText')
        .populate('employmentStatusMaster', 'code title titleText')
        .populate('workLine', 'code title titleText')
        .populate('personnelType', 'code title titleText')
        .populate('orgGroup', 'title titleText')
        .populate('orgUnitMaster', 'code title titleText')
        .populate('subUnitMaster', 'title titleText')
        .populate('positionMaster', 'positionCode positionStatus positionTitle orgPath')
        .populate('suggestedAffiliation', 'key');

    if (limit > 0) identitiesQuery.limit(limit);
    const identities = await identitiesQuery.exec();

    const summary = {
        identityCount: identities.length,
        createdAccountCount: 0,
        linkedExistingAccountCount: 0,
        alreadyLinkedCount: 0,
        skippedCount: 0,
        warnings: []
    };

    for (const identity of identities) {
        if (!identity || !identity.personnelCode) {
            summary.skippedCount += 1;
            continue;
        }
        if (identity.linkedAccount) {
            summary.alreadyLinkedCount += 1;
            continue;
        }

        let account = await Account.findOne({ code: identity.personnelCode });
        if (account) {
            await HrIdentityMaster.updateOne({ _id: identity._id }, { linkedAccount: account._id });
            summary.linkedExistingAccountCount += 1;
            continue;
        }

        const row = buildRowFromIdentity(identity);
        const lifecycle = buildLifecycleFromHrRow(row, identity.suggestedAffiliation ? identity.suggestedAffiliation._id : null, {});
        const persisted = splitLifecycleStorage(lifecycle, {});
        const payload = buildAccountCreatePayload(row, activeStatus ? toObjectId(activeStatus._id) : null, persisted.lifecycle, persisted.hrContext);
        account = await Account.create(payload);
        await HrIdentityMaster.updateOne({ _id: identity._id }, { linkedAccount: account._id });
        summary.createdAccountCount += 1;
    }

    return summary;
}

module.exports = {
    backfillAccountsFromHrIdentities,
    buildRowFromIdentity
};
