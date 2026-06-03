'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../../../../config/config');
const hrOrgGroupService = require('./hr_org_group_master');
const hrOrgUnitService = require('./hr_org_unit_master');
const { syncHrRows } = require('./hr-sync');
const { buildPreview, buildPreviewReport } = require('./hr_sync_runner');

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
const { backfillAccountsFromHrIdentities } = require('./hr_account_backfill');

let connected = false;

function mockResponse() {
    return {
        statusCode: 200,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(payload) {
            this.body = payload;
            return this;
        }
    };
}

async function ensureConnection() {
    if (connected) return;
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
    connected = true;
}

async function cleanupBySuffix(suffix) {
    const regex = new RegExp(suffix);
    await Account.deleteMany({ code: regex });
    await HrIdentityMaster.deleteMany({
        $or: [
            { identityKey: regex },
            { personnelCode: regex },
            { positionCode: regex }
        ]
    });
    await HrPositionMaster.deleteMany({
        $or: [
            { positionCode: regex },
            { positionTitle: regex }
        ]
    });
    await HrWorkforceMaster.deleteMany({
        $or: [
            { key: regex },
            { workLineName: regex },
            { personnelTypeName: regex },
            { orgGroupName: regex }
        ]
    });
    await HrOrgUnitMaster.deleteMany({ key: regex });
    await HrSubUnitMaster.deleteMany({ key: regex });
    await HrOrgGroupMaster.deleteMany({ $or: [{ key: regex }, { 'title.value': regex }] });
    await HrDegreeLevelMaster.deleteMany({ $or: [{ key: regex }, { code: regex }, { 'title.value': regex }] });
    await HrEmploymentStatusMaster.deleteMany({ $or: [{ key: regex }, { code: regex }, { 'title.value': regex }] });
    await HrWorkLineMaster.deleteMany({ $or: [{ key: regex }, { code: regex }, { 'title.value': regex }] });
    await HrPersonnelTypeMaster.deleteMany({ $or: [{ key: regex }, { code: regex }, { 'title.value': regex }] });
    await HrAcademicRankMaster.deleteMany({ $or: [{ key: regex }, { 'title.value': regex }] });
    await HrPositionTitleMaster.deleteMany({ $or: [{ key: regex }, { 'title.value': regex }] });
    await HrSyncRun.deleteMany({ sourceFile: regex });
}

test.before(async function () {
    await ensureConnection();
});

test.after(async function () {
    if (connected) {
        await mongoose.disconnect();
    }
});

test('HR master services support create, update, delete, and dependency protection', async function () {
    const suffix = `test-${Date.now()}`;
    await cleanupBySuffix(suffix);

    const createGroupRes = mockResponse();
    await hrOrgGroupService.onCreate({
        body: {
            key: `org-group-${suffix}`,
            title: [{ key: 'th', value: `กลุ่มทดสอบ ${suffix}` }],
            description: [{ key: 'th', value: 'สร้างจาก automated test' }],
            source: 'MANUAL'
        }
    }, createGroupRes);
    assert.equal(createGroupRes.statusCode, 200);
    const createdGroup = await HrOrgGroupMaster.findOne({ key: `org-group-${suffix}` }).lean();
    assert.ok(createdGroup && createdGroup._id);
    const groupId = String(createdGroup._id);

    const createUnitRes = mockResponse();
    await hrOrgUnitService.onCreate({
        body: {
            key: `org-group-${suffix}:unit-${suffix}`,
            code: `U-${suffix}`,
            title: [{ key: 'th', value: `หน่วยงานทดสอบ ${suffix}` }],
            description: [{ key: 'th', value: 'หน่วยงานสำหรับทดสอบ CRUD' }],
            orgGroupId: groupId,
            source: 'MANUAL'
        }
    }, createUnitRes);
    assert.equal(createUnitRes.statusCode, 200);
    const createdUnit = await HrOrgUnitMaster.findOne({ key: `org-group-${suffix}:unit-${suffix}` }).lean();
    assert.ok(createdUnit && createdUnit._id);
    const unitId = String(createdUnit._id);

    const updateUnitRes = mockResponse();
    await hrOrgUnitService.onUpdate({
        body: {
            _id: unitId,
            key: `org-group-${suffix}:unit-${suffix}`,
            code: `U-${suffix}-2`,
            title: [{ key: 'th', value: `หน่วยงานทดสอบอัปเดต ${suffix}` }],
            description: [{ key: 'th', value: 'อัปเดตจาก automated test' }],
            orgGroupId: groupId,
            source: 'MANUAL'
        }
    }, updateUnitRes);
    assert.equal(updateUnitRes.statusCode, 200);
    const updatedUnit = await HrOrgUnitMaster.findOne({ _id: unitId }).lean();
    assert.equal(updatedUnit.code, `U-${suffix}-2`);

    const deleteGroupBlockedRes = mockResponse();
    await hrOrgGroupService.onDelete({ body: { id: groupId } }, deleteGroupBlockedRes);
    assert.equal(deleteGroupBlockedRes.statusCode, 409);
    assert.equal(deleteGroupBlockedRes.body.message, 'master_in_use');

    const deleteUnitRes = mockResponse();
    await hrOrgUnitService.onDelete({ body: { id: unitId } }, deleteUnitRes);
    assert.equal(deleteUnitRes.statusCode, 200);

    const deleteGroupRes = mockResponse();
    await hrOrgGroupService.onDelete({ body: { id: groupId } }, deleteGroupRes);
    assert.equal(deleteGroupRes.statusCode, 200);

    await cleanupBySuffix(suffix);
});

test('HR sync is idempotent and links created accounts back to HR identity', async function () {
    const suffix = `sync-${Date.now()}`;
    await cleanupBySuffix(suffix);

    const row = [
        `POS-${suffix}`,
        'O : เปิด',
        `EMP-${suffix}`,
        `เจ้าหน้าที่ทดสอบ ${suffix}`,
        'ไม่มีตำแหน่งทางวิชาการ',
        `WL-${suffix}`,
        `สายงานทดสอบ ${suffix}`,
        `PT-${suffix}`,
        `ประเภทบุคลากรทดสอบ ${suffix}`,
        `กลุ่มหน่วยงานทดสอบ ${suffix}`,
        `OU-${suffix}`,
        `หน่วยงานทดสอบ ${suffix}`,
        '2022-01-01',
        '2030-12-31',
        'M',
        '30',
        `DG-${suffix}`,
        `ระดับวุฒิทดสอบ ${suffix}`,
        'GEN TEST',
        '0-5 ปี',
        'นครราชสีมา',
        '4',
        `ES-${suffix}`,
        `สถานภาพทดสอบ ${suffix}`,
        `ฝ่ายทดสอบ ${suffix}`,
        'หมายเหตุทดสอบ',
        '2569',
        '2026-03-12T00:00:00Z',
        'เดิม',
        'นาย',
        'ทดสอบ',
        suffix
    ];

    const first = await syncHrRows([row], {
        sourceFile: `AUTOTEST-${suffix}`,
        sourceSheet: 'HRAutoUpdate',
        autoCreateAccounts: true
    });
    assert.equal(first.rowCount, 1);
    assert.equal(first.createdAccountCount, 1);
    assert.equal(first.updatedAccountCount, 0);
    assert.equal(first.matchedAccountCount, 1);
    assert.equal(first.unmatchedAccountCount, 0);

    const second = await syncHrRows([row], {
        sourceFile: `AUTOTEST-${suffix}`,
        sourceSheet: 'HRAutoUpdate',
        autoCreateAccounts: true
    });
    assert.equal(second.rowCount, 1);
    assert.equal(second.createdAccountCount, 0);
    assert.equal(second.updatedAccountCount, 1);
    assert.equal(second.matchedAccountCount, 1);
    assert.equal(second.unmatchedAccountCount, 0);

    const identity = await HrIdentityMaster.findOne({ personnelCode: `EMP-${suffix}` }).lean();
    const account = await Account.findOne({ code: `EMP-${suffix}` }).lean();
    assert.ok(identity && identity.linkedAccount);
    assert.ok(account && account.hrContext && account.hrContext.snapshot);

    await cleanupBySuffix(suffix);
});

test('HR sync preview summarizes normalized rows correctly', async function () {
    const suffix = `preview-${Date.now()}`;
    const rowA = [
        `POS-${suffix}-1`,
        'O : เปิด',
        `EMP-${suffix}-1`,
        `เจ้าหน้าที่ทดสอบ ${suffix} A`,
        '',
        `WL-${suffix}`,
        `สายงานทดสอบ ${suffix}`,
        `PT-${suffix}`,
        `ประเภทบุคลากรทดสอบ ${suffix}`,
        `กลุ่มหน่วยงานทดสอบ ${suffix}`,
        `OU-${suffix}`,
        `หน่วยงานทดสอบ ${suffix}`,
        '2022-01-01',
        '2030-12-31',
        'M',
        '30',
        `DG-${suffix}`,
        `ระดับวุฒิทดสอบ ${suffix}`,
        'GEN TEST',
        '0-5 ปี',
        'นครราชสีมา',
        '4',
        `ES-${suffix}`,
        `สถานภาพทดสอบ ${suffix}`,
        `ฝ่ายทดสอบ ${suffix}`,
        'หมายเหตุทดสอบ',
        '2569',
        '2026-03-12T00:00:00Z',
        'เดิม',
        'นาย',
        'ทดสอบ',
        `${suffix}A`
    ];
    const rowB = rowA.slice();
    rowB[0] = `POS-${suffix}-2`;
    rowB[2] = `EMP-${suffix}-2`;
    rowB[3] = `เจ้าหน้าที่ทดสอบ ${suffix} B`;
    rowB[24] = `ฝ่ายทดสอบย่อย ${suffix}`;

    const preview = buildPreview([rowA, rowB], ['positionCode', 'positionStatus']);
    assert.equal(preview.rowCount, 2);
    assert.equal(preview.personnelCount, 2);
    assert.equal(preview.positionCount, 2);
    assert.equal(preview.orgGroupCount, 1);
    assert.equal(preview.orgUnitCount, 1);
    assert.equal(preview.subUnitCount, 2);
    assert.equal(preview.sample.length, 2);
    assert.equal(preview.sample[0].personnelCode, `EMP-${suffix}-1`);
    assert.equal(preview.warnings.length, 0);
});

test('HR sync preview report exposes create and update impact counts', async function () {
    const suffix = `preview-report-${Date.now()}`;
    await cleanupBySuffix(suffix);

    const row = [
        `POS-${suffix}`,
        'O : เปิด',
        `EMP-${suffix}`,
        `เจ้าหน้าที่ทดสอบ ${suffix}`,
        '',
        `WL-${suffix}`,
        `สายงานทดสอบ ${suffix}`,
        `PT-${suffix}`,
        `ประเภทบุคลากรทดสอบ ${suffix}`,
        `กลุ่มหน่วยงานทดสอบ ${suffix}`,
        `OU-${suffix}`,
        `หน่วยงานทดสอบ ${suffix}`,
        '2022-01-01',
        '2030-12-31',
        'M',
        '30',
        `DG-${suffix}`,
        `ระดับวุฒิทดสอบ ${suffix}`,
        'GEN TEST',
        '0-5 ปี',
        'นครราชสีมา',
        '4',
        `ES-${suffix}`,
        `สถานภาพทดสอบ ${suffix}`,
        `ฝ่ายทดสอบ ${suffix}`,
        'หมายเหตุทดสอบ',
        '2569',
        '2026-03-12T00:00:00Z',
        'เดิม',
        'นาย',
        'ทดสอบ',
        suffix
    ];

    const first = await buildPreviewReport([row], ['positionCode'], { createAccounts: true });
    assert.equal(first.createIdentityCount, 1);
    assert.equal(first.updateIdentityCount, 0);
    assert.equal(first.createPositionCount, 1);
    assert.equal(first.updatePositionCount, 0);
    assert.equal(first.createAccountCandidateCount, 1);
    assert.equal(first.updateAccountCandidateCount, 0);

    await syncHrRows([row], {
        sourceFile: `AUTOTEST-${suffix}`,
        sourceSheet: 'HRAutoUpdate',
        autoCreateAccounts: true
    });

    const second = await buildPreviewReport([row], ['positionCode'], { createAccounts: true });
    assert.equal(second.createIdentityCount, 0);
    assert.equal(second.updateIdentityCount, 1);
    assert.equal(second.createPositionCount, 0);
    assert.equal(second.updatePositionCount, 1);
    assert.equal(second.createAccountCandidateCount, 0);
    assert.equal(second.updateAccountCandidateCount, 1);

    await cleanupBySuffix(suffix);
});

test('HR account backfill creates and links accounts for unlinked HR identities', async function () {
    const suffix = `backfill-${Date.now()}`;
    await cleanupBySuffix(suffix);

    const identity = await HrIdentityMaster.create({
        identityKey: `IDENTITY-${suffix}`,
        personnelCode: `EMP-${suffix}`,
        prefix: 'นาย',
        firstName: 'ทดสอบ',
        lastName: suffix,
        fullName: `นาย ทดสอบ ${suffix}`,
        positionCode: `POS-${suffix}`,
        positionTitle: `ตำแหน่งทดสอบ ${suffix}`,
        orgGroupName: `กลุ่มทดสอบ ${suffix}`,
        orgUnitName: `หน่วยงานทดสอบ ${suffix}`,
        subUnitName: `ฝ่ายทดสอบ ${suffix}`,
        employmentStatusName: `สถานภาพทดสอบ ${suffix}`,
        vacancy: false,
        source: 'HR_IMPORT'
    });

    const summary = await backfillAccountsFromHrIdentities({});
    assert.ok(summary.createdAccountCount >= 1);

    const updatedIdentity = await HrIdentityMaster.findById(identity._id).lean();
    const account = await Account.findOne({ code: `EMP-${suffix}` }).lean();
    assert.ok(account && updatedIdentity && updatedIdentity.linkedAccount);

    await cleanupBySuffix(suffix);
});
