'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildAccountCreatePayload,
    buildLifecycleFromHrRow,
    buildOrgPath,
    deriveAffiliationKey,
    normalizeHrRow
} = require('../../settings/service/hr-sync');
const { splitLifecycleStorage, mergeLifecycleWithHrContext } = require('./lifecycle-boundary');
const {
    normalizeLangArray,
    pickLangValue,
    toLangArray
} = require('../../settings/service/hr_shared');

test('normalizeHrRow maps Excel columns into HR sync record', function () {
    const row = normalizeHrRow([
        '10003',
        'O : เปิด',
        '50217118',
        'รองอธิการบดี',
        'ผู้ช่วยศาสตราจารย์',
        1002,
        'รองอธิการบดี',
        1,
        'พนักงานบริหารวิชาการ',
        'สำนักงานบริหารกลาง',
        0,
        'ผู้บริหาร',
        '2007-06-01',
        '2027-05-31',
        'M',
        '46'
    ]);

    assert.equal(row.positionCode, '10003');
    assert.equal(row.personnelCode, '50217118');
    assert.equal(row.orgGroupName, 'สำนักงานบริหารกลาง');
    assert.equal(row.orgUnitName, 'ผู้บริหาร');
});

test('deriveAffiliationKey chooses executive and academic university categories', function () {
    assert.equal(deriveAffiliationKey({
        positionTitle: 'รองอธิการบดี',
        academicTitle: 'ผู้ช่วยศาสตราจารย์',
        workLineName: 'รองอธิการบดี',
        personnelTypeName: 'พนักงานบริหารวิชาการ',
        orgGroupName: 'สำนักงานบริหารกลาง',
        orgUnitName: 'ผู้บริหาร',
        employmentStatusName: 'พนักงานบริหารวิชาการ'
    }), 'EXECUTIVE');

    assert.equal(deriveAffiliationKey({
        positionTitle: 'อาจารย์',
        academicTitle: '',
        workLineName: 'วิชาการ',
        personnelTypeName: 'พนักงานวิชาการ',
        orgGroupName: 'สำนักวิชา',
        orgUnitName: 'คอมพิวเตอร์',
        employmentStatusName: 'พนักงานมหาวิทยาลัย'
    }), 'ACADEMIC');
});

test('buildLifecycleFromHrRow produces HR-backed affiliation, position, movement and snapshot', function () {
    const row = normalizeHrRow([
        '10003',
        'O : เปิด',
        '50217118',
        'รองอธิการบดี',
        'ผู้ช่วยศาสตราจารย์',
        1002,
        'รองอธิการบดี',
        1,
        'พนักงานบริหารวิชาการ',
        'สำนักงานบริหารกลาง',
        0,
        'ผู้บริหาร',
        '2007-06-01',
        '2027-05-31'
    ]);
    const currentLifecycle = {
        positions: [{ code: '00001', title: 'อาจารย์', orgPath: ['สำนักวิชา', 'คอมพิวเตอร์'] }],
        movements: [],
        developments: []
    };
    const lifecycle = buildLifecycleFromHrRow(row, '000000000000000000000001', currentLifecycle);

    assert.equal(buildOrgPath(row).join(' / '), 'สำนักงานบริหารกลาง / ผู้บริหาร');
    assert.equal(String(lifecycle.primaryAffiliation), '000000000000000000000001');
    assert.equal(lifecycle.affiliations[0].status, 'ACTIVE');
    assert.equal(lifecycle.positions[0].title, 'รองอธิการบดี');
    assert.equal(lifecycle.movements.length, 1);
    assert.equal(lifecycle.hrSnapshot.positionCode, '10003');
});

test('normalizeHrRow keeps separated masters source values for later reference mapping', function () {
    const row = normalizeHrRow([
        '20001',
        'O : เปิด',
        '59000001',
        'อาจารย์',
        'รองศาสตราจารย์',
        '1001',
        'สายวิชาการ',
        '2',
        'พนักงานมหาวิทยาลัย',
        'สำนักวิชาเทคโนโลยีสารสนเทศ',
        'IT',
        'สาขาวิทยาการข้อมูล',
        '2018-01-01',
        '2030-12-31',
        'F',
        '35',
        '2',
        'ปริญญาโท',
        'Gen Y',
        'E : 6-10 ปี',
        'เชียงราย',
        '8',
        '10',
        'พนักงานมหาวิทยาลัย',
        'สาขาวิทยาการข้อมูล'
    ]);

    assert.equal(row.workLineName, 'สายวิชาการ');
    assert.equal(row.orgGroupName, 'สำนักวิชาเทคโนโลยีสารสนเทศ');
    assert.equal(row.orgUnitName, 'สาขาวิทยาการข้อมูล');
    assert.equal(row.degreeLevelName, 'ปริญญาโท');
    assert.equal(row.employmentStatusName, 'พนักงานมหาวิทยาลัย');
});

test('HR localization helpers normalize legacy strings into multilang arrays', function () {
    const title = normalizeLangArray('สายวิชาการ');
    const description = toLangArray({ th: 'คำอธิบาย', en: 'Description' });

    assert.deepEqual(title, [{ key: 'th', value: 'สายวิชาการ' }]);
    assert.equal(pickLangValue(description), 'คำอธิบาย');
});

test('buildAccountCreatePayload creates account shell for HR import', function () {
    const payload = buildAccountCreatePayload({
        personnelCode: '50217118',
        prefix: 'นาย',
        firstName: 'สมชาย',
        lastName: 'ตัวอย่าง'
    }, '000000000000000000000021', { provisioning: { state: 'PROVISIONED' } });

    assert.equal(payload.code, '50217118');
    assert.equal(payload.authen[0].username, '50217118');
    assert.equal(payload.userinfo.firstName[0].value, 'สมชาย');
    assert.equal(payload.status, '000000000000000000000021');
    assert.equal(payload.lifecycle.provisioning.state, 'PROVISIONED');
});

test('splitLifecycleStorage moves HR-derived records out of lifecycle core', function () {
    const lifecycle = {
        primaryAffiliation: '000000000000000000000001',
        affiliations: [{ type: '000000000000000000000001', title: 'อาจารย์' }],
        positions: [{ title: 'อาจารย์' }],
        movements: [{ type: 'TRANSFER', toTitle: 'คณบดี' }],
        leaves: [{ type: 'STUDY_LEAVE' }],
        developments: [{ title: 'Leadership' }],
        assignments: [{ title: 'Acting Dean' }],
        hrSnapshot: { personnelCode: '50217118' },
        provisioning: { state: 'PROVISIONED' }
    };
    const persisted = splitLifecycleStorage(lifecycle, {});

    assert.equal(Array.isArray(persisted.lifecycle.movements), false);
    assert.equal(Array.isArray(persisted.hrContext.movements), true);
    assert.equal(persisted.hrContext.snapshot.personnelCode, '50217118');

    const merged = mergeLifecycleWithHrContext(persisted.lifecycle, persisted.hrContext);
    assert.equal(merged.movements.length, 1);
    assert.equal(merged.hrSnapshot.personnelCode, '50217118');
});
