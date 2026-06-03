'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildCatalogIndex,
    evaluateLifecycle,
    normalizeLifecyclePayload
} = require('../../settings/service/lifecycle-master');
const {
    buildLifecycleTimeline,
    summarizeSignals
} = require('./identity-lifecycle');
const { mergeLifecycleWithHrContext: mergeFromBoundary } = require('./lifecycle-boundary');

function oid(value) {
    return String(value).padStart(24, '0');
}

function isoDateOffset(days) {
    const value = new Date();
    value.setHours(0, 0, 0, 0);
    value.setDate(value.getDate() + days);
    return value.toISOString().slice(0, 10);
}

function createCatalog() {
    const academic = { _id: oid(1), key: 'ACADEMIC', title: [{ key: 'en', value: 'Academic' }] };
    const operational = { _id: oid(2), key: 'OPERATIONAL', title: [{ key: 'en', value: 'Operational' }] };
    const lms = { _id: oid(11), key: 'LMS_STAFF', title: [{ key: 'en', value: 'LMS Staff' }], defaultScope: 'faculty' };
    const facultyApproval = { _id: oid(12), key: 'FACULTY_APPROVAL', title: [{ key: 'en', value: 'Faculty Approval' }], defaultScope: 'faculty' };
    const unitApproval = { _id: oid(13), key: 'UNIT_APPROVAL', title: [{ key: 'en', value: 'Unit Approval' }], defaultScope: 'unit' };
    const activeStatus = { _id: oid(21), key: 'ACTIVE', title: [{ key: 'en', value: 'Active' }] };

    return {
        affiliationTypes: [academic, operational],
        accessProfiles: [lms, facultyApproval, unitApproval],
        positionRules: [
            {
                _id: oid(31),
                key: 'RULE_DEAN',
                matchType: 'CONTAINS',
                matchValues: ['dean'],
                orgScope: 'faculty',
                priority: 10,
                affiliationTypes: [academic],
                accessProfiles: [facultyApproval],
                state: true
            },
            {
                _id: oid(32),
                key: 'RULE_HEAD',
                matchType: 'CONTAINS',
                matchValues: ['head'],
                orgScope: 'unit',
                priority: 20,
                affiliationTypes: [academic, operational],
                accessProfiles: [unitApproval],
                state: true
            }
        ],
        provisioningPolicies: [
            {
                _id: oid(41),
                key: 'POLICY_ACADEMIC',
                affiliationType: academic,
                defaultAccessProfiles: [lms],
                defaultTargetStatus: activeStatus,
                autoProvision: true,
                autoDeprovision: true,
                revokeSessionsOnDeprovision: true
            }
        ],
        accountStatuses: [activeStatus]
    };
}

test('normalizeLifecyclePayload maps legacy keys to referenced ids', function () {
    const catalog = createCatalog();
    const index = buildCatalogIndex(catalog);
    const lifecycle = normalizeLifecyclePayload({
        primaryAffiliation: 'ACADEMIC',
        affiliations: [{ type: 'ACADEMIC', title: 'Lecturer', isPrimary: true }],
        accessProfiles: [{ key: 'LMS_STAFF', scope: 'faculty' }]
    }, {}, index);

    assert.equal(String(lifecycle.primaryAffiliation), oid(1));
    assert.equal(String(lifecycle.affiliations[0].type), oid(1));
    assert.equal(String(lifecycle.accessProfiles[0].profile), oid(11));
    assert.equal(lifecycle.migration.unmappedAffiliations.length, 0);
});

test('evaluateLifecycle uses DB policies and rules without hardcoded fallback', function () {
    const catalog = createCatalog();
    const index = buildCatalogIndex(catalog);
    const lifecycle = normalizeLifecyclePayload({
        primaryAffiliation: oid(1),
        affiliations: [{ type: oid(1), title: 'Lecturer', isPrimary: true }],
        positions: [{ title: 'Dean of Science', type: 'POSITION' }]
    }, {}, index);
    const evaluation = evaluateLifecycle(lifecycle, catalog, {});

    assert.equal(evaluation.targetStatusKey, 'ACTIVE');
    assert.ok(evaluation.recommendedProfiles.some(function (item) { return item.key === 'LMS_STAFF'; }));
    assert.ok(evaluation.recommendedProfiles.some(function (item) { return item.key === 'FACULTY_APPROVAL'; }));
    assert.equal(evaluation.configurationErrors.length, 0);
});

test('evaluateLifecycle respects rule priority and dedupes duplicate profiles', function () {
    const catalog = createCatalog();
    catalog.positionRules.unshift({
        _id: oid(33),
        key: 'RULE_DEAN_DUPLICATE',
        matchType: 'EXACT',
        matchValues: ['dean of science'],
        orgScope: 'faculty',
        priority: 5,
        affiliationTypes: [catalog.affiliationTypes[0]],
        accessProfiles: [catalog.accessProfiles[1]],
        state: true
    });
    const index = buildCatalogIndex(catalog);
    const lifecycle = normalizeLifecyclePayload({
        primaryAffiliation: oid(1),
        affiliations: [{ type: oid(1), title: 'Lecturer', isPrimary: true }],
        positions: [{ title: 'Dean of Science', type: 'POSITION' }]
    }, {}, index);
    const evaluation = evaluateLifecycle(lifecycle, catalog, {});

    assert.equal(evaluation.matchedRules[0].key, 'RULE_DEAN_DUPLICATE');
    assert.equal(evaluation.recommendedProfiles.filter(function (item) { return item.key === 'FACULTY_APPROVAL'; }).length, 1);
});

test('evaluateLifecycle returns configuration errors when policy is missing', function () {
    const catalog = createCatalog();
    catalog.provisioningPolicies = [];
    const index = buildCatalogIndex(catalog);
    const lifecycle = normalizeLifecyclePayload({
        primaryAffiliation: oid(1),
        affiliations: [{ type: oid(1), title: 'Lecturer', isPrimary: true }]
    }, {}, index);
    const evaluation = evaluateLifecycle(lifecycle, catalog, {});

    assert.equal(evaluation.targetStatusKey, null);
    assert.ok(evaluation.configurationErrors.some(function (item) {
        return String(item).indexOf('Missing provisioning policy') !== -1 || String(item).indexOf('Primary affiliation') !== -1;
    }));
});

test('evaluateLifecycle adds assignment access and leave-based warning', function () {
    const catalog = createCatalog();
    const index = buildCatalogIndex(catalog);
    const lifecycle = normalizeLifecyclePayload({
        primaryAffiliation: oid(1),
        affiliations: [{ type: oid(1), title: 'Lecturer', isPrimary: true }],
        leaves: [{ type: 'STUDY_LEAVE', startDate: '2025-01-01', endDate: '2026-12-31', status: 'APPROVED', accessImpact: 'SUSPEND' }],
        assignments: [{ title: 'Acting Dean', type: 'TEMPORARY_ROLE', scope: 'faculty', accessProfiles: [oid(13)], status: 'ACTIVE' }]
    }, {}, index);
    const evaluation = evaluateLifecycle(lifecycle, catalog, {});

    assert.equal(evaluation.targetStatusKey, 'SUSPENDED');
    assert.ok(evaluation.recommendedProfiles.some(function (item) { return item.key === 'UNIT_APPROVAL'; }));
    assert.ok(evaluation.warnings.some(function (item) {
        return String(item).indexOf('requires suspended access handling') !== -1;
    }));
});

test('buildLifecycleTimeline and summarizeSignals expose progression and risk signals', function () {
    const joinerDate = isoDateOffset(-500);
    const contractEndDate = isoDateOffset(45);
    const promotionDate = isoDateOffset(-120);
    const leaveStartDate = isoDateOffset(-10);
    const leaveEndDate = isoDateOffset(20);
    const developmentEndDate = isoDateOffset(-5);
    const assignmentStartDate = isoDateOffset(-30);
    const lastProvisionedAt = isoDateOffset(-15);
    const catalog = createCatalog();
    const index = buildCatalogIndex(catalog);
    const lifecycle = normalizeLifecyclePayload({
        primaryAffiliation: oid(1),
        affiliations: [{ type: oid(1), title: 'Lecturer', isPrimary: true, startDate: joinerDate, endDate: contractEndDate }],
        positions: [{ title: 'Dean of Science', type: 'POSITION', startDate: promotionDate }],
        movements: [{ type: 'PROMOTION', fromTitle: 'Lecturer', toTitle: 'Dean of Science', effectiveDate: promotionDate }],
        leaves: [{ type: 'TRAINING_LEAVE', startDate: leaveStartDate, endDate: leaveEndDate, status: 'APPROVED', accessImpact: 'LIMIT' }],
        developments: [{ type: 'TRAINING', title: 'Strategic Leadership', provider: 'HRD', endDate: developmentEndDate, hours: 18 }],
        assignments: [{ title: 'Acting Dean', type: 'TEMPORARY_ROLE', scope: 'faculty', accessProfiles: [oid(13)], status: 'ACTIVE', startDate: assignmentStartDate }],
        provisioning: { joinerDate: joinerDate, lastProvisionedAt: lastProvisionedAt }
    }, {}, index);
    const evaluation = evaluateLifecycle(lifecycle, catalog, { createDate: isoDateOffset(-540) });
    const timeline = buildLifecycleTimeline(evaluation, lifecycle, { createDate: isoDateOffset(-540) });
    const signals = summarizeSignals(evaluation.lifecycle, lifecycle, evaluation, { status: { key: 'ACTIVE' } });

    assert.ok(timeline.some(function (item) { return item.type === 'MOVEMENT'; }));
    assert.ok(timeline.some(function (item) { return item.type === 'DEVELOPMENT'; }));
    assert.ok(timeline.some(function (item) { return item.type === 'PROVISIONED'; }));
    assert.equal(signals.activeLeaveCount, 1);
    assert.equal(signals.activeAssignmentCount, 1);
    assert.equal(signals.totalLearningHours, 18);
    assert.equal(signals.progressionRisk, 'MEDIUM');
});

test('mergeLifecycleWithHrContext rebuilds evaluation input from separated HR context', function () {
    const merged = mergeFromBoundary({
        primaryAffiliation: oid(1),
        affiliations: [{ type: oid(1), title: 'Lecturer', isPrimary: true }],
        positions: [{ title: 'Dean of Science', type: 'POSITION', startDate: '2025-01-01' }],
        provisioning: { state: 'PROVISIONED' }
    }, {
        leaves: [{ type: 'STUDY_LEAVE', startDate: '2025-01-01', endDate: '2026-12-31', status: 'APPROVED', accessImpact: 'SUSPEND' }],
        developments: [{ type: 'TRAINING', title: 'Strategic Leadership', provider: 'HRD', endDate: '2026-02-20', hours: 18 }],
        assignments: [{ title: 'Acting Dean', type: 'TEMPORARY_ROLE', scope: 'faculty', accessProfiles: [oid(13)], status: 'ACTIVE', startDate: '2026-01-01' }],
        movements: [{ type: 'PROMOTION', fromTitle: 'Lecturer', toTitle: 'Dean of Science', effectiveDate: '2025-01-01' }],
        snapshot: { personnelCode: '61360131' }
    });

    assert.equal(merged.leaves.length, 1);
    assert.equal(merged.developments.length, 1);
    assert.equal(merged.assignments.length, 1);
    assert.equal(merged.movements.length, 1);
    assert.equal(merged.hrSnapshot.personnelCode, '61360131');
});
