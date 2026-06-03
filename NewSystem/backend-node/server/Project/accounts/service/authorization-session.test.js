'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../../../../config/config');
const { collectAccountScopeKeys, hasAssignmentScope } = require('../../security/service/account-access');
const { writeAudit } = require('../../../../helpers/audit.logger');
const AuditEvent = require('../../security/models/audit_event.model');

let connected = false;

async function ensureConnection() {
    if (connected) return;
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
    connected = true;
}

test.before(async function () {
    await ensureConnection();
});

test.after(async function () {
    if (connected) {
        await AuditEvent.deleteMany({ module: 'test-auth' });
        await mongoose.disconnect();
    }
});

test('collectAccountScopeKeys combines HR snapshot and lifecycle paths', function () {
    const keys = collectAccountScopeKeys({
        hrContext: {
            snapshot: {
                orgUnitCode: 'OU-001',
                orgUnitName: 'Science',
                orgGroupName: 'Academic Affairs'
            }
        },
        lifecycle: {
            affiliations: [
                {
                    orgCode: 'ORG-001',
                    orgPath: ['Academic Affairs', 'Science', 'Physics']
                }
            ]
        }
    });

    assert.ok(keys.includes('OU-001'));
    assert.ok(keys.includes('Science'));
    assert.ok(keys.includes('Academic Affairs'));
    assert.ok(keys.includes('ORG-001'));
    assert.ok(keys.includes('Physics'));
});

test('hasAssignmentScope respects self, unit, and org scopes', function () {
    const targetAccount = {
        _id: 'acc-target',
        hrContext: {
            snapshot: {
                orgUnitCode: 'OU-777',
                orgUnitName: 'Registrar'
            }
        },
        lifecycle: {
            affiliations: [{ orgPath: ['University', 'Registrar'] }]
        }
    };

    assert.equal(hasAssignmentScope([{ dataScope: 'self', active: true }], 'acc-target', targetAccount), true);
    assert.equal(hasAssignmentScope([{ dataScope: 'self', active: true }], 'acc-other', targetAccount), false);
    assert.equal(hasAssignmentScope([{ dataScope: 'unit', active: true, scopeUnits: ['OU-777'] }], 'acc-other', targetAccount), true);
    assert.equal(hasAssignmentScope([{ dataScope: 'unit', active: true, scopeUnits: ['OU-999'] }], 'acc-other', targetAccount), false);
    assert.equal(hasAssignmentScope([{ dataScope: 'org', active: true }], 'acc-other', targetAccount), true);
});

test('writeAudit persists audit event document', async function () {
    const result = await writeAudit({
        module: 'test-auth',
        action: 'persist-audit',
        actorId: 'actor-1',
        resourceId: 'resource-1',
        detail: { ok: true }
    }, {
        ip: '127.0.0.1',
        get: function (header) {
            return header === 'User-Agent' ? 'node-test' : '';
        }
    });

    assert.ok(result && result._id);
    const doc = await AuditEvent.findOne({ _id: result._id }).lean();
    assert.ok(doc);
    assert.equal(doc.module, 'test-auth');
    assert.equal(doc.action, 'persist-audit');
    assert.equal(doc.ip, '127.0.0.1');
});
