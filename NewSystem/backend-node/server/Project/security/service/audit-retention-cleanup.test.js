'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildArchiveCollectionName,
  cleanupAuditRetention,
  resolveCutoffDate
} = require('./audit-retention-cleanup');

function createFakeDb(seed) {
  const state = Object.assign({}, seed || {});
  Object.keys(state).forEach(function (name) {
    state[name] = Array.isArray(state[name]) ? state[name].map(function (item) { return Object.assign({}, item); }) : [];
  });

  return {
    state: state,
    listCollections(filter) {
      return {
        async toArray() {
          const names = Object.keys(state).filter(function (name) {
            return !filter || !filter.name || filter.name === name;
          });
          return names.map(function (name) { return { name: name }; });
        }
      };
    },
    collection(name) {
      if (!state[name]) state[name] = [];
      return {
        async countDocuments() {
          return state[name].length;
        },
        find(query) {
          const docs = state[name].filter(function (item) {
            if (!query || !query.createdAt || !query.createdAt.$lt) return true;
            return new Date(item.createdAt).getTime() < new Date(query.createdAt.$lt).getTime();
          });
          return {
            async toArray() {
              return docs.map(function (item) { return Object.assign({}, item); });
            }
          };
        },
        async insertMany(items) {
          state[name] = state[name].concat(items.map(function (item) { return Object.assign({}, item); }));
          return { insertedCount: items.length };
        },
        async deleteMany(query) {
          const ids = new Set((query && query._id && Array.isArray(query._id.$in) ? query._id.$in : []).map(String));
          const before = state[name].length;
          state[name] = state[name].filter(function (item) { return !ids.has(String(item._id)); });
          return { deletedCount: before - state[name].length };
        }
      };
    }
  };
}

test('resolveCutoffDate rejects invalid retention days', function () {
  assert.throws(function () {
    resolveCutoffDate(-1, new Date('2026-04-20T00:00:00.000Z'));
  }, /invalid_retention_days/);
});

test('audit-retention-cleanup reports eligible documents in dry-run mode', async function () {
  const db = createFakeDb({
    Security_AuditEvent: [
      { _id: 'a1', createdAt: new Date('2026-01-01T00:00:00.000Z') },
      { _id: 'a2', createdAt: new Date('2026-04-19T00:00:00.000Z') }
    ]
  });

  const summary = await cleanupAuditRetention(db, {
    execute: false,
    retentionDays: 30,
    now: new Date('2026-04-20T00:00:00.000Z'),
    batchId: '20260420T000000Z'
  });

  assert.equal(summary.status, 'dry-run');
  assert.equal(summary.eligibleCount, 1);
  assert.equal(db.state.Security_AuditEvent.length, 2);
});

test('audit-retention-cleanup archives and purges only expired events', async function () {
  const db = createFakeDb({
    Security_AuditEvent: [
      { _id: 'a1', createdAt: new Date('2026-01-01T00:00:00.000Z') },
      { _id: 'a2', createdAt: new Date('2026-04-19T00:00:00.000Z') }
    ]
  });

  const summary = await cleanupAuditRetention(db, {
    execute: true,
    retentionDays: 30,
    now: new Date('2026-04-20T00:00:00.000Z'),
    batchId: '20260420T000100Z'
  });

  const archiveCollection = buildArchiveCollectionName('20260420T000100Z');
  assert.equal(summary.status, 'archived_and_purged');
  assert.equal(summary.eligibleCount, 1);
  assert.equal(db.state.Security_AuditEvent.length, 1);
  assert.equal(db.state.Security_AuditEvent[0]._id, 'a2');
  assert.equal(db.state[archiveCollection].length, 1);
  assert.equal(db.state[archiveCollection][0].payload._id, 'a1');
});
