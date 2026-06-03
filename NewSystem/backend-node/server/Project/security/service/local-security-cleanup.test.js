'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildArchiveCollectionName,
  cleanupLocalSecurityOwnership
} = require('./local-security-cleanup');

function createFakeDb(seed) {
  const state = Object.assign({}, seed || {});
  Object.keys(state).forEach(function (name) {
    state[name] = Array.isArray(state[name]) ? state[name].map(function (item) { return Object.assign({}, item); }) : [];
  });

  return {
    state: state,
    listCollections() {
      return {
        async toArray() {
          return Object.keys(state).map(function (name) { return { name: name }; });
        }
      };
    },
    collection(name) {
      if (!state[name]) state[name] = [];
      return {
        async countDocuments() {
          return state[name].length;
        },
        find() {
          return {
            async toArray() {
              return state[name].map(function (item) { return Object.assign({}, item); });
            }
          };
        },
        async insertMany(items) {
          state[name] = state[name].concat(items.map(function (item) { return Object.assign({}, item); }));
          return { insertedCount: items.length };
        },
        async deleteMany() {
          const deletedCount = state[name].length;
          state[name] = [];
          return { deletedCount: deletedCount };
        }
      };
    }
  };
}

test('local-security-cleanup reports dry-run plan without mutating source collections', async function () {
  const db = createFakeDb({
    Security_Menu: [{ _id: 'menu-1' }, { _id: 'menu-2' }],
    Security_Group: [{ _id: 'group-1' }]
  });

  const summary = await cleanupLocalSecurityOwnership(db, {
    execute: false,
    batchId: '20260420T120000Z',
    includeCollections: ['Security_Menu', 'Security_Group']
  });

  assert.equal(summary.execute, false);
  assert.equal(summary.targets[0].status, 'dry-run');
  assert.equal(summary.targets[0].sourceCount, 2);
  assert.equal(db.state.Security_Menu.length, 2);
  assert.equal(db.state[buildArchiveCollectionName('Security_Menu', '20260420T120000Z')], undefined);
});

test('local-security-cleanup archives then purges target collections on execute', async function () {
  const db = createFakeDb({
    Security_Assignment: [{ _id: 'assign-1', account: 'acc-1' }]
  });

  const summary = await cleanupLocalSecurityOwnership(db, {
    execute: true,
    batchId: '20260420T120100Z',
    includeCollections: ['Security_Assignment']
  });

  const archiveCollection = buildArchiveCollectionName('Security_Assignment', '20260420T120100Z');
  assert.equal(summary.targets[0].status, 'archived_and_purged');
  assert.equal(db.state.Security_Assignment.length, 0);
  assert.equal(db.state[archiveCollection].length, 1);
  assert.equal(db.state[archiveCollection][0].payload._id, 'assign-1');
});
