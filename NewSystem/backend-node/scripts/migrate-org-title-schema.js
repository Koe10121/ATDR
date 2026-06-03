'use strict';

const mongoose = require('mongoose');
const cfg = require('../config/config');

const OrganizationGroup = require('../server/Project/employment/models/organization_group.model');
const OrganizationUnit = require('../server/Project/employment/models/organization_unit.model');
const EmploymentRecord = require('../server/Project/employment/models/record.model');

function trimText(value) {
  return String(value || '').trim();
}

function firstTitleValue(title) {
  if (!Array.isArray(title)) return '';
  const found = title.find((item) => item && typeof item.value === 'string' && trimText(item.value));
  return found ? trimText(found.value) : '';
}

function toTitle(nameText) {
  const text = trimText(nameText);
  if (!text) return [];
  return [{ key: 'th', value: text }];
}

function pickGroupName(doc) {
  return firstTitleValue(doc.title) || trimText(doc.nameFull) || trimText(doc.code) || `GRP-${String(doc._id).slice(-8)}`;
}

function pickUnitName(doc) {
  return firstTitleValue(doc.title) || trimText(doc.nameFull) || trimText(doc.code) || `UNIT-${String(doc._id).slice(-8)}`;
}

function pickGroupCode(doc) {
  const code = trimText(doc.code);
  if (code) return code;
  return `GRP-${String(doc._id).slice(-8).toUpperCase()}`;
}

function pickUnitCode(doc) {
  const code = trimText(doc.code);
  if (code) return code;
  return `UNIT-${String(doc._id).slice(-8).toUpperCase()}`;
}

async function dropIndexesContaining(collection, fieldName) {
  const indexes = await collection.indexes();
  let dropped = 0;
  for (const idx of indexes) {
    if (idx.name === '_id_') continue;
    const keys = Object.keys(idx.key || {});
    if (keys.includes(fieldName)) {
      await collection.dropIndex(idx.name);
      dropped += 1;
    }
  }
  return dropped;
}

function sameKey(indexKey, expectedKey) {
  const a = JSON.stringify(indexKey || {});
  const b = JSON.stringify(expectedKey || {});
  return a === b;
}

async function ensureUniqueIndex(collection, expectedKey) {
  const indexes = await collection.indexes();
  let hasUnique = false;

  for (const idx of indexes) {
    if (!sameKey(idx.key, expectedKey)) continue;
    if (idx.unique) {
      hasUnique = true;
      continue;
    }
    await collection.dropIndex(idx.name);
  }

  if (!hasUnique) {
    await collection.createIndex(expectedKey, { unique: true });
  }
}

async function migrateGroups() {
  const groups = await OrganizationGroup.find({}).lean();
  const byCode = new Map();
  let updated = 0;
  let merged = 0;

  for (const g of groups) {
    const code = pickGroupCode(g);
    const nameText = pickGroupName(g);
    const setPayload = {
      code,
      title: toTitle(nameText),
      description: Array.isArray(g.description) ? g.description : []
    };

    await OrganizationGroup.collection.updateOne(
      { _id: g._id },
      { $set: setPayload, $unset: { nameFull: 1, normalizedName: 1 } }
    );
    updated += 1;

    const key = code;
    if (!byCode.has(key)) {
      byCode.set(key, String(g._id));
      continue;
    }

    const keepId = byCode.get(key);
    const dupId = String(g._id);
    if (keepId === dupId) continue;

    await OrganizationUnit.updateMany({ group: new mongoose.Types.ObjectId(dupId) }, { $set: { group: new mongoose.Types.ObjectId(keepId) } });
    await EmploymentRecord.updateMany({ organizationGroup: new mongoose.Types.ObjectId(dupId) }, { $set: { organizationGroup: new mongoose.Types.ObjectId(keepId) } });
    await OrganizationGroup.deleteOne({ _id: new mongoose.Types.ObjectId(dupId) });
    merged += 1;
  }

  return { updated, merged };
}

async function migrateUnits() {
  const units = await OrganizationUnit.find({}).lean();
  const byGroupCode = new Map();
  let updated = 0;
  let merged = 0;

  for (const u of units) {
    if (!u.group) continue;
    const code = pickUnitCode(u);
    const nameText = pickUnitName(u);
    const setPayload = {
      code,
      title: toTitle(nameText),
      description: Array.isArray(u.description) ? u.description : []
    };

    await OrganizationUnit.collection.updateOne(
      { _id: u._id },
      { $set: setPayload, $unset: { nameFull: 1, normalizedName: 1 } }
    );
    updated += 1;

    const key = `${String(u.group)}|${code}`;
    if (!byGroupCode.has(key)) {
      byGroupCode.set(key, String(u._id));
      continue;
    }

    const keepId = byGroupCode.get(key);
    const dupId = String(u._id);
    if (keepId === dupId) continue;

    await EmploymentRecord.updateMany({ organizationUnit: new mongoose.Types.ObjectId(dupId) }, { $set: { organizationUnit: new mongoose.Types.ObjectId(keepId) } });
    await OrganizationUnit.deleteOne({ _id: new mongoose.Types.ObjectId(dupId) });
    merged += 1;
  }

  return { updated, merged };
}

async function syncIndexes() {
  const groupCollection = OrganizationGroup.collection;
  const unitCollection = OrganizationUnit.collection;

  const droppedGroup = await dropIndexesContaining(groupCollection, 'normalizedName');
  const droppedUnit = await dropIndexesContaining(unitCollection, 'normalizedName');

  await ensureUniqueIndex(groupCollection, { code: 1 });
  await ensureUniqueIndex(unitCollection, { code: 1, group: 1 });

  return { droppedGroup, droppedUnit };
}

async function run() {
  await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

  const groupResult = await migrateGroups();
  const unitResult = await migrateUnits();
  const recordCleanup = await EmploymentRecord.updateMany(
    {},
    { $unset: { organization: 1, unitCode: 1 } }
  );
  const indexResult = await syncIndexes();

  const duplicateGroupCodes = await OrganizationGroup.aggregate([
    { $group: { _id: '$code', c: { $sum: 1 } } },
    { $match: { _id: { $ne: null }, c: { $gt: 1 } } },
    { $count: 'total' }
  ]);

  const duplicateUnitKeys = await OrganizationUnit.aggregate([
    { $group: { _id: { code: '$code', group: '$group' }, c: { $sum: 1 } } },
    { $match: { '_id.code': { $ne: null }, c: { $gt: 1 } } },
    { $count: 'total' }
  ]);

  console.log(JSON.stringify({
    groupResult,
    unitResult,
    recordCleanup: {
      matched: recordCleanup && recordCleanup.n != null ? recordCleanup.n : recordCleanup.matchedCount,
      modified: recordCleanup && recordCleanup.nModified != null ? recordCleanup.nModified : recordCleanup.modifiedCount
    },
    indexResult,
    totals: {
      groups: await OrganizationGroup.countDocuments({}),
      units: await OrganizationUnit.countDocuments({})
    },
    duplicatesAfter: {
      groups: duplicateGroupCodes[0] ? duplicateGroupCodes[0].total : 0,
      units: duplicateUnitKeys[0] ? duplicateUnitKeys[0].total : 0
    }
  }, null, 2));

  await mongoose.disconnect();
}

run().catch(async (err) => {
  console.error(err);
  try { await mongoose.disconnect(); } catch (e) {}
  process.exit(1);
});
