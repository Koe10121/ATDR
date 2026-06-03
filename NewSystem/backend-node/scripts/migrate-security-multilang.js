'use strict';

const mongoose = require('mongoose');
const cfg = require('../config/config');

const SecurityType = require('../server/Project/security/models/type.model');
const SecurityMenu = require('../server/Project/security/models/menu.model');
const SecurityGroup = require('../server/Project/security/models/group.model');

function trimText(value) {
  return String(value || '').trim();
}

function normalizeMultiLanguage(items, fallbackValue) {
  if (Array.isArray(items)) {
    const normalized = items
      .map((item) => ({
        key: trimText(item && item.key) || null,
        value: trimText(item && item.value)
      }))
      .filter((item) => item.key && item.value);

    if (normalized.length) return normalized;
  }

  const fallback = trimText(fallbackValue);
  return fallback ? [{ key: 'th', value: fallback }] : [];
}

async function migrateCollection(Model, fields) {
  const docs = await Model.find({}).lean();
  let modified = 0;

  for (const doc of docs) {
    const setPayload = {};
    let changed = false;

    fields.forEach((field) => {
      const normalized = normalizeMultiLanguage(doc[field], doc[field]);
      const before = JSON.stringify(Array.isArray(doc[field]) ? doc[field] : doc[field] == null ? [] : doc[field]);
      const after = JSON.stringify(normalized);
      if (before !== after) {
        setPayload[field] = normalized;
        changed = true;
      }
    });

    if (!changed) continue;

    await Model.collection.updateOne({ _id: doc._id }, { $set: setPayload });
    modified += 1;
  }

  return { total: docs.length, modified };
}

async function run() {
  await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

  const types = await migrateCollection(SecurityType, ['title', 'description']);
  const menus = await migrateCollection(SecurityMenu, ['title', 'description']);
  const groups = await migrateCollection(SecurityGroup, ['title', 'description']);

  console.log(JSON.stringify({ types, menus, groups }, null, 2));

  await mongoose.disconnect();
}

run().catch(async (error) => {
  console.error(error);
  try {
    await mongoose.disconnect();
  } catch (disconnectError) {}
  process.exit(1);
});
