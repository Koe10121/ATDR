'use strict';

const mongoose = require('mongoose');
const cfg = require('../config/config');
const Account = require('../server/Project/accounts/controller/account');
const AccountModel = require('../server/Project/accounts/models/account.model');
const { buildCatalogIndex, ensureLifecycleMasterData, loadLifecycleCatalog, normalizeLifecyclePayload } = require('../server/Project/settings/service/lifecycle-master');

async function run() {
  await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
  await ensureLifecycleMasterData();
  const catalog = await loadLifecycleCatalog();
  const index = buildCatalogIndex(catalog);
  const accounts = await AccountModel.find({ 'lifecycle': { $exists: true } }).lean();

  const report = {
    total: accounts.length,
    migrated: 0,
    skipped: 0,
    unmapped: []
  };

  for (const item of accounts) {
    const normalized = normalizeLifecyclePayload(item.lifecycle || {}, item.lifecycle || {}, index);
    const hasUnmapped = (normalized.migration.unmappedAffiliations || []).length || (normalized.migration.unmappedAccessProfiles || []).length || (normalized.migration.legacyPrimaryAffiliation || '');
    await Account.onUpdate({ _id: item._id }, {
      lifecycle: Object.assign({}, normalized, {
        migration: Object.assign({}, normalized.migration, {
          lastMigratedAt: new Date()
        })
      })
    });
    report.migrated += 1;
    if (hasUnmapped) {
      report.unmapped.push({
        accountId: String(item._id),
        legacyPrimaryAffiliation: normalized.migration.legacyPrimaryAffiliation || null,
        unmappedAffiliations: normalized.migration.unmappedAffiliations || [],
        unmappedAccessProfiles: normalized.migration.unmappedAccessProfiles || []
      });
    }
  }

  console.log(JSON.stringify(report, null, 2));
  await mongoose.disconnect();
}

run().catch(async (error) => {
  console.error(error);
  try {
    await mongoose.disconnect();
  } catch (disconnectError) {}
  process.exit(1);
});
