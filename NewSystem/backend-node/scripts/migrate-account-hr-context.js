'use strict';

const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const AccountModel = require('../server/Project/accounts/models/account.model');
const { splitLifecycleStorage } = require('../server/Project/accounts/service/lifecycle-boundary');

function hasLegacyHrFields(lifecycle) {
    return !!(
        (Array.isArray(lifecycle && lifecycle.movements) && lifecycle.movements.length) ||
        (Array.isArray(lifecycle && lifecycle.leaves) && lifecycle.leaves.length) ||
        (Array.isArray(lifecycle && lifecycle.developments) && lifecycle.developments.length) ||
        (Array.isArray(lifecycle && lifecycle.assignments) && lifecycle.assignments.length) ||
        (lifecycle && lifecycle.hrSnapshot)
    );
}

async function main() {
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
    const accounts = await AccountModel.find({ lifecycle: { $exists: true } });
    const report = {
        total: accounts.length,
        migrated: 0,
        skipped: 0
    };

    for (const account of accounts) {
        const lifecycle = account.lifecycle || {};
        const hrContext = account.hrContext || {};
        if (!hasLegacyHrFields(lifecycle)) {
            report.skipped += 1;
            continue;
        }
        const persisted = splitLifecycleStorage(lifecycle, hrContext);
        account.lifecycle = persisted.lifecycle;
        account.hrContext = persisted.hrContext;
        await account.save();
        report.migrated += 1;
    }

    console.log(JSON.stringify(report, null, 2));
    await mongoose.disconnect();
}

main().catch(async function (error) {
    console.error(error && error.stack ? error.stack : error);
    try {
        await mongoose.disconnect();
    } catch (err) {}
    process.exit(1);
});
