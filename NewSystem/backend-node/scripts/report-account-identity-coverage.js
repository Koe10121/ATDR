'use strict';

const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const Account = require('../server/Project/accounts/models/account.model');
const HrIdentity = require('../server/Project/settings/models/hr_identity_master.model');

async function main() {
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

    const linkedHrAccountIds = await HrIdentity.distinct('linkedAccount', { linkedAccount: { $ne: null } });
    const linkedSet = new Set(linkedHrAccountIds.map(function (item) { return String(item); }));
    const accounts = await Account.find({}, { code: 1, email: 1, userinfo: 1, hrContext: 1, lifecycle: 1 }).lean();

    const summary = {
        totalAccounts: accounts.length,
        linkedHrAccounts: 0,
        hrSnapshotOnlyAccounts: 0,
        nonHrAccounts: 0,
        googleAccounts: 0
    };

    const details = accounts.map(function (item) {
        const accountId = String(item && item._id);
        const isLinkedHr = linkedSet.has(accountId);
        const hasHrSnapshot = !!(item && item.hrContext && item.hrContext.snapshot);
        const isGoogle = String(item && item.code || '').startsWith('GOOG-');
        const firstName = Array.isArray(item && item.userinfo && item.userinfo.firstName) && item.userinfo.firstName[0] ? item.userinfo.firstName[0].value : '';
        const lastName = Array.isArray(item && item.userinfo && item.userinfo.lastName) && item.userinfo.lastName[0] ? item.userinfo.lastName[0].value : '';

        if (isLinkedHr) summary.linkedHrAccounts += 1;
        else if (hasHrSnapshot) summary.hrSnapshotOnlyAccounts += 1;
        else summary.nonHrAccounts += 1;
        if (isGoogle) summary.googleAccounts += 1;

        return {
            accountId: accountId,
            code: item && item.code ? String(item.code) : null,
            email: item && item.email ? String(item.email) : null,
            fullName: [firstName, lastName].filter(Boolean).join(' ').trim() || null,
            provisioningState: item && item.lifecycle && item.lifecycle.provisioning && item.lifecycle.provisioning.state ? String(item.lifecycle.provisioning.state) : null,
            isLinkedHr: isLinkedHr,
            hasHrSnapshot: hasHrSnapshot,
            isGoogle: isGoogle,
            category: isLinkedHr ? 'LINKED_HR' : (hasHrSnapshot ? 'HR_SNAPSHOT_ONLY' : 'NON_HR')
        };
    });

    console.log(JSON.stringify({ summary: summary, details: details }, null, 2));
    await mongoose.disconnect();
}

main().catch(async function (error) {
    console.error(error && error.stack ? error.stack : error);
    try {
        await mongoose.disconnect();
    } catch (err) {}
    process.exit(1);
});
