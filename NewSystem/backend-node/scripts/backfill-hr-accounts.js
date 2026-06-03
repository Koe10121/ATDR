'use strict';

const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const { backfillAccountsFromHrIdentities } = require('../server/Project/settings/service/hr_account_backfill');

function parseArgs(argv) {
    const result = { limit: 0 };
    for (let index = 0; index < argv.length; index += 1) {
        const item = argv[index];
        if (item === '--limit') result.limit = Number(argv[index + 1] || 0) || 0;
    }
    return result;
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
    const summary = await backfillAccountsFromHrIdentities({ limit: args.limit });
    console.log(JSON.stringify(summary, null, 2));
    await mongoose.connection.close();
}

main().catch(async function (error) {
    console.error(error && error.stack ? error.stack : error);
    try {
        await mongoose.connection.close();
    } catch (err) {}
    process.exit(1);
});
