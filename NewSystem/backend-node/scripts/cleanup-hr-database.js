'use strict';

const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const { cleanupHrDatabase } = require('../server/Project/settings/service/hr-cleanup');

async function main() {
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
    const summary = await cleanupHrDatabase();
    console.log(JSON.stringify(summary, null, 2));
    await mongoose.disconnect();
}

main().catch(async function (error) {
    console.error(error && error.stack ? error.stack : error);
    try {
        await mongoose.disconnect();
    } catch (err) {}
    process.exit(1);
});
