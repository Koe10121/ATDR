'use strict';

const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const { cleanupAuditRetention } = require('../server/Project/security/service/audit-retention-cleanup');

function readRetentionDays() {
  const flag = process.argv.find(function (item) {
    return String(item).indexOf('--retention-days=') === 0;
  });
  const fromFlag = flag ? flag.split('=').slice(1).join('=') : '';
  const raw = fromFlag || (cfg.security && cfg.security.auditRetentionDays) || '90';
  return Number(raw);
}

async function main() {
  const execute = process.argv.includes('--execute');
  const retentionDays = readRetentionDays();

  await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
  const summary = await cleanupAuditRetention(mongoose.connection.db, {
    execute: execute,
    retentionDays: retentionDays
  });
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
