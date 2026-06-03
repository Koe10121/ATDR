'use strict';

const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const { cleanupLocalSecurityOwnership } = require('../server/Project/security/service/local-security-cleanup');

async function main() {
  const execute = process.argv.includes('--execute');

  await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
  const summary = await cleanupLocalSecurityOwnership(mongoose.connection.db, {
    execute: execute
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
