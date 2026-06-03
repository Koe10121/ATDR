'use strict';

const mongoose = require('mongoose');
const cfg = require('../config/config');

const Account = require('../server/Project/accounts/controller/account');
const AccountModel = require('../server/Project/accounts/models/account.model');
const {
  ensureAccountStatusMasterData,
  resolveAccountStatus
} = require('../server/Project/accounts/service/account-status');

async function run() {
  await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

  const master = await ensureAccountStatusMasterData();
  const accounts = await AccountModel.find({}).select('_id status').lean();

  let migrated = 0;
  let unchanged = 0;

  for (const item of accounts) {
    const before = String(item && item.status ? item.status : '');
    const resolved = await resolveAccountStatus(Account, item);
    const after = String(
      resolved &&
      resolved.account &&
      resolved.account.status &&
      resolved.account.status._id
        ? resolved.account.status._id
        : resolved && resolved.status && resolved.status._id
          ? resolved.status._id
          : ''
    );

    if (before !== after) migrated += 1;
    else unchanged += 1;
  }

  console.log(JSON.stringify({
    group: master.group,
    statuses: Object.values(master.statuses),
    totals: {
      accounts: accounts.length,
      migrated,
      unchanged
    }
  }, null, 2));

  await mongoose.disconnect();
}

run().catch(async (error) => {
  console.error(error);
  try {
    await mongoose.disconnect();
  } catch (disconnectError) {}
  process.exit(1);
});
