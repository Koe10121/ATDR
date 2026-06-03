'use strict';

require('dotenv').config({
  path: process.env.DOTENV_CONFIG_PATH || process.env.dotenv_config_path || undefined
});

const mongoose = require('mongoose');
const config = require('../config/config');
const configureMongoose = require('../helpers/configure-mongoose');
const AccountModel = require('../server/Project/accounts/models/account.model');
const {
  ensureAccountStatusMasterData
} = require('../server/Project/accounts/service/account-status');
const {
  ensureBootstrapAccessForAccount
} = require('../server/Project/security/service/bootstrap-access');
const RuntimeAccess = require('../server/Project/settings/controller/runtime_access');
const TypeModel = require('../server/Project/security/models/type.model');
const MenuModel = require('../server/Project/security/models/menu.model');
const GroupModel = require('../server/Project/security/models/group.model');
const PermissionModel = require('../server/Project/security/models/permission.model');
const AssignmentModel = require('../server/Project/security/models/assignment.model');

const project = config.project || {};
const projectName = project.name || process.env.PROJECT_NAME || 'NewSystem';
const projectCode = String(project.code || process.env.PROJECT_CODE || 'newSystem')
  .trim()
  .toLowerCase()
  .replace(/[^a-z0-9]+/g, '-')
  .replace(/^-+|-+$/g, '') || 'newSystem';
const projectAcronym = projectName
  .split(/[^a-zA-Z0-9]+/)
  .filter(Boolean)
  .map((part) => part.charAt(0).toUpperCase())
  .join('')
  .slice(0, 6) || projectCode.replace(/-/g, '').toUpperCase().slice(0, 6);

function splitEnvList(value) {
  return String(value || '')
    .split(',')
    .map((item) => String(item || '').trim())
    .filter(Boolean);
}

async function resolveAccounts() {
  const accounts = [];
  const accountIds = splitEnvList(process.env.PROJECT_INIT_ADMIN_ACCOUNT_IDS);
  const accountEmails = splitEnvList(process.env.PROJECT_INIT_ADMIN_EMAILS).map((item) => item.toLowerCase());

  for (const id of accountIds) {
    if (!mongoose.Types.ObjectId.isValid(id)) continue;
    const account = await AccountModel.findOne({ _id: new mongoose.Types.ObjectId(id) });
    if (account) accounts.push(account);
  }

  for (const email of accountEmails) {
    const account = await AccountModel.findOne({
      $or: [
        { email: email },
        { 'authen.email': email }
      ]
    });

    if (account && !accounts.find((item) => String(item._id) === String(account._id))) {
      accounts.push(account);
    }
  }

  return accounts;
}

async function seedAdminAccountIfRequested() {
  const email = String(process.env.PROJECT_INIT_SEED_ADMIN_EMAIL || '').trim().toLowerCase();
  if (!email) return null;

  const sessionToken = String(process.env.PROJECT_INIT_SEED_ADMIN_X_ACCESS_TOKEN || '').trim();
  const requestedAccountId = String(process.env.PROJECT_INIT_SEED_ADMIN_ACCOUNT_ID || '').trim();
  const accountObjectId = mongoose.Types.ObjectId.isValid(requestedAccountId)
    ? new mongoose.Types.ObjectId(requestedAccountId)
    : null;
  const firstName = String(process.env.PROJECT_INIT_SEED_ADMIN_FIRSTNAME || projectName).trim();
  const lastName = String(process.env.PROJECT_INIT_SEED_ADMIN_LASTNAME || 'Admin').trim();

  const update = {
    dateTime: new Date(),
    code: process.env.PROJECT_INIT_SEED_ADMIN_CODE || projectAcronym + '-INIT-ADMIN',
    email: email,
    authen: [{
      username: email,
      password: null,
      email: email,
      oAtuhToken: null
    }],
    userinfo: {
      firstName: [{ key: 'en', value: firstName }],
      lastName: [{ key: 'en', value: lastName }],
      image: null
    },
    verification: []
  };

  if (sessionToken) {
    update.control = {
      sso: false,
      limit: 4,
      trustedDevices: [],
      device: [{
        version: '1',
        ip: '127.0.0.1',
        device: 'init-' + projectCode + '-core',
        dateTime: new Date(),
        xAccessToken: sessionToken,
        expired_key: Math.floor(Date.now() / 1000) + 86400,
        deviceId: projectCode + '-init-device',
        fingerprint: projectCode + '-init-fingerprint',
        networkKey: '127.0.0',
        rememberDeviceRequested: false
      }]
    };
  }

  return AccountModel.findOneAndUpdate(
    accountObjectId
      ? {
        $or: [
          { _id: accountObjectId },
          { email: email }
        ]
      }
      : { email: email },
    Object.assign(
      { $set: update },
      accountObjectId ? { $setOnInsert: { _id: accountObjectId } } : {}
    ),
    { upsert: true, new: true }
  );
}

async function countSummary() {
  const [
    accounts,
    statusGroups,
    statuses,
    types,
    menus,
    groups,
    permissions,
    assignments
  ] = await Promise.all([
    AccountModel.countDocuments({}),
    mongoose.connection.collection('Setting_Group').countDocuments({}),
    mongoose.connection.collection('Setting_Status').countDocuments({}),
    TypeModel.countDocuments({}),
    MenuModel.countDocuments({}),
    GroupModel.countDocuments({}),
    PermissionModel.countDocuments({}),
    AssignmentModel.countDocuments({})
  ]);

  return {
    accounts,
    statusGroups,
    statuses,
    types,
    menus,
    groups,
    permissions,
    assignments
  };
}

async function run() {
  configureMongoose(mongoose);
  await mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

  const statusMaster = await ensureAccountStatusMasterData();
  const runtimeAccess = await RuntimeAccess.ensureDefaultRecord();
  const seededAccount = await seedAdminAccountIfRequested();
  const accounts = await resolveAccounts();

  if (seededAccount && !accounts.find((item) => String(item._id) === String(seededAccount._id))) {
    accounts.push(seededAccount);
  }

  const assignedAccounts = [];
  for (const account of accounts) {
    await ensureBootstrapAccessForAccount(account._id);
    assignedAccounts.push({
      accountId: String(account._id),
      accountEmail: account.email || null
    });
  }

  const summary = await countSummary();

  console.log(JSON.stringify({
    ok: true,
    statusGroupId: String(statusMaster.group._id),
    statusKeys: Object.keys(statusMaster.statuses),
    runtimeAccess: runtimeAccess && runtimeAccess.doc ? {
      id: String(runtimeAccess.doc._id),
      created: !!runtimeAccess.created
    } : null,
    assignedAccounts,
    seededAccount: seededAccount ? {
      accountId: String(seededAccount._id),
      accountEmail: seededAccount.email || null
    } : null,
    summary
  }, null, 2));

  await mongoose.connection.close();
}

run().catch(async function (err) {
  console.error(JSON.stringify({
    ok: false,
    message: err.message
  }, null, 2));
  try {
    await mongoose.connection.close();
  } catch (closeError) {}
  process.exit(1);
});
