'use strict';

require('dotenv').config();

const mongoose = require('mongoose');
const config = require('../config/config');
const configureMongoose = require('../helpers/configure-mongoose');
const AccountModel = require('../server/Project/accounts/models/account.model');
const { ensureBootstrapAccessForAccount } = require('../server/Project/security/service/bootstrap-access');

async function run() {
  configureMongoose(mongoose);
  await mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

  const sessionToken = process.env.PROJECT_E2E_ADMIN_X_ACCESS_TOKEN || 'newSystem-e2e-admin-token';
  const email = process.env.PROJECT_E2E_ADMIN_EMAIL || 'admin.e2e@local.test';

  const account = await AccountModel.findOneAndUpdate(
    { email: email },
    {
      $set: {
        dateTime: new Date(),
        code: 'M-E2E-ADMIN',
        email: email,
        authen: [{
          username: email,
          password: null,
          email: email,
          oAtuhToken: null
        }],
        userinfo: {
          firstName: [{ key: 'en', value: 'NewSystem' }],
          lastName: [{ key: 'en', value: 'Admin' }],
          image: null
        },
        control: {
          sso: false,
          limit: 4,
          trustedDevices: [],
          device: [{
            version: '1',
            ip: '127.0.0.1',
            device: 'seed-script',
            dateTime: new Date(),
            xAccessToken: sessionToken,
            expired_key: Math.floor(Date.now() / 1000) + 86400,
            deviceId: 'newSystem-seed-device',
            fingerprint: 'newSystem-seed-fingerprint',
            networkKey: '127.0.0',
            rememberDeviceRequested: false
          }]
        },
        verification: [],
        status: null
      }
    },
    { upsert: true, new: true }
  );

  await ensureBootstrapAccessForAccount(account._id);

  console.log(JSON.stringify({
    email: email,
    xAccessToken: sessionToken
  }));

  await mongoose.connection.close();
}

run().catch(async function (err) {
  console.error(err);
  try {
    await mongoose.connection.close();
  } catch (closeError) {}
  process.exit(1);
});
