'use strict';

require('dotenv').config({
  path: process.env.DOTENV_CONFIG_PATH || process.env.dotenv_config_path || undefined
});

const crypto = require('crypto');

const axios = require('axios');
const { MongoClient } = require('mongodb');

function firstNonEmpty() {
  for (let index = 0; index < arguments.length; index += 1) {
    const value = arguments[index];
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return String(value).trim();
    }
  }
  return '';
}

function createHttpClient(baseUrl, token) {
  return axios.create({
    baseURL: String(baseUrl || '').replace(/\/+$/, ''),
    timeout: Number(process.env.IAM_SDK_TIMEOUT_MS || 5000),
    headers: {
      'x-access-token': token,
      'user-agent': 'newSystem-live-smoke/1.0',
      lang: 'en'
    },
    validateStatus: function () {
      return true;
    }
  });
}

async function requestAndAssert(client, method, path, options) {
  const response = await client.request({
    method: method,
    url: path,
    params: options && options.params ? options.params : undefined,
    data: options && Object.prototype.hasOwnProperty.call(options, 'data') ? options.data : undefined
  });

  const expectedStatus = options && options.expectedStatus ? options.expectedStatus : 200;
  if (response.status !== expectedStatus) {
    const error = new Error(String(method).toUpperCase() + ' ' + path + ' returned ' + response.status);
    error.response = response;
    throw error;
  }

  return response.data;
}

async function createTemporaryIamSession() {
  const uri = firstNonEmpty(
    process.env.PROJECT_LIVE_TEST_IAM_MONGODB_URI,
    process.env.IAM_LIVE_TEST_MONGODB_URI
  );
  const email = firstNonEmpty(
    process.env.PROJECT_LIVE_TEST_ACCOUNT_EMAIL,
    process.env.PROJECT_PERMISSION_ACCOUNT_EMAIL
  ).toLowerCase();

  if (!uri) {
    throw new Error('PROJECT_LIVE_TEST_IAM_MONGODB_URI is required for live smoke');
  }
  if (!email) {
    throw new Error('PROJECT_LIVE_TEST_ACCOUNT_EMAIL or PROJECT_PERMISSION_ACCOUNT_EMAIL is required for live smoke');
  }

  const mongoClient = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 });
  const token = 'newSystem-live-smoke-' + crypto.randomBytes(16).toString('hex');
  const now = new Date();
  const expiresAtUnix = Math.floor(Date.now() / 1000) + 1800;
  const sessionPayload = {
    version: '1',
    ip: '127.0.0.1',
    device: 'newSystem-live-smoke-script',
    dateTime: now,
    xAccessToken: token,
    expired_key: expiresAtUnix,
    deviceId: 'newSystem-live-smoke-device',
    fingerprint: crypto.createHash('sha256').update('newSystem-live-smoke-device|newSystem-live-smoke-script').digest('hex'),
    networkKey: '127.0.0',
    clientId: firstNonEmpty(process.env.IAM_SDK_CLIENT_ID),
    audience: firstNonEmpty(process.env.IAM_SDK_AUDIENCE),
    system: 'newSystem',
    rememberDeviceRequested: false
  };

  await mongoClient.connect();
  const db = mongoClient.db('IAM');
  const collection = db.collection('Information_Accounts');
  const account = await collection.findOne({
    $or: [
      { email: email },
      { 'authen.email': email }
    ]
  }, {
    projection: {
      _id: 1,
      email: 1
    }
  });

  if (!account || !account._id) {
    await mongoClient.close();
    throw new Error('IAM account not found for ' + email);
  }

  await collection.updateOne(
    { _id: account._id },
    {
      $pull: {
        'control.device': {
          xAccessToken: token
        }
      }
    }
  );

  await collection.updateOne(
    { _id: account._id },
    {
      $push: {
        'control.device': sessionPayload
      }
    }
  );

  return {
    mongoClient: mongoClient,
    collection: collection,
    accountObjectId: account._id,
    accountId: String(account._id),
    accountEmail: account.email || email,
    token: token
  };
}

async function removeTemporaryToken(state) {
  if (!state || !state.collection || !state.accountObjectId || !state.token) return;
  await state.collection.updateOne(
    { _id: state.accountObjectId },
    {
      $pull: {
        'control.device': {
          xAccessToken: state.token
        }
      }
    }
  );
}

async function main() {
  const baseServerUrl = firstNonEmpty(process.env.BASE_SERVER_URL, process.env.PROJECT_BASE_URL);
  if (!baseServerUrl) {
    throw new Error('BASE_SERVER_URL or PROJECT_BASE_URL is required');
  }

  const session = await createTemporaryIamSession();

  try {
    const client = createHttpClient(baseServerUrl, session.token);

    const authMe = await requestAndAssert(client, 'get', '/api/v1/auth/me');
    const authSessions = await requestAndAssert(client, 'get', '/api/v1/auth/sessions');
    const myPermissions = await requestAndAssert(client, 'get', '/api/v1/security/permission/my');
    const accounts = await requestAndAssert(client, 'get', '/api/v1/accounts');
    const accountGroups = await requestAndAssert(client, 'get', '/api/v1/accounts/group/options');
    const accountStatuses = await requestAndAssert(client, 'get', '/api/v1/accounts/status/options');

    const effectiveAccountId = firstNonEmpty(session.accountId, authMe && authMe.data && authMe.data._id);
    const effectivePermissions = await requestAndAssert(
      client,
      'get',
      '/api/v1/accounts/' + effectiveAccountId + '/effective-permissions'
    );

    const sessionRows = authSessions && authSessions.data && Array.isArray(authSessions.data.sessions)
      ? authSessions.data.sessions
      : [];
    const accountRows = accounts && Array.isArray(accounts.data) ? accounts.data : [];
    const groupRows = accountGroups && accountGroups.data && Array.isArray(accountGroups.data.groups)
      ? accountGroups.data.groups
      : [];
    const statusRows = accountStatuses && accountStatuses.data && Array.isArray(accountStatuses.data.statuses)
      ? accountStatuses.data.statuses
      : [];
    const permissionMatrix = myPermissions && myPermissions.data && myPermissions.data.matrix
      ? myPermissions.data.matrix
      : {};
    const effectiveMatrix = effectivePermissions && effectivePermissions.data && effectivePermissions.data.matrix
      ? effectivePermissions.data.matrix
      : {};

    console.log(JSON.stringify({
      ok: true,
      account: {
        accountId: session.accountId,
        email: session.accountEmail
      },
      checks: {
        authMeEmail: authMe && authMe.data ? authMe.data.email : null,
        sessionCount: sessionRows.length,
        currentSessionVisible: sessionRows.some(function (item) { return !!(item && item.current); }),
        accountListCount: accountRows.length,
        accountVisibleInScope: accountRows.some(function (item) {
          return item && String(item.email || '').toLowerCase() === session.accountEmail.toLowerCase();
        }),
        groupOptionLabels: groupRows.map(function (item) { return item && item.label ? String(item.label) : ''; }).filter(Boolean),
        statusOptionKeys: statusRows.map(function (item) { return item && item.key ? String(item.key) : ''; }).filter(Boolean),
        permissionPaths: Object.keys(permissionMatrix).sort(),
        effectivePermissionPaths: Object.keys(effectiveMatrix).sort()
      }
    }, null, 2));
  } finally {
    await removeTemporaryToken(session).catch(function () {});
    await session.mongoClient.close().catch(function () {});
  }
}

main().catch(async function (error) {
  console.error(JSON.stringify({
    ok: false,
    message: error.message,
    response: error.response && error.response.data ? error.response.data : null
  }, null, 2));
  process.exit(1);
});
