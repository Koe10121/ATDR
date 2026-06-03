'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const express = require('express');

const newSystemConfig = require('../../../config/config');
const { createMockIamServer } = require('../../../test/mock-iam-server');

const ROUTER_PATH = path.resolve(__dirname, './accounts.routes');

let mockServer;
let appServer;

async function startHttpApp() {
  const router = require(ROUTER_PATH);
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  await new Promise(function (resolve) {
    appServer = app.listen(0, '127.0.0.1', resolve);
  });
  const address = appServer.address();
  return `http://127.0.0.1:${address.port}`;
}

async function stopHttpApp() {
  if (!appServer) return;
  await new Promise(function (resolve, reject) {
    appServer.close(function (error) {
      if (error) return reject(error);
      resolve();
    });
  });
  appServer = null;
}

async function requestJson(baseAppUrl, method, pathName, options) {
  const response = await fetch(`${baseAppUrl}${pathName}`, {
    method: method,
    headers: Object.assign({
      'Content-Type': 'application/json'
    }, options && options.headers ? options.headers : {}),
    body: options && Object.prototype.hasOwnProperty.call(options, 'body')
      ? JSON.stringify(options.body)
      : undefined
  });
  return {
    status: response.status,
    body: await response.json()
  };
}

function setNewSystemAccountAssignments(accountId) {
  mockServer.state.accountAssignments = [
    {
      _id: 'acct-assign-newSystem',
      account: accountId || 'acc-1',
      group: { _id: 'group-2', name: 'New System Admin' },
      active: true,
      dataScope: 'org',
      scopeUnits: []
    }
  ];
}

function resetUserSession() {
  mockServer.state.userSessions = new Map([
    ['user-token-1', {
      account: {
        _id: 'acc-1',
        email: 'newSystem.ops@example.com',
        status: { key: 'ACTIVE' },
        control: { device: [], trustedDevices: [] }
      },
      sessions: [{ _id: 'session-1', current: true }],
      trustedDevices: [{ _id: 'trusted-1', deviceId: 'browser-1' }]
    }]
  ]);
}

test.before(async function () {
  mockServer = createMockIamServer();
  const serverInfo = await mockServer.start();

  newSystemConfig.iam.baseUrl = serverInfo.baseUrl;
  newSystemConfig.iam.timeout = 5000;
  newSystemConfig.iamAdmin.baseUrl = serverInfo.baseUrl;
  newSystemConfig.iamAdmin.tokenPath = '/api/v1/b2b/token';
  newSystemConfig.iamAdmin.basePath = '/api/v1/b2b/admin';
  newSystemConfig.iamAdmin.clientId = 'new-system-sdk';
  newSystemConfig.iamAdmin.clientSecret = 'super-secret';
  newSystemConfig.iamAdmin.scope = 'new.system.registry.read new.system.registry.write new.system.report.read iam.security.read iam.security.write iam.audit.read iam.accounts.read';
  newSystemConfig.iamAdmin.audience = 'new-system-api';
  newSystemConfig.security.permissionSource = 'iam';
});

test.after(async function () {
  delete require.cache[ROUTER_PATH];
  await stopHttpApp();
  await mockServer.stop();
});

test.beforeEach(function () {
  resetUserSession();
});

test('accounts routes proxy signin and auth me to IAM', async function () {
  setNewSystemAccountAssignments('acc-1');
  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const signinResult = await requestJson(appBaseUrl, 'POST', '/api/v1/signin', {
    body: { email: 'newSystem.ops@example.com' }
  });
  assert.equal(signinResult.status, 200);
  assert.equal(signinResult.body.data.xAccessToken, 'user-token-1');

  const meResult = await requestJson(appBaseUrl, 'GET', '/api/v1/auth/me', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(meResult.status, 200);
  assert.equal(meResult.body.data._id, 'acc-1');

  await stopHttpApp();
});

test('accounts routes reject signin when account is not in newSystem scope', async function () {
  mockServer.state.accountAssignments = [
    {
      _id: 'acct-assign-iam',
      account: 'acc-1',
      group: { _id: 'group-1', name: 'IAM Governance' },
      active: true,
      dataScope: 'org',
      scopeUnits: []
    }
  ];

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const signinResult = await requestJson(appBaseUrl, 'POST', '/api/v1/signin', {
    body: { email: 'newSystem.ops@example.com' }
  });
  assert.equal(signinResult.status, 403);
  assert.equal(signinResult.body.error, 'account_not_in_newSystem_scope');

  const meResult = await requestJson(appBaseUrl, 'GET', '/api/v1/auth/me', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(meResult.status, 404);

  await stopHttpApp();
});

test('accounts routes proxy account update to IAM after IAM-backed authorization', async function () {
  mockServer.state.permissionMatrix = {
    '/accounts/directory': { view: true, edit: true, action: true },
    '/accounts/lifecycle': { view: true, edit: true, action: true }
  };
  setNewSystemAccountAssignments('acc-1');

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const updateResult = await requestJson(appBaseUrl, 'PUT', '/api/v1/accounts/acc-1', {
    headers: {
      'x-access-token': 'user-token-1'
    },
    body: {
      email: 'newSystem.updated@example.com'
    }
  });

  assert.equal(updateResult.status, 200);
  assert.equal(updateResult.body.data.email, 'newSystem.updated@example.com');
  assert.equal(mockServer.state.accounts[0].email, 'newSystem.updated@example.com');

  await stopHttpApp();
});

test('accounts routes expose only newSystem assigned accounts', async function () {
  mockServer.state.permissionMatrix = {
    '/accounts/directory': { view: true, edit: true, action: true }
  };
  mockServer.state.accounts = [
    {
      _id: 'acc-1',
      email: 'newSystem.ops@example.com',
      securityGroups: [
        { _id: 'group-1', title: [{ key: 'en', value: 'IAM Governance' }] },
        { _id: 'group-2', title: [{ key: 'en', value: 'New System Admin' }] }
      ]
    },
    { _id: 'acc-iam', email: 'iam.admin@mfu.ac.th' }
  ];
  mockServer.state.accountAssignments = [
    {
      _id: 'acct-assign-newSystem',
      account: { _id: 'acc-1', email: 'newSystem.ops@example.com' },
      group: { _id: 'group-2', name: 'New System Admin' },
      active: true,
      dataScope: 'org',
      scopeUnits: []
    },
    {
      _id: 'acct-assign-iam',
      account: 'acc-iam',
      group: { _id: 'group-1', name: 'IAM Governance' },
      active: true,
      dataScope: 'org',
      scopeUnits: []
    }
  ];

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const accountsResult = await requestJson(appBaseUrl, 'GET', '/api/v1/accounts', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(accountsResult.status, 200);
  assert.deepEqual(
    accountsResult.body.data.map(function (item) { return item.email; }),
    ['newSystem.ops@example.com']
  );
  assert.deepEqual(
    accountsResult.body.data[0].securityGroups.map(function (item) { return item && item._id; }),
    ['group-2']
  );

  const updateIamAccountResult = await requestJson(appBaseUrl, 'PUT', '/api/v1/accounts/acc-iam', {
    headers: {
      'x-access-token': 'user-token-1'
    },
    body: {
      email: 'iam.updated@example.com'
    }
  });
  assert.equal(updateIamAccountResult.status, 404);
  assert.equal(updateIamAccountResult.body.error, 'account_not_in_newSystem_scope');
  assert.equal(mockServer.state.accounts[1].email, 'iam.admin@mfu.ac.th');

  await stopHttpApp();
});

test('accounts routes remove only newSystem access from account', async function () {
  mockServer.state.permissionMatrix = {
    '/accounts/directory': { view: true, edit: true, action: true }
  };
  mockServer.state.accounts = [
    { _id: 'acc-1', email: 'newSystem.ops@example.com' }
  ];
  mockServer.state.accountAssignments = [
    {
      _id: 'acct-assign-newSystem',
      account: { _id: 'acc-1', email: 'newSystem.ops@example.com' },
      group: { _id: 'group-2', name: 'New System Admin' },
      active: true,
      dataScope: 'org',
      scopeUnits: []
    },
    {
      _id: 'acct-assign-iam',
      account: { _id: 'acc-1', email: 'newSystem.ops@example.com' },
      group: { _id: 'group-1', name: 'IAM Governance' },
      active: true,
      dataScope: 'org',
      scopeUnits: []
    }
  ];

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const removeResult = await requestJson(appBaseUrl, 'DELETE', '/api/v1/accounts/acc-1/newSystem-access', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(removeResult.status, 200);
  assert.equal(removeResult.body.data.removed, 1);
  assert.deepEqual(
    mockServer.state.accountAssignments.map(function (item) { return item._id; }),
    ['acct-assign-iam']
  );

  const accountsResult = await requestJson(appBaseUrl, 'GET', '/api/v1/accounts', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(accountsResult.status, 200);
  assert.deepEqual(accountsResult.body.data, []);

  await stopHttpApp();
});

test('accounts routes invite account into newSystem scope', async function () {
  mockServer.state.permissionMatrix = {
    '/accounts/directory': { view: true, edit: true, action: true }
  };
  mockServer.state.accounts = [
    { _id: 'acc-1', email: 'newSystem.ops@example.com' }
  ];
  mockServer.state.accountAssignments = [];

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const inviteResult = await requestJson(appBaseUrl, 'POST', '/api/v1/accounts/invite', {
    headers: {
      'x-access-token': 'user-token-1'
    },
    body: {
      email: 'new.newSystem@example.com',
      firstName: 'New',
      lastName: 'NewSystem',
      groupIds: ['group-2', 'group-1']
    }
  });
  assert.equal(inviteResult.status, 201);
  assert.equal(inviteResult.body.data.account.email, 'new.newSystem@example.com');
  assert.deepEqual(
    inviteResult.body.data.groups.map(function (item) { return item && item._id; }),
    ['group-2']
  );
  assert.equal(mockServer.state.accountAssignments.some(function (item) {
    return item.group && item.group._id === 'group-1';
  }), false);

  const accountsResult = await requestJson(appBaseUrl, 'GET', '/api/v1/accounts', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(accountsResult.status, 200);
  assert.deepEqual(
    accountsResult.body.data.map(function (item) { return item.email; }),
    ['new.newSystem@example.com']
  );

  await stopHttpApp();
});

test('accounts routes expose only newSystem scoped sessions and trusted devices', async function () {
  mockServer.state.permissionMatrix = {
    '/accounts/directory': { view: true, edit: true, action: true }
  };
  setNewSystemAccountAssignments('acc-1');
  const session = mockServer.state.userSessions.get('user-token-1');
  session.sessions = [
    {
      _id: 'newSystem-session',
      deviceId: 'newSystem-browser',
      clientId: 'new-system-sdk',
      audience: 'new-system-api',
      system: 'newSystem'
    },
    {
      _id: 'iam-session',
      deviceId: 'iam-browser',
      clientId: 'iam-console',
      audience: 'iam-admin-api',
      system: 'iam'
    }
  ];
  session.trustedDevices = [
    {
      _id: 'newSystem-device',
      deviceId: 'newSystem-browser',
      clientId: 'new-system-sdk',
      audience: 'new-system-api',
      system: 'newSystem'
    },
    {
      _id: 'iam-device',
      deviceId: 'iam-browser',
      clientId: 'iam-console',
      audience: 'iam-admin-api',
      system: 'iam'
    }
  ];

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const sessionsResult = await requestJson(appBaseUrl, 'GET', '/api/v1/accounts/acc-1/sessions', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(sessionsResult.status, 200);
  assert.deepEqual(
    sessionsResult.body.data.sessions.map(function (item) { return item._id; }),
    ['newSystem-session']
  );

  const devicesResult = await requestJson(appBaseUrl, 'GET', '/api/v1/accounts/acc-1/trusted-devices', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(devicesResult.status, 200);
  assert.deepEqual(
    devicesResult.body.data.trustedDevices.map(function (item) { return item._id; }),
    ['newSystem-device']
  );

  await stopHttpApp();
});

test('accounts routes revoke only newSystem scoped sessions and trusted devices', async function () {
  mockServer.state.permissionMatrix = {
    '/accounts/directory': { view: true, edit: true, action: true }
  };
  setNewSystemAccountAssignments('acc-1');
  const session = mockServer.state.userSessions.get('user-token-1');
  session.sessions = [
    {
      _id: 'newSystem-session',
      deviceId: 'newSystem-browser',
      clientId: 'new-system-sdk',
      audience: 'new-system-api',
      system: 'newSystem'
    },
    {
      _id: 'shared-id',
      deviceId: 'iam-browser',
      clientId: 'iam-console',
      audience: 'iam-admin-api',
      system: 'iam'
    }
  ];
  session.trustedDevices = [
    {
      _id: 'newSystem-device',
      deviceId: 'newSystem-browser',
      clientId: 'new-system-sdk',
      audience: 'new-system-api',
      system: 'newSystem'
    },
    {
      _id: 'shared-device-id',
      deviceId: 'iam-browser',
      clientId: 'iam-console',
      audience: 'iam-admin-api',
      system: 'iam'
    }
  ];

  delete require.cache[ROUTER_PATH];
  const appBaseUrl = await startHttpApp();

  const revokeSessionResult = await requestJson(appBaseUrl, 'DELETE', '/api/v1/accounts/acc-1/sessions/newSystem-session', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(revokeSessionResult.status, 200);
  assert.equal(session.sessions.some(function (item) { return item._id === 'newSystem-session'; }), false);
  assert.equal(session.sessions.some(function (item) { return item._id === 'shared-id'; }), true);

  const revokeDeviceResult = await requestJson(appBaseUrl, 'DELETE', '/api/v1/accounts/acc-1/trusted-devices/newSystem-device', {
    headers: {
      'x-access-token': 'user-token-1'
    }
  });
  assert.equal(revokeDeviceResult.status, 200);
  assert.equal(session.trustedDevices.some(function (item) { return item._id === 'newSystem-device'; }), false);
  assert.equal(session.trustedDevices.some(function (item) { return item._id === 'shared-device-id'; }), true);

  await stopHttpApp();
});
