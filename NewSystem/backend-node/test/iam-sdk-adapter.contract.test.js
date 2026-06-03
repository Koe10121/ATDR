'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildBasicAuthorization,
  createIamSdkAdapter,
  normalizeAudience,
  normalizeScope
} = require('../server/integrations/iam/iam-sdk-adapter');
const { createMockIamServer } = require('./mock-iam-server');

let mockServer;
let baseUrl;

test.before(async function () {
  mockServer = createMockIamServer();
  const serverInfo = await mockServer.start();
  baseUrl = serverInfo.baseUrl;
});

test.after(async function () {
  await mockServer.stop();
});

test('IAM adapter normalizes scopes, audience, and basic authorization', function () {
  assert.equal(normalizeScope(['sample.read', 'sample.read', 'iam.security.write']), 'sample.read iam.security.write');
  assert.equal(normalizeScope('sample.read sample.read iam.security.write'), 'sample.read iam.security.write');
  assert.equal(normalizeAudience(['new-system-api']), 'new-system-api');
  assert.equal(
    buildBasicAuthorization('client-a', 'secret-b'),
    'Basic ' + Buffer.from('client-a:secret-b').toString('base64')
  );
});

test('IAM adapter handles token, profile, and admin operations end-to-end', async function () {
  const sdk = createIamSdkAdapter({
    baseUrl: baseUrl,
    clientId: 'sample-sdk',
    clientSecret: 'super-secret',
    token: {
      scope: 'sample.read sample.write iam.security.write iam.audit.read iam.accounts.read',
      audience: 'new-system-api'
    },
    admin: {
      scope: 'iam.security.write iam.audit.read iam.accounts.read',
      audience: 'iam-admin-api'
    }
  });

  const firstToken = await sdk.getAccessToken();
  const secondToken = await sdk.getAccessToken();
  assert.equal(firstToken, secondToken);
  assert.equal(mockServer.state.tokenRequests, 1);

  const introspection = await sdk.introspectToken(firstToken);
  assert.equal(introspection.active, true);
  assert.equal(introspection.client_id, 'sample-sdk');

  const profile = await sdk.getClientProfile({ token: firstToken });
  assert.equal(profile.client_id, 'sample-sdk');
  assert.equal(profile.audience, 'new-system-api');

  const clientsBefore = await sdk.admin.listApplicationClients();
  assert.equal(clientsBefore.data.length, 1);

  const created = await sdk.admin.createApplicationClient({
    application: {
      ApplicationId: 'sample-created-client',
      AppId: 'SAMPLE',
      title: [{ key: 'en', value: 'Sample Created Client' }],
      description: [{ key: 'en', value: 'Sample Created Client' }],
      types: ['app']
    },
    environments: [{
      title: [{ key: 'en', value: 'prod' }],
      endpoint: 'https://api.sample.example.com',
      status: 'live',
      clientId: 'sample-created-client',
      server: {
        type: 'container'
      }
    }],
    status: 'active',
    metadata: {
      targetSystem: 'newSystem',
      partnerId: 'sample-team',
      tenant: 'iam-shared'
    }
  });
  assert.equal(created.data.application.AppId, 'SAMPLE');
  assert.equal(created.data.environments[0].clientId, 'sample-created-client');
  assert.equal(created.data.environments[0].clientSecret, 'mock-secret-100');

  const updated = await sdk.admin.updateApplicationClient({
    _id: created.data._id,
    application: Object.assign({}, created.data.application, {
      title: [{ key: 'en', value: 'Sample Updated Client' }]
    }),
    environments: created.data.environments,
    status: created.data.status,
    metadata: created.data.metadata
  });
  assert.equal(updated.data.application.title[0].value, 'Sample Updated Client');

  const rotated = await sdk.admin.rotateApplicationClientSecret(created.data._id, {
    environmentClientId: created.data.environments[0].clientId
  });
  assert.equal(rotated.data.clientSecret, 'rotated-secret-456');

  const types = await sdk.admin.listSecurityTypes();
  assert.equal(types.data.some(function (item) {
    return item && item._id === 'type-newSystem';
  }), true);

  const groups = await sdk.admin.listSecurityGroups();
  assert.equal(groups.data.some(function (item) {
    return item && item._id === 'group-2';
  }), true);

  const permissions = await sdk.admin.listSecurityPermissions();
  assert.equal(permissions.data[0].name, 'iam.security.write');

  const assignments = await sdk.admin.listSecurityAssignments();
  assert.equal(assignments.data[0].subject, 'sample-team');

  const account = await sdk.admin.lookupAccountByEmail('ops@example.com');
  assert.equal(account.data.email, 'ops@example.com');

  const accounts = await sdk.admin.listAccounts();
  assert.equal(accounts.data.some(function (item) {
    return item && item.email === 'ops@example.com';
  }), true);

  const effectivePermissions = await sdk.admin.getEffectivePermissions('acc-1');
  assert.equal(effectivePermissions.data.permissions.includes('newSystem.accounts.manage'), true);

  const deleted = await sdk.admin.deleteApplicationClient(created.data._id);
  assert.equal(deleted.data._id, created.data._id);

  const auditEvents = await sdk.admin.listAuditEvents();
  assert.ok(auditEvents.data.some(function (item) {
    return item.action === 'secret_rotated';
  }));
});
