'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const path = require('path');
const test = require('node:test');
const { promisify } = require('node:util');

const { createMockIamServer } = require('./mock-iam-server');

const execFileAsync = promisify(execFile);

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

test('bootstrap script provisions template-managed permission data through IAM admin APIs', async function () {
  const scriptPath = path.resolve(__dirname, '../scripts/bootstrap-iam-permissions.js');
  const execution = await execFileAsync(process.execPath, [scriptPath], {
    cwd: path.resolve(__dirname, '..'),
    env: Object.assign({}, process.env, {
      PROJECT_CODE: 'newSystem',
      PROJECT_NAME: 'NewSystem',
      PROJECT_PERMISSION_TYPE_TITLE: 'New System Administration',
      PROJECT_PERMISSION_GROUP_TITLE: 'NewSystem Owners',
      PROJECT_PERMISSION_ROOT_PATH: '/sample/security/permission',
      PROJECT_PERMISSION_PATHS: '/sample/security/permission,/dashboard,/reports',
      IAM_SDK_BASE_URL: baseUrl,
      IAM_SDK_CLIENT_ID: 'sample-sdk',
      IAM_SDK_CLIENT_SECRET: 'super-secret',
      IAM_SDK_AUDIENCE: 'new-system-api',
      IAM_SDK_ADMIN_AUDIENCE: 'iam-admin-api',
      IAM_SDK_SCOPE: 'sample.read sample.write iam.security.read iam.security.write iam.audit.read iam.accounts.read'
    })
  });

  const payload = JSON.parse(execution.stdout);

  assert.equal(payload.ok, true);
  assert.equal(payload.compatProfile, 'b2b-admin-v1');
  assert.equal(payload.menuCount, payload.paths.length);
  assert.ok(payload.paths.includes('/sample/security/permission'));
  assert.ok(payload.paths.includes('/dashboard'));
  assert.ok(payload.paths.includes('/reports'));
  assert.ok(payload.paths.includes('/accounts/directory'));
});
