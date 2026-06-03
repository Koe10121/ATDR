'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
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

test('register script provisions or rotates a NewSystem managed client and updates env.local-compatible values', async function () {
  const scriptPath = path.resolve(__dirname, '../scripts/register-newSystem-iam-client.js');
  const tempEnvFile = path.join(os.tmpdir(), `newSystem-register-${Date.now()}.env`);

  fs.writeFileSync(tempEnvFile, [
    'PROJECT_CODE=newSystem',
    'PROJECT_NAME=NewSystem',
    'PROJECT_ENV=local',
    'PROJECT_BASE_URL=http://127.0.0.1:8097',
    `IAM_SDK_BASE_URL=${baseUrl}`,
    'IAM_SDK_CLIENT_ID=sample-sdk',
    'IAM_SDK_CLIENT_SECRET=super-secret',
    'IAM_SDK_AUDIENCE=new-system-api',
    'IAM_SDK_ADMIN_AUDIENCE=iam-admin-api',
    'IAM_SDK_SCOPE=iam.security.read iam.security.write iam.audit.read iam.accounts.read',
    'PROJECT_PERMISSION_ACCOUNT_EMAIL=ops@example.com',
    'PROJECT_IAM_APPLICATION_ID=new-system-gateway',
    'PROJECT_IAM_APP_ID=new-system-sdk',
    'PROJECT_IAM_MANAGED_CLIENT_ID=new-system-gateway-local',
    'PROJECT_IAM_MANAGED_CLIENT_NAME=NewSystem Gateway Local',
    'PROJECT_IAM_MANAGED_CLIENT_ENDPOINT=http://127.0.0.1:8097',
    'PROJECT_IAM_MANAGED_CLIENT_OWNER_EMAIL=ops@example.com',
    'PROJECT_IAM_MANAGED_CLIENT_PARTNER_ID=new-system-team',
    'PROJECT_IAM_MANAGED_CLIENT_TENANT=iam-shared',
    'PROJECT_IAM_MANAGED_CLIENT_ALLOWED_SCOPES=new.system.read new.system.write',
    'PROJECT_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES=new-system-api'
  ].join('\n') + '\n', 'utf8');

  const execution = await execFileAsync(process.execPath, ['-r', 'dotenv/config', scriptPath, `dotenv_config_path=${tempEnvFile}`], {
    cwd: path.resolve(__dirname, '..'),
    env: Object.assign({}, process.env, {
      DOTENV_CONFIG_PATH: tempEnvFile
    })
  });

  const payload = JSON.parse(execution.stdout);
  const updatedEnv = fs.readFileSync(tempEnvFile, 'utf8');

  assert.equal(payload.ok, true);
  assert.equal(payload.permissionAccount.email, 'ops@example.com');
  assert.equal(payload.managedClient.clientId, 'new-system-gateway-local');
  assert.equal(payload.managedClient.audience, 'new-system-api');
  assert.equal(payload.managedClient.scope, 'new.system.read new.system.write');
  assert.match(updatedEnv, /^PROJECT_IAM_MANAGED_CLIENT_RECORD_ID=.+$/m);
  assert.match(updatedEnv, /^PROJECT_IAM_MANAGED_CLIENT_SECRET=.+$/m);
  assert.match(updatedEnv, /^PROJECT_PERMISSION_ACCOUNT_ID=acc-2$/m);
  assert.match(updatedEnv, /^PROJECT_INIT_ADMIN_EMAILS=ops@example.com$/m);
});

test('register script refuses to update a different managed client record with a reused application identity', async function () {
  const scriptPath = path.resolve(__dirname, '../scripts/register-newSystem-iam-client.js');
  const tempEnvFile = path.join(os.tmpdir(), `newSystem-register-collision-${Date.now()}.env`);

  fs.writeFileSync(tempEnvFile, [
    'PROJECT_CODE=newSystem',
    'PROJECT_NAME=NewSystem',
    'PROJECT_ENV=preprod',
    'PROJECT_BASE_URL=https://newSystem-preprod.example.com',
    `IAM_SDK_BASE_URL=${baseUrl}`,
    'IAM_SDK_CLIENT_ID=sample-sdk',
    'IAM_SDK_CLIENT_SECRET=super-secret',
    'IAM_SDK_AUDIENCE=new-system-api',
    'IAM_SDK_ADMIN_AUDIENCE=iam-admin-api',
    'IAM_SDK_SCOPE=iam.security.read iam.security.write iam.audit.read iam.accounts.read',
    'PROJECT_PERMISSION_ACCOUNT_EMAIL=ops@example.com',
    'PROJECT_IAM_APPLICATION_ID=sample-seed-client',
    'PROJECT_IAM_APP_ID=SAMPLE',
    'PROJECT_IAM_MANAGED_CLIENT_ID=new-system-gateway-preprod',
    'PROJECT_IAM_MANAGED_CLIENT_NAME=NewSystem Gateway Preprod',
    'PROJECT_IAM_MANAGED_CLIENT_ENDPOINT=https://newSystem-preprod.example.com',
    'PROJECT_IAM_MANAGED_CLIENT_OWNER_EMAIL=ops@example.com',
    'PROJECT_IAM_MANAGED_CLIENT_PARTNER_ID=new-system-team',
    'PROJECT_IAM_MANAGED_CLIENT_TENANT=iam-shared',
    'PROJECT_IAM_MANAGED_CLIENT_ALLOWED_SCOPES=new.system.read new.system.write',
    'PROJECT_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES=new-system-api'
  ].join('\n') + '\n', 'utf8');

  await assert.rejects(
    execFileAsync(process.execPath, ['-r', 'dotenv/config', scriptPath, `dotenv_config_path=${tempEnvFile}`], {
      cwd: path.resolve(__dirname, '..'),
      env: Object.assign({}, process.env, {
        DOTENV_CONFIG_PATH: tempEnvFile
      })
    }),
    function (error) {
      return error && /environment clientId new-system-gateway-preprod/.test(error.stderr || '');
    }
  );
});
