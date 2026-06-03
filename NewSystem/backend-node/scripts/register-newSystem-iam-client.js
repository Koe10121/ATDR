'use strict';

require('dotenv').config({
  path: process.env.DOTENV_CONFIG_PATH || process.env.dotenv_config_path || undefined
});

const fs = require('fs');
const path = require('path');

const projectConfig = require('../config/project.config');
const { createNewSystemIamService } = require('../server/integrations/newSystem/newSystem-iam.service');

function firstNonEmpty() {
  for (let index = 0; index < arguments.length; index += 1) {
    const value = arguments[index];
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return String(value).trim();
    }
  }
  return '';
}

function slugify(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

function formatEnvironmentLabel(value) {
  const normalized = slugify(value || 'local');
  if (!normalized) return 'Local';
  return normalized
    .split('-')
    .map(function (part) {
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(' ');
}

function parseEnvList(value) {
  return String(value || '')
    .split(',')
    .map(function (item) { return String(item || '').trim().toLowerCase(); })
    .filter(Boolean);
}

function mergeEnvList() {
  return Array.from(new Set([].concat.apply([], Array.prototype.slice.call(arguments).map(parseEnvList)))).join(',');
}

function resolveEnvFilePath() {
  const configured = firstNonEmpty(process.env.DOTENV_CONFIG_PATH, process.env.dotenv_config_path, '.env.local');
  return path.resolve(process.cwd(), configured);
}

function upsertEnvValue(content, key, value) {
  const normalizedValue = String(value == null ? '' : value);
  const entry = key + '=' + normalizedValue;
  const pattern = new RegExp('^' + key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=.*$', 'm');

  if (pattern.test(content)) {
    return content.replace(pattern, entry);
  }

  const suffix = content.endsWith('\n') || content.length === 0 ? '' : '\n';
  return content + suffix + entry + '\n';
}

function updateEnvFile(filePath, updates) {
  let content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  Object.keys(updates).forEach(function (key) {
    content = upsertEnvValue(content, key, updates[key]);
  });
  fs.writeFileSync(filePath, content, 'utf8');
}

function createIamService() {
  return createNewSystemIamService({
    baseUrl: projectConfig.iam.baseUrl,
    clientId: projectConfig.iamAdmin.clientId,
    clientSecret: projectConfig.iamAdmin.clientSecret,
    timeoutMs: projectConfig.iamAdmin.timeoutMs,
    token: {
      path: projectConfig.iamAdmin.tokenPath,
      scope: projectConfig.iamAdmin.scope,
      audience: projectConfig.iamAdmin.audience
    },
    admin: {
      path: projectConfig.iamAdmin.basePath,
      scope: projectConfig.iamAdmin.scope,
      audience: projectConfig.iamAdmin.audience
    },
    endpoints: {
      introspectPath: projectConfig.iam.introspectPath,
      mePath: projectConfig.iam.profilePath
    }
  });
}

function ensureConfig() {
  if (!projectConfig.iamAdmin.baseUrl || !projectConfig.iamAdmin.clientId || !projectConfig.iamAdmin.clientSecret) {
    throw new Error('IAM admin client is not configured');
  }
}

function buildManagedClientConfig() {
  const project = projectConfig.project || {};
  const projectCode = firstNonEmpty(project.code, 'newSystem');
  const projectName = firstNonEmpty(project.name, 'NewSystem');
  const projectEnvironment = firstNonEmpty(project.environment, process.env.NODE_ENV, 'local');
  const projectScopePrefix = slugify(projectCode).replace(/-/g, '.');
  const projectBaseUrl = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_ENDPOINT,
    process.env.BASE_SERVER_URL,
    project.baseUrl,
    'http://127.0.0.1:8097'
  );
  const environmentLabel = formatEnvironmentLabel(projectEnvironment);
  const managedClientId = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_ID,
    slugify(projectCode) + '-gateway-' + slugify(projectEnvironment || 'local')
  );
  const managedClientName = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_NAME,
    projectName + ' Gateway ' + environmentLabel
  );
  const applicationId = firstNonEmpty(
    process.env.PROJECT_IAM_APPLICATION_ID,
    slugify(projectCode) + '-gateway'
  );
  const appId = firstNonEmpty(
    process.env.PROJECT_IAM_APP_ID,
    slugify(projectCode) + '-sdk'
  );
  const ownerEmail = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_OWNER_EMAIL,
    process.env.PROJECT_PERMISSION_ACCOUNT_EMAIL,
    'admin@mfu.ac.th'
  ).toLowerCase();
  const partnerId = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_PARTNER_ID,
    slugify(projectCode) + '-team'
  );
  const tenant = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_TENANT,
    'iam-shared'
  );
  const allowedScopes = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_ALLOWED_SCOPES,
    projectScopePrefix + '.read ' + projectScopePrefix + '.write'
  );
  const allowedAudiences = firstNonEmpty(
    process.env.PROJECT_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES,
    projectConfig.iam.requiredAudience,
    slugify(projectCode) + '-api'
  );

  return {
    projectCode: projectCode,
    projectName: projectName,
    projectEnvironment: projectEnvironment,
    projectBaseUrl: projectBaseUrl,
    managedClientId: managedClientId,
    managedClientName: managedClientName,
    applicationId: applicationId,
    appId: appId,
    ownerEmail: ownerEmail,
    partnerId: partnerId,
    tenant: tenant,
    allowedScopes: allowedScopes,
    allowedAudiences: allowedAudiences
  };
}

async function findExistingManagedClient(iamService, managedClientConfig) {
  const list = await iamService.listManagedClients();
  const rows = Array.isArray(list && list.data) ? list.data : [];
  const configuredRecordId = firstNonEmpty(process.env.PROJECT_IAM_MANAGED_CLIENT_RECORD_ID);

  return rows.find(function (item) {
    const environments = Array.isArray(item && item.environments) ? item.environments : [];
    const hasMatchingClientId = environments.some(function (environment) {
      return String(environment && environment.clientId || '') === managedClientConfig.managedClientId;
    });

    if (configuredRecordId && String(item && item._id || '') === configuredRecordId) {
      return true;
    }

    return hasMatchingClientId;
  }) || null;
}

async function findApplicationIdentityCollision(iamService, managedClientConfig) {
  const list = await iamService.listManagedClients();
  const rows = Array.isArray(list && list.data) ? list.data : [];
  const configuredRecordId = firstNonEmpty(process.env.PROJECT_IAM_MANAGED_CLIENT_RECORD_ID);

  if (configuredRecordId) return null;

  return rows.find(function (item) {
    const application = item && item.application ? item.application : {};
    const environments = Array.isArray(item && item.environments) ? item.environments : [];
    const hasMatchingClientId = environments.some(function (environment) {
      return String(environment && environment.clientId || '') === managedClientConfig.managedClientId;
    });

    if (hasMatchingClientId) return false;

    return String(application.ApplicationId || '') === managedClientConfig.applicationId ||
      String(application.AppId || '') === managedClientConfig.appId;
  }) || null;
}

function buildManagedClientPayload(managedClientConfig) {
  return {
    applicationId: managedClientConfig.applicationId,
    appId: managedClientConfig.appId,
    clientId: managedClientConfig.managedClientId,
    clientName: managedClientConfig.managedClientName,
    description: managedClientConfig.projectName + ' managed IAM application client',
    ownerEmail: managedClientConfig.ownerEmail,
    partnerId: managedClientConfig.partnerId,
    tenant: managedClientConfig.tenant,
    targetSystem: managedClientConfig.projectCode,
    systemCode: managedClientConfig.appId,
    allowedScopes: managedClientConfig.allowedScopes,
    allowedAudiences: managedClientConfig.allowedAudiences,
    metadata: {
      applicationId: managedClientConfig.applicationId,
      systemCode: managedClientConfig.appId,
      targetSystem: managedClientConfig.projectCode,
      ownerEmail: managedClientConfig.ownerEmail,
      partnerId: managedClientConfig.partnerId,
      tenant: managedClientConfig.tenant,
      environments: [{
        name: managedClientConfig.projectEnvironment,
        clientId: managedClientConfig.managedClientId,
        serverBaseUrl: managedClientConfig.projectBaseUrl,
        healthCheckUrl: managedClientConfig.projectBaseUrl.replace(/\/+$/, '') + '/api/v1/newsystem/documents/stats',
        docsUrl: managedClientConfig.projectBaseUrl.replace(/\/+$/, '') + '/swagger',
        ssl: managedClientConfig.projectBaseUrl.startsWith('https://') ? 'yes' : 'no',
        vpn: 'no',
        serverType: 'container'
      }]
    }
  };
}

function pickManagedEnvironment(record, clientId) {
  const environments = Array.isArray(record && record.environments) ? record.environments : [];
  return environments.find(function (environment) {
    return String(environment && environment.clientId || '') === String(clientId || '');
  }) || environments[0] || null;
}

async function ensureManagedClient(iamService, managedClientConfig) {
  const payload = buildManagedClientPayload(managedClientConfig);
  const existing = await findExistingManagedClient(iamService, managedClientConfig);

  if (existing && existing._id) {
    const updated = await iamService.updateManagedClient(Object.assign({ _id: existing._id }, payload));
    const rotated = await iamService.rotateManagedClientSecret(existing._id, {
      environmentClientId: managedClientConfig.managedClientId
    });
    const record = updated && updated.data ? updated.data : updated;
    const environment = pickManagedEnvironment(record, managedClientConfig.managedClientId);

    return {
      mode: 'updated',
      recordId: String(existing._id),
      clientId: managedClientConfig.managedClientId,
      clientSecret: rotated && rotated.data ? rotated.data.clientSecret : '',
      environment: environment,
      record: record
    };
  }

  const collision = await findApplicationIdentityCollision(iamService, managedClientConfig);
  if (collision && collision._id) {
    throw new Error(
      'IAM managed client identity already exists without environment clientId ' +
      managedClientConfig.managedClientId +
      '. Set PROJECT_IAM_APPLICATION_ID/PROJECT_IAM_APP_ID per environment or set PROJECT_IAM_MANAGED_CLIENT_RECORD_ID explicitly.'
    );
  }

  const created = await iamService.registerManagedClient(payload);
  const record = created && created.data ? created.data : created;
  const environment = pickManagedEnvironment(record, managedClientConfig.managedClientId);

  return {
    mode: 'created',
    recordId: record && record._id ? String(record._id) : '',
    clientId: managedClientConfig.managedClientId,
    clientSecret: environment && environment.clientSecret ? String(environment.clientSecret) : '',
    environment: environment,
    record: record
  };
}

async function lookupPermissionAccount(iamService, email) {
  const normalizedEmail = firstNonEmpty(email).toLowerCase();
  if (!normalizedEmail) return null;
  const result = await iamService.lookupAccountByEmail(normalizedEmail);
  return result && result.data ? result.data : null;
}

async function main() {
  ensureConfig();

  const envFilePath = resolveEnvFilePath();
  const managedClientConfig = buildManagedClientConfig();
  const iamService = createIamService();
  const bootstrap = await iamService.bootstrap();
  const permissionAccount = await lookupPermissionAccount(iamService, managedClientConfig.ownerEmail);
  const managedClient = await ensureManagedClient(iamService, managedClientConfig);

  const envUpdates = {
    PROJECT_CODE: managedClientConfig.projectCode,
    PROJECT_NAME: managedClientConfig.projectName,
    PROJECT_ENV: managedClientConfig.projectEnvironment,
    PROJECT_BASE_URL: managedClientConfig.projectBaseUrl,
    IAM_SDK_CLIENT_ID: managedClient.clientId,
    IAM_SDK_CLIENT_SECRET: managedClient.clientSecret,
    IAM_SDK_AUDIENCE: managedClientConfig.allowedAudiences,
    IAM_SDK_SCOPE: managedClientConfig.allowedScopes,
    IAM_ADMIN_CLIENT_ID: projectConfig.iamAdmin.clientId,
    IAM_ADMIN_CLIENT_SECRET: projectConfig.iamAdmin.clientSecret,
    IAM_ADMIN_AUDIENCE: projectConfig.iamAdmin.audience,
    IAM_ADMIN_SCOPE: projectConfig.iamAdmin.scope,
    PROJECT_PERMISSION_ACCOUNT_EMAIL: managedClientConfig.ownerEmail,
    PROJECT_IAM_APPLICATION_ID: managedClientConfig.applicationId,
    PROJECT_IAM_APP_ID: managedClientConfig.appId,
    PROJECT_IAM_MANAGED_CLIENT_RECORD_ID: managedClient.recordId,
    PROJECT_IAM_MANAGED_CLIENT_ID: managedClient.clientId,
    PROJECT_IAM_MANAGED_CLIENT_SECRET: managedClient.clientSecret,
    PROJECT_IAM_MANAGED_CLIENT_NAME: managedClientConfig.managedClientName,
    PROJECT_IAM_MANAGED_CLIENT_ENDPOINT: managedClientConfig.projectBaseUrl,
    PROJECT_IAM_MANAGED_CLIENT_OWNER_EMAIL: managedClientConfig.ownerEmail,
    PROJECT_IAM_MANAGED_CLIENT_PARTNER_ID: managedClientConfig.partnerId,
    PROJECT_IAM_MANAGED_CLIENT_TENANT: managedClientConfig.tenant,
    PROJECT_IAM_MANAGED_CLIENT_ALLOWED_SCOPES: managedClientConfig.allowedScopes,
    PROJECT_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES: managedClientConfig.allowedAudiences,
    PROJECT_INIT_ADMIN_EMAILS: mergeEnvList(process.env.PROJECT_INIT_ADMIN_EMAILS, managedClientConfig.ownerEmail),
    PROJECT_INIT_SEED_ADMIN_EMAIL: managedClientConfig.ownerEmail
  };

  if (permissionAccount && permissionAccount._id) {
    envUpdates.PROJECT_PERMISSION_ACCOUNT_ID = String(permissionAccount._id);
    envUpdates.PROJECT_INIT_SEED_ADMIN_ACCOUNT_ID = String(permissionAccount._id);
  }

  updateEnvFile(envFilePath, envUpdates);

  console.log(JSON.stringify({
    ok: true,
    envFile: envFilePath,
    adminClientId: bootstrap && bootstrap.introspection ? bootstrap.introspection.client_id : projectConfig.iamAdmin.clientId,
    permissionAccount: permissionAccount ? {
      accountId: String(permissionAccount._id || ''),
      email: permissionAccount.email || managedClientConfig.ownerEmail
    } : null,
    managedClient: {
      mode: managedClient.mode,
      recordId: managedClient.recordId,
      clientId: managedClient.clientId,
      endpoint: managedClient.environment && managedClient.environment.endpoint ? managedClient.environment.endpoint : managedClientConfig.projectBaseUrl,
      audience: managedClientConfig.allowedAudiences,
      scope: managedClientConfig.allowedScopes
    }
  }, null, 2));
}

main().catch(function (error) {
  console.error(JSON.stringify({
    ok: false,
    message: error.message,
    response: error.response && error.response.data ? error.response.data : null
  }, null, 2));
  process.exit(1);
});
