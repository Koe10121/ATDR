'use strict';

function firstNonEmpty() {
  for (let index = 0; index < arguments.length; index += 1) {
    const value = arguments[index];
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return String(value).trim();
    }
  }
  return '';
}

function toNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toBoolean(value, fallback) {
  if (value === undefined || value === null || String(value).trim() === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return fallback;
}

function parseList(value) {
  return String(value || '')
    .split(',')
    .map(function (item) { return String(item || '').trim(); })
    .filter(Boolean);
}

function uniqueList(items) {
  return Array.from(new Set((items || []).filter(Boolean)));
}

function buildDefaultPermissionPaths(rootPath) {
  return uniqueList([
    rootPath,
    '/dashboard',
    '/newsystem/registry',
    '/newsystem/review',
    '/newsystem/reports',
    '/operations/business',
    '/management/category',
    '/config/message-authen',
    '/config/email-notifications',
    '/config/workflow-actions',
    '/config/runtime-access',
    '/config/database-backup',
    '/config/setting-message',
    '/config/verification',
    '/setting/group',
    '/setting/message-status',
    '/security/permissions/menu',
    '/security/permissions/group',
    '/security/permissions/matrix',
    '/security/audit',
    '/accounts/directory',
    '/accounts/lifecycle'
  ]);
}

const projectCode = firstNonEmpty(process.env.PROJECT_CODE, 'newSystem');
const projectName = firstNonEmpty(process.env.PROJECT_NAME, 'NewSystem');
const projectDescription = firstNonEmpty(process.env.PROJECT_DESCRIPTION, 'New System IAM-integrated service');
const projectVersion = firstNonEmpty(process.env.PROJECT_VERSION, '1.0.0');
const projectEnvironment = firstNonEmpty(process.env.PROJECT_ENV, 'prod');
const projectBaseUrl = firstNonEmpty(process.env.PROJECT_BASE_URL, 'https://new-system.mfu.ac.th');

const iamBaseUrl = firstNonEmpty(process.env.IAM_SDK_BASE_URL, 'https://iam.mfu.ac.th');
const iamClientId = firstNonEmpty(process.env.IAM_SDK_CLIENT_ID);
const iamClientSecret = firstNonEmpty(process.env.IAM_SDK_CLIENT_SECRET);
const iamAudience = firstNonEmpty(process.env.IAM_SDK_AUDIENCE, projectCode + '-api');
const iamAdminClientId = firstNonEmpty(
  process.env.IAM_ADMIN_CLIENT_ID,
  process.env.IAM_SDK_ADMIN_CLIENT_ID,
  iamClientId
);
const iamAdminClientSecret = firstNonEmpty(
  process.env.IAM_ADMIN_CLIENT_SECRET,
  process.env.IAM_SDK_ADMIN_CLIENT_SECRET,
  iamClientSecret
);
const iamAdminAudience = firstNonEmpty(
  process.env.IAM_ADMIN_AUDIENCE,
  process.env.IAM_SDK_ADMIN_AUDIENCE,
  iamAudience
);
const iamScope = firstNonEmpty(
  process.env.IAM_SDK_SCOPE,
  projectCode.replace(/-/g, '.') + '.read ' + projectCode.replace(/-/g, '.') + '.write'
);
const iamAdminScope = firstNonEmpty(
  process.env.IAM_ADMIN_SCOPE,
  process.env.IAM_SDK_ADMIN_SCOPE,
  iamScope
);
const iamTimeoutMs = toNumber(firstNonEmpty(process.env.IAM_SDK_TIMEOUT_MS, 5000), 5000);
const iamTokenPath = firstNonEmpty(process.env.IAM_SDK_TOKEN_PATH, '/api/v1/b2b/token');
const iamIntrospectPath = firstNonEmpty(process.env.IAM_SDK_INTROSPECT_PATH, '/api/v1/b2b/introspect');
const iamProfilePath = firstNonEmpty(process.env.IAM_SDK_PROFILE_PATH, '/api/v1/b2b/clients/me');
const iamAdminBasePath = firstNonEmpty(process.env.IAM_SDK_ADMIN_BASE_PATH, '/api/v1/b2b/admin');
const iamCompatProfile = firstNonEmpty(process.env.IAM_COMPAT_PROFILE, 'b2b-admin-v1');

const permissionRootPath = firstNonEmpty(
  process.env.PROJECT_PERMISSION_ROOT_PATH,
  process.env.PERMISSION_ROOT_PATH,
  '/' + projectCode.replace(/[^a-z0-9-]+/gi, '-').toLowerCase() + '/security/permission'
);
const permissionPaths = uniqueList(buildDefaultPermissionPaths(permissionRootPath).concat(parseList(firstNonEmpty(
  process.env.PROJECT_PERMISSION_PATHS,
  process.env.PERMISSION_PATHS
))));
const permissionTypeTitle = firstNonEmpty(
  process.env.PROJECT_PERMISSION_TYPE_TITLE,
  process.env.PERMISSION_TYPE_TITLE,
  projectName + ' Administration'
);
const permissionGroupTitle = firstNonEmpty(
  process.env.PROJECT_PERMISSION_GROUP_TITLE,
  process.env.PERMISSION_GROUP_TITLE,
  projectName + ' Admin'
);
const permissionSource = firstNonEmpty(
  process.env.PROJECT_PERMISSION_SOURCE,
  process.env.PERMISSION_SOURCE,
  'iam'
).toLowerCase();
const permissionBootstrapMode = firstNonEmpty(
  process.env.PROJECT_PERMISSION_BOOTSTRAP_MODE,
  process.env.PERMISSION_BOOTSTRAP_MODE,
  'iam'
).toLowerCase();
const permissionAccountEmail = firstNonEmpty(
  process.env.PROJECT_PERMISSION_ACCOUNT_EMAIL,
  process.env.PERMISSION_ACCOUNT_EMAIL
).toLowerCase();
const permissionAccountId = firstNonEmpty(
  process.env.PROJECT_PERMISSION_ACCOUNT_ID,
  process.env.PERMISSION_ACCOUNT_ID
);
const authRequire2FA = toBoolean(firstNonEmpty(
  process.env.PROJECT_AUTH_REQUIRE_2FA,
  process.env.AUTH_REQUIRE_2FA,
  'true'
), true);
const auditRetentionDays = toNumber(firstNonEmpty(
  process.env.PROJECT_AUDIT_RETENTION_DAYS,
  process.env.AUDIT_RETENTION_DAYS,
  90
), 90);

module.exports = {
  project: {
    code: projectCode,
    name: projectName,
    description: projectDescription,
    version: projectVersion,
    environment: projectEnvironment,
    baseUrl: projectBaseUrl
  },
  iam: {
    baseUrl: iamBaseUrl,
    clientId: iamClientId,
    clientSecret: iamClientSecret,
    scope: iamScope,
    requiredAudience: iamAudience,
    timeoutMs: iamTimeoutMs,
    compatProfile: iamCompatProfile,
    introspectPath: iamIntrospectPath,
    profilePath: iamProfilePath
  },
  iamAdmin: {
    baseUrl: iamBaseUrl,
    clientId: iamAdminClientId,
    clientSecret: iamAdminClientSecret,
    audience: iamAdminAudience,
    scope: iamAdminScope,
    timeoutMs: iamTimeoutMs,
    tokenPath: iamTokenPath,
    basePath: iamAdminBasePath
  },
  security: {
    auditRetentionDays: auditRetentionDays,
    authRequire2FA: authRequire2FA,
    permissionAccountEmail: permissionAccountEmail,
    permissionAccountId: permissionAccountId,
    permissionBootstrapMode: permissionBootstrapMode,
    permissionSource: permissionSource,
    permissionTypeTitle: permissionTypeTitle,
    permissionGroupTitle: permissionGroupTitle,
    permissionRootPath: permissionRootPath,
    permissionPaths: permissionPaths
  }
};
