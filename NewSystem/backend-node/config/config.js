/**
 * Created by sherlock on 01/02/2017.
 */

var os = require("os");
require('dotenv').config();

function firstNonEmpty() {
    for (var index = 0; index < arguments.length; index += 1) {
        var value = arguments[index];
        if (value !== undefined && value !== null && String(value).trim() !== '') {
            return value;
        }
    }
    return '';
}

function toNumber(value, fallback) {
    var parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function toBoolean(value, fallback) {
    if (value === undefined || value === null || String(value).trim() === '') {
        return fallback;
    }
    var normalized = String(value).trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
    return fallback;
}

function parseList(value) {
    return String(value || '')
        .split(',')
        .map(function (item) {
            return String(item || '').trim();
        })
        .filter(Boolean);
}

function uniqueList(items) {
    return Array.from(new Set((items || []).filter(Boolean)));
}

function slugify(value) {
    return String(value || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .replace(/-{2,}/g, '-');
}

var projectCode = firstNonEmpty(process.env.PROJECT_CODE, 'newSystem');
var projectName = firstNonEmpty(process.env.PROJECT_NAME, 'NewSystem');
var projectDescription = firstNonEmpty(process.env.PROJECT_DESCRIPTION, projectName + ' IAM-integrated service');
var projectVersion = firstNonEmpty(process.env.PROJECT_VERSION, '1.0.0');
var projectEnvironment = firstNonEmpty(process.env.PROJECT_ENV, process.env.NODE_ENV, 'prod');
var projectBaseUrl = firstNonEmpty(process.env.PROJECT_BASE_URL, process.env.BASE_SERVER_URL, 'https://new-system.mfu.ac.th');
var projectSlug = slugify(projectCode || projectName || 'newSystem') || 'newSystem';
var projectScopePrefix = projectSlug.replace(/-/g, '.');

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

var iamSdkBaseUrl = firstNonEmpty(process.env.IAM_SDK_BASE_URL, process.env.IAM_BASE_URL, 'https://iam.mfu.ac.th');
var iamSdkClientId = firstNonEmpty(process.env.IAM_SDK_CLIENT_ID);
var iamSdkClientSecret = firstNonEmpty(process.env.IAM_SDK_CLIENT_SECRET);
var iamSdkAudience = firstNonEmpty(process.env.IAM_SDK_AUDIENCE, process.env.IAM_B2B_REQUIRED_AUDIENCE, projectSlug + '-api');
var iamSdkAdminClientId = firstNonEmpty(process.env.IAM_ADMIN_CLIENT_ID, process.env.IAM_SDK_ADMIN_CLIENT_ID, iamSdkClientId);
var iamSdkAdminClientSecret = firstNonEmpty(process.env.IAM_ADMIN_CLIENT_SECRET, process.env.IAM_SDK_ADMIN_CLIENT_SECRET, iamSdkClientSecret);
var iamSdkAdminAudience = firstNonEmpty(process.env.IAM_ADMIN_AUDIENCE, process.env.IAM_SDK_ADMIN_AUDIENCE, iamSdkAudience);
var iamSdkScope = firstNonEmpty(
    process.env.IAM_SDK_SCOPE,
    projectScopePrefix + '.read ' + projectScopePrefix + '.write'
);
var iamSdkAdminScope = firstNonEmpty(
    process.env.IAM_ADMIN_SCOPE,
    process.env.IAM_SDK_ADMIN_SCOPE,
    iamSdkScope
);
var iamSdkTimeout = toNumber(firstNonEmpty(process.env.IAM_SDK_TIMEOUT_MS, process.env.IAM_ADMIN_TIMEOUT_MS, process.env.IAM_B2B_TIMEOUT_MS, 5000), 5000);
var iamSdkIntrospectPath = firstNonEmpty(process.env.IAM_SDK_INTROSPECT_PATH, process.env.IAM_B2B_INTROSPECT_PATH, '/api/v1/b2b/introspect');
var iamSdkProfilePath = firstNonEmpty(process.env.IAM_SDK_PROFILE_PATH, process.env.IAM_B2B_PROFILE_PATH, '/api/v1/b2b/clients/me');
var iamSdkTokenPath = firstNonEmpty(process.env.IAM_SDK_TOKEN_PATH, process.env.IAM_ADMIN_TOKEN_PATH, '/api/v1/b2b/token');
var iamSdkAdminBasePath = firstNonEmpty(process.env.IAM_SDK_ADMIN_BASE_PATH, process.env.IAM_ADMIN_BASE_PATH, '/api/v1/b2b/admin');
var newSystemPermissionRootPath = firstNonEmpty(
    process.env.PROJECT_PERMISSION_ROOT_PATH,
    process.env.PERMISSION_ROOT_PATH,
    '/' + projectSlug + '/security/permission'
);
var newSystemPermissionPaths = uniqueList(
    buildDefaultPermissionPaths(newSystemPermissionRootPath).concat(
        parseList(
            firstNonEmpty(
                process.env.PROJECT_PERMISSION_PATHS,
                process.env.PERMISSION_PATHS
            )
        )
    )
);
var newSystemPermissionTypeTitle = firstNonEmpty(
    process.env.PROJECT_PERMISSION_TYPE_TITLE,
    process.env.PERMISSION_TYPE_TITLE,
    projectName + ' Administration'
);
var newSystemPermissionGroupTitle = firstNonEmpty(
    process.env.PROJECT_PERMISSION_GROUP_TITLE,
    process.env.PERMISSION_GROUP_TITLE,
    projectName + ' Admin'
);
var newSystemPermissionSource = firstNonEmpty(
    process.env.PROJECT_PERMISSION_SOURCE,
    process.env.PERMISSION_SOURCE,
    'iam'
).toLowerCase();
var newSystemPermissionBootstrapMode = firstNonEmpty(
    process.env.PROJECT_PERMISSION_BOOTSTRAP_MODE,
    process.env.PERMISSION_BOOTSTRAP_MODE,
    'iam'
).toLowerCase();
var newSystemAuthRequire2FA = toBoolean(
    firstNonEmpty(
        process.env.PROJECT_AUTH_REQUIRE_2FA,
        process.env.AUTH_REQUIRE_2FA,
        'true'
    ),
    true
);
var newSystemAuditRetentionDays = toNumber(
    firstNonEmpty(
        process.env.PROJECT_AUDIT_RETENTION_DAYS,
        process.env.AUDIT_RETENTION_DAYS,
        90
    ),
    90
);

module.exports = {
    debug: true,
    project: {
        code: projectCode,
        name: projectName,
        description: projectDescription,
        version: projectVersion,
        environment: projectEnvironment,
        baseUrl: projectBaseUrl
    },
    key:process.env.KEY,
    mongoURI: process.env.MONGODB,
    // mongoURI: 'mongodb+srv://'+process.env.MONGO_USER+':'+process.env.MONGO_PASS+'@'+process.env.MONGO_HOST+'/'+process.env.MONGO_NAME+'?authSource=admin',
    timeout: process.env.TIMEOUT,
    tokenLength: process.env.TOKENLANGTH,
    tokenExpired: (86400000 * process.env.TOKENEXPIRED),
    transactionExpired: (60000 *process.env.TRANSACTIONEXPIRED),
    host: {
        name: os.hostname(),
        url:process.env.BASE_SERVER_URL,
        port: process.env.PORT
    },

    images_part : {
        profile : "profile/",
        ranks : "ranks/"
    },
    iam: {
        baseUrl: iamSdkBaseUrl,
        clientId: iamSdkClientId,
        clientSecret: iamSdkClientSecret,
        introspectPath: iamSdkIntrospectPath,
        profilePath: iamSdkProfilePath,
        requiredAudience: iamSdkAudience,
        scope: iamSdkScope,
        timeout: iamSdkTimeout
    },
    iamAdmin: {
        baseUrl: iamSdkBaseUrl,
        tokenPath: iamSdkTokenPath,
        basePath: iamSdkAdminBasePath,
        audience: iamSdkAdminAudience,
        scope: iamSdkAdminScope,
        clientId: iamSdkAdminClientId,
        clientSecret: iamSdkAdminClientSecret,
        timeout: iamSdkTimeout
    },
    security: {
        auditRetentionDays: newSystemAuditRetentionDays,
        authRequire2FA: newSystemAuthRequire2FA,
        permissionGroupTitle: newSystemPermissionGroupTitle,
        permissionRootPath: newSystemPermissionRootPath,
        permissionPaths: newSystemPermissionPaths,
        permissionSource: newSystemPermissionSource,
        permissionBootstrapMode: newSystemPermissionBootstrapMode,
        permissionTypeTitle: newSystemPermissionTypeTitle
    }



};
