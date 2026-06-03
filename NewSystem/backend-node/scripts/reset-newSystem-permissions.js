'use strict';

require('dotenv').config({
  path: process.env.DOTENV_CONFIG_PATH || process.env.dotenv_config_path || undefined
});

const axios = require('axios');
const newSystemConfig = require('../config/config');
const projectConfig = require('../config/project.config');

const securityConfig = projectConfig.security || {};
const DEFAULT_TYPE_TITLE = securityConfig.permissionTypeTitle || 'New System Administration';
const DEFAULT_GROUP_TITLE = securityConfig.permissionGroupTitle || 'New System Admin';
const DEFAULT_ADMIN_EMAIL = securityConfig.permissionAccountEmail || '';
const DEFAULT_ADMIN_ACCOUNT_ID = securityConfig.permissionAccountId || '';
const DEFAULT_MENU_PATHS = (
  Array.isArray(securityConfig.permissionPaths) && securityConfig.permissionPaths.length > 1
    ? securityConfig.permissionPaths
    : [
  securityConfig.permissionRootPath || '/new-system/security/permission',
  '/dashboard',
  '/newsystem/registry',
  '/newsystem/review',
  '/newsystem/reports',
  '/operations/business',
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
]).slice();

function ensureConfig() {
  if (!newSystemConfig.iamAdmin.baseUrl || !newSystemConfig.iamAdmin.clientId || !newSystemConfig.iamAdmin.clientSecret) {
    throw new Error('IAM admin client is not configured');
  }
  if (!DEFAULT_ADMIN_EMAIL && !DEFAULT_ADMIN_ACCOUNT_ID) {
    throw new Error('PROJECT_PERMISSION_ACCOUNT_EMAIL or PROJECT_PERMISSION_ACCOUNT_ID is required');
  }
}

async function getAdminToken() {
  ensureConfig();
  const response = await axios.post(
    `${newSystemConfig.iamAdmin.baseUrl}${newSystemConfig.iamAdmin.tokenPath}`,
    {
      grant_type: 'client_credentials',
      client_id: newSystemConfig.iamAdmin.clientId,
      client_secret: newSystemConfig.iamAdmin.clientSecret,
      scope: newSystemConfig.iamAdmin.scope,
      audience: newSystemConfig.iamAdmin.audience
    },
    {
      timeout: newSystemConfig.iamAdmin.timeout
    }
  );

  return String((response.data && response.data.access_token) || '');
}

async function adminRequest(token, method, path, payload, params) {
  try {
    const normalizedMethod = String(method || 'get').trim().toLowerCase();
    const requestConfig = {
      method: method,
      url: `${newSystemConfig.iamAdmin.baseUrl}${newSystemConfig.iamAdmin.basePath}${path}`,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      params: params || {},
      timeout: newSystemConfig.iamAdmin.timeout
    };

    if (normalizedMethod !== 'get' && normalizedMethod !== 'head' && payload !== undefined) {
      requestConfig.data = payload;
    }

    const response = await axios({
      method: requestConfig.method,
      url: requestConfig.url,
      headers: requestConfig.headers,
      data: requestConfig.data,
      params: requestConfig.params,
      timeout: requestConfig.timeout
    });

    return response.data || {};
  } catch (error) {
    const wrapped = new Error(`${String(method || 'get').toUpperCase()} ${path} failed`);
    wrapped.response = error.response;
    wrapped.requestPayload = payload || null;
    wrapped.requestParams = params || null;
    throw wrapped;
  }
}

function toLang(value) {
  return [{ key: 'en', value: String(value || '').trim() }];
}

async function removeAll(token, path) {
  const list = await adminRequest(token, 'get', path);
  const rows = Array.isArray(list && list.data) ? list.data : [];

  for (const row of rows) {
    if (!row || !row._id) continue;
    await adminRequest(token, 'delete', path, { id: row._id });
  }

  return rows.length;
}

async function ensureType(token) {
  const created = await adminRequest(token, 'post', '/security/type', {
    title: toLang(DEFAULT_TYPE_TITLE),
    description: toLang('NewSystem delegated administration type')
  });
  return created.data;
}

async function ensureGroup(token, typeId) {
  const created = await adminRequest(token, 'post', '/security/group', {
    title: toLang(DEFAULT_GROUP_TITLE),
    description: toLang('NewSystem delegated administration group'),
    visibleType: typeId,
    state: true
  });
  return created.data;
}

async function ensureMenus(token, typeId) {
  const menus = [];

  for (const path of DEFAULT_MENU_PATHS) {
    const created = await adminRequest(token, 'post', '/security/menu', {
      title: toLang(path),
      description: toLang(`NewSystem permission for ${path}`),
      path: path,
      type: typeId,
      state: true
    });
    menus.push(created.data);
  }

  return menus;
}

async function ensurePermissions(token, groupId, menus) {
  for (const menu of menus) {
    await adminRequest(token, 'post', '/security/permission', {
      group: groupId,
      menu: menu._id,
      all: true,
      view: true,
      edit: true,
      delete: true,
      action: true,
      logs: true
    });
  }
}

async function resolveAccount(token, email) {
  const result = await adminRequest(token, 'get', '/accounts/lookup', null, {
    email: String(email || '').trim().toLowerCase()
  });
  return result && result.data ? result.data : null;
}

async function createAssignment(token, accountId, groupId) {
  const result = await adminRequest(token, 'post', '/security/assignment', {
    account: accountId,
    group: groupId,
    active: true,
    dataScope: 'org',
    scopeUnits: []
  });
  return result.data;
}

async function main() {
  const token = await getAdminToken();
  const account = DEFAULT_ADMIN_ACCOUNT_ID
    ? { _id: String(DEFAULT_ADMIN_ACCOUNT_ID), email: DEFAULT_ADMIN_EMAIL || null }
    : await resolveAccount(token, DEFAULT_ADMIN_EMAIL);
  if (!account || !account._id) {
    throw new Error(`IAM account not found for ${DEFAULT_ADMIN_EMAIL || DEFAULT_ADMIN_ACCOUNT_ID}`);
  }

  const deletedAssignments = await removeAll(token, '/security/assignment');
  const deletedPermissions = await removeAll(token, '/security/permission');
  const deletedGroups = await removeAll(token, '/security/group');
  const deletedMenus = await removeAll(token, '/security/menu');
  const deletedTypes = await removeAll(token, '/security/type');

  const type = await ensureType(token);
  const menus = await ensureMenus(token, type._id);
  const group = await ensureGroup(token, type._id);
  await ensurePermissions(token, group._id, menus);
  await createAssignment(token, account._id, group._id);

  console.log(JSON.stringify({
    ok: true,
    deleted: {
      assignments: deletedAssignments,
      permissions: deletedPermissions,
      groups: deletedGroups,
      menus: deletedMenus,
      types: deletedTypes
    },
    rebuilt: {
      typeId: type._id,
      groupId: group._id,
      menuCount: menus.length,
      accountId: account._id,
      accountEmail: account.email || DEFAULT_ADMIN_EMAIL
    }
  }, null, 2));
}

main().catch(function (error) {
  console.error(JSON.stringify({
    ok: false,
    message: error.message,
    response: error.response && error.response.data ? error.response.data : null,
    requestPayload: error.requestPayload || null,
    requestParams: error.requestParams || null
  }, null, 2));
  process.exit(1);
});
