'use strict';

require('dotenv').config({
  path: process.env.DOTENV_CONFIG_PATH || process.env.dotenv_config_path || undefined
});

const axios = require('axios');
const newSystemConfig = require('../config/config');
const projectConfig = require('../config/project.config');

const securityConfig = projectConfig.security || {};
const project = projectConfig.project || {};
const PROJECT_NAME = project.name || 'NewSystem';
const DEFAULT_TYPE_TITLE = securityConfig.permissionTypeTitle || PROJECT_NAME + ' Administration';
const DEFAULT_GROUP_TITLE = securityConfig.permissionGroupTitle || PROJECT_NAME + ' Admin';
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
  return String(response.data && response.data.access_token || '');
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
    throw wrapped;
  }
}

function toLang(value) {
  return [{ key: 'en', value: String(value || '').trim() }];
}

async function ensureType(token) {
  const list = await adminRequest(token, 'get', '/security/type');
  const rows = Array.isArray(list && list.data) ? list.data : [];
  let item = rows.find(function (row) {
    return Array.isArray(row && row.title) && row.title.some(function (part) {
      return part && part.value === DEFAULT_TYPE_TITLE;
    });
  });
  if (item) return item;

  const created = await adminRequest(token, 'post', '/security/type', {
    title: toLang(DEFAULT_TYPE_TITLE),
    description: toLang(PROJECT_NAME + ' delegated administration type')
  });
  return created.data;
}

async function ensureGroup(token, typeId) {
  const list = await adminRequest(token, 'get', '/security/group');
  const rows = Array.isArray(list && list.data) ? list.data : [];
  let item = rows.find(function (row) {
    return Array.isArray(row && row.title) && row.title.some(function (part) {
      return part && part.value === DEFAULT_GROUP_TITLE;
    });
  });
  if (item) return item;

  const created = await adminRequest(token, 'post', '/security/group', {
    title: toLang(DEFAULT_GROUP_TITLE),
    description: toLang(PROJECT_NAME + ' delegated administration group'),
    visibleType: typeId,
    state: true
  });
  return created.data;
}

async function ensureMenus(token, typeId) {
  const list = await adminRequest(token, 'get', '/security/menu');
  const rows = Array.isArray(list && list.data) ? list.data : [];
  const menus = [];

  for (const path of DEFAULT_MENU_PATHS) {
    let item = rows.find(function (row) {
      return row && row.path === path;
    });
    if (!item) {
      const created = await adminRequest(token, 'post', '/security/menu', {
        title: toLang(path),
        description: toLang(`${PROJECT_NAME} permission for ${path}`),
        path: path,
        type: typeId,
        state: true
      });
      item = created.data;
    }
    menus.push(item);
  }

  return menus;
}

async function ensurePermissions(token, groupId, menus) {
  let list = await adminRequest(token, 'get', '/security/permission');
  let rows = Array.isArray(list && list.data) ? list.data : [];

  for (const menu of menus) {
    let existing = rows.find(function (row) {
      const rowGroupId = row && row.group && row.group._id ? String(row.group._id) : String(row && row.group || '');
      const rowMenuId = row && row.menu && row.menu._id ? String(row.menu._id) : String(row && row.menu || '');
      return rowGroupId === String(groupId) && rowMenuId === String(menu._id);
    });

    const payload = {
      group: groupId,
      menu: menu._id,
      all: true,
      view: true,
      edit: true,
      delete: true,
      action: true,
      logs: true
    };

    if (existing && existing._id) {
      await adminRequest(token, 'put', '/security/permission', Object.assign({ _id: existing._id }, payload));
      continue;
    }

    try {
      await adminRequest(token, 'post', '/security/permission', payload);
    } catch (error) {
      list = await adminRequest(token, 'get', '/security/permission');
      rows = Array.isArray(list && list.data) ? list.data : [];
      existing = rows.find(function (row) {
        const rowGroupId = row && row.group && row.group._id ? String(row.group._id) : String(row && row.group || '');
        const rowMenuId = row && row.menu && row.menu._id ? String(row.menu._id) : String(row && row.menu || '');
        return rowGroupId === String(groupId) && rowMenuId === String(menu._id);
      });
      if (!existing) {
        throw error;
      }
    }
  }
}

async function resolveAccount(token) {
  if (DEFAULT_ADMIN_ACCOUNT_ID) {
    return {
      _id: String(DEFAULT_ADMIN_ACCOUNT_ID),
      email: DEFAULT_ADMIN_EMAIL || null
    };
  }

  const result = await adminRequest(token, 'get', '/accounts/lookup', null, {
    email: String(DEFAULT_ADMIN_EMAIL || '').trim().toLowerCase()
  });
  return result && result.data ? result.data : null;
}

async function ensureAssignment(token, accountId, groupId) {
  let list = await adminRequest(token, 'get', '/security/assignment', null, {
    accountId: String(accountId || ''),
    active: true
  });
  let rows = Array.isArray(list && list.data) ? list.data : [];
  let existing = rows.find(function (row) {
    const rowGroupId = row && row.group && row.group._id ? String(row.group._id) : String(row && row.group || '');
    const rowAccountId = row && row.account && row.account._id ? String(row.account._id) : String(row && row.account || '');
    return rowGroupId === String(groupId) && rowAccountId === String(accountId);
  });

  const payload = {
    account: accountId,
    group: groupId,
    active: true,
    dataScope: 'org',
    scopeUnits: []
  };

  if (existing && existing._id) {
    await adminRequest(token, 'put', '/security/assignment', Object.assign({ _id: existing._id }, payload));
    return existing;
  }

  try {
    const created = await adminRequest(token, 'post', '/security/assignment', payload);
    return created && created.data ? created.data : created;
  } catch (error) {
    list = await adminRequest(token, 'get', '/security/assignment', null, {
      accountId: String(accountId || ''),
      active: true
    });
    rows = Array.isArray(list && list.data) ? list.data : [];
    existing = rows.find(function (row) {
      const rowGroupId = row && row.group && row.group._id ? String(row.group._id) : String(row && row.group || '');
      const rowAccountId = row && row.account && row.account._id ? String(row.account._id) : String(row && row.account || '');
      return rowGroupId === String(groupId) && rowAccountId === String(accountId);
    });
    if (!existing) {
      throw error;
    }
    return existing;
  }
}

async function main() {
  const token = await getAdminToken();
  const type = await ensureType(token);
  const menus = await ensureMenus(token, type._id);
  const group = await ensureGroup(token, type._id);
  await ensurePermissions(token, group._id, menus);
  const account = await resolveAccount(token);
  if (!account || !account._id) {
    throw new Error(`IAM account not found for ${DEFAULT_ADMIN_EMAIL || DEFAULT_ADMIN_ACCOUNT_ID}`);
  }
  const assignment = await ensureAssignment(token, account._id, group._id);

  console.log(JSON.stringify({
    ok: true,
    typeId: type._id,
    groupId: group._id,
    menuCount: menus.length,
    accountId: String(account._id),
    accountEmail: account.email || DEFAULT_ADMIN_EMAIL || null,
    assignmentId: assignment && assignment._id ? String(assignment._id) : null,
    paths: menus.map(function (item) { return item.path; })
  }, null, 2));
}

main().catch(function (error) {
  console.error(JSON.stringify({
    message: error.message,
    response: error.response && error.response.data ? error.response.data : null
  }));
  process.exit(1);
});
