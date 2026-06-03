'use strict';

const axios = require('axios');
const config = require('../../../../config/config');
const AccountModel = require('../../accounts/controller/account');
const { createNewSystemSdk } = require('../../../integrations/iam/sdk');
const USER_API_BASE_PATH = '/api/v1';

function getAdminConfig() {
  return config.iamAdmin || {};
}

function ensureAdminConfig() {
  const adminConfig = getAdminConfig();
  if (!adminConfig.baseUrl || !adminConfig.tokenPath || !adminConfig.clientId || !adminConfig.clientSecret) {
    const error = new Error('iam_admin_not_configured');
    error.statusCode = 503;
    error.payload = {
      status: false,
      error: 'iam_admin_not_configured',
      details: {
        baseUrl: Boolean(adminConfig.baseUrl),
        tokenPath: Boolean(adminConfig.tokenPath),
        clientId: Boolean(adminConfig.clientId),
        clientSecret: Boolean(adminConfig.clientSecret)
      }
    };
    throw error;
  }
  return adminConfig;
}

function normalizeError(err, fallbackError) {
  const statusCode = err.statusCode || (err.response && err.response.status) || 502;
  const payload = err.payload
    ? err.payload
    : err.response && err.response.data
      ? err.response.data
      : { status: false, error: err.message || fallbackError };
  return { statusCode, payload };
}

function relaySetCookie(response, result) {
  const headers = result && result.headers ? result.headers : {};
  const cookies = headers['set-cookie'] || headers['Set-Cookie'];
  if (cookies && response && typeof response.setHeader === 'function') {
    response.setHeader('Set-Cookie', cookies);
  }
}

function pickLangValue(items) {
  if (!Array.isArray(items)) return '';
  const found = items.find(function (item) {
    return item && item.key === 'en' && item.value;
  }) || items.find(function (item) {
    return item && item.value;
  });
  return found ? String(found.value) : '';
}

function getVisibleTypeTitle(rawGroup) {
  if (!rawGroup || typeof rawGroup !== 'object') return '';
  const visibleType = rawGroup.visibleType;
  if (visibleType && typeof visibleType === 'object') {
    return pickLangValue(visibleType.title) || String(visibleType.name || visibleType.key || '');
  }
  return '';
}

function getGroupTitle(rawGroup) {
  if (!rawGroup || typeof rawGroup !== 'object') return '';
  return pickLangValue(rawGroup.title) || String(rawGroup.name || rawGroup.label || rawGroup.key || '');
}

function normalizeLooseKey(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '');
}

function normalizePermissionPath(value) {
  if (!value) return '';
  let normalized = String(value).trim();
  const queryIndex = normalized.indexOf('?');
  if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex);
  const hashIndex = normalized.indexOf('#');
  if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex);
  normalized = normalized.replace(/\/{2,}/g, '/');
  if (!normalized.startsWith('/')) normalized = `/${normalized}`;
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

function getConfiguredPermissionPaths() {
  const permissionPaths = config.security && Array.isArray(config.security.permissionPaths)
    ? config.security.permissionPaths
    : [];
  return new Set(
    permissionPaths
      .map(normalizePermissionPath)
      .filter(Boolean)
  );
}

function getPermissionMenuPath(item) {
  if (!item || typeof item !== 'object') return '';
  if (item.menu && typeof item.menu === 'object' && item.menu.path) {
    return normalizePermissionPath(item.menu.path);
  }
  if (item.path) {
    return normalizePermissionPath(item.path);
  }
  return '';
}

function shouldPreferGroupVariant(nextGroup, currentGroup) {
  const preferredGroupTitle = config.security && config.security.permissionGroupTitle
    ? String(config.security.permissionGroupTitle).trim()
    : '';
  if (!preferredGroupTitle) return false;

  const nextMatches = normalizeLooseKey(getGroupTitle(nextGroup)) === normalizeLooseKey(preferredGroupTitle);
  const currentMatches = normalizeLooseKey(getGroupTitle(currentGroup)) === normalizeLooseKey(preferredGroupTitle);
  return nextMatches && !currentMatches;
}

function dedupeByGroupTitle(items, resolveGroup) {
  const list = Array.isArray(items) ? items : [];
  const pickGroup = typeof resolveGroup === 'function'
    ? resolveGroup
    : function (item) { return item; };
  const uniqueItems = new Map();

  list.forEach(function (item, index) {
    const group = pickGroup(item) || {};
    const groupTitle = getGroupTitle(group);
    const groupId = group && group._id ? String(group._id) : '';
    const key = normalizeLooseKey(groupTitle) || (groupId ? `id:${groupId}` : `index:${index}`);
    const currentItem = uniqueItems.get(key);
    const currentGroup = currentItem ? pickGroup(currentItem) : null;

    if (!currentItem || shouldPreferGroupVariant(group, currentGroup)) {
      uniqueItems.set(key, item);
    }
  });

  return Array.from(uniqueItems.values());
}

function filterPermissionRows(rows, allowedGroupIds, allowedMenuPaths) {
  return (Array.isArray(rows) ? rows : []).filter(function (item) {
    const groupId = getRefId(item && item.group ? item.group : null);
    const menuPath = getPermissionMenuPath(item);
    return groupId && allowedGroupIds.has(groupId) && menuPath && allowedMenuPaths.has(menuPath);
  });
}

function filterPermissionMatrix(matrix, allowedMenuPaths) {
  if (!matrix || typeof matrix !== 'object') return {};
  return Object.keys(matrix).reduce(function (acc, key) {
    const normalizedKey = normalizePermissionPath(key);
    if (normalizedKey && allowedMenuPaths.has(normalizedKey)) {
      acc[normalizedKey] = matrix[key];
    }
    return acc;
  }, {});
}

function buildPermissionMatrixFromRows(rows) {
  return (Array.isArray(rows) ? rows : []).reduce(function (acc, row) {
    const path = getPermissionMenuPath(row);
    if (!path) return acc;
    if (!acc[path]) {
      acc[path] = { all: false, view: false, edit: false, delete: false, action: false, logs: false };
    }
    acc[path].all = acc[path].all || !!row.all;
    acc[path].view = acc[path].view || !!row.view;
    acc[path].edit = acc[path].edit || !!row.edit;
    acc[path].delete = acc[path].delete || !!row.delete;
    acc[path].action = acc[path].action || !!row.action;
    acc[path].logs = acc[path].logs || !!row.logs;
    return acc;
  }, {});
}

function buildEffectivePermissionsFromMatrix(matrix) {
  const source = matrix && typeof matrix === 'object' ? matrix : {};
  return Object.keys(source)
    .sort()
    .map(function (path) {
      return Object.assign({ path: path }, source[path] || {});
    });
}

function getRefId(ref) {
  if (ref && typeof ref === 'object') {
    return ref._id ? String(ref._id) : '';
  }
  return ref ? String(ref) : '';
}

function getRefTitle(ref) {
  if (!ref || typeof ref !== 'object') return '';
  return pickLangValue(ref.title) || String(ref.name || ref.key || '');
}

function getItemTitle(item) {
  return item && typeof item === 'object'
    ? pickLangValue(item.title) || String(item.name || item.key || '')
    : '';
}

function getProjectAppId() {
  const projectConfig = config.project || {};
  return String(
    projectConfig.code ||
    process.env.PROJECT_CODE ||
    process.env.VUE_APP_PROJECT_APP_ID ||
    'project'
  ).trim();
}

function isExpectedTypeRef(ref, expectedTypeTitle) {
  return !!(expectedTypeTitle && getRefTitle(ref) === expectedTypeTitle);
}

function withScopedMenuType(menu, scopedType, expectedTypeTitle, allowedMenuPaths) {
  const cloned = Object.assign({}, menu || {});
  const menuPath = normalizePermissionPath(cloned.path || '');
  const alreadyScoped = isExpectedTypeRef(cloned.type, expectedTypeTitle);
  if (!alreadyScoped && scopedType && menuPath && allowedMenuPaths.has(menuPath)) {
    cloned.type = scopedType;
    cloned.source = cloned.source || getProjectAppId();
    cloned.appId = cloned.appId || getProjectAppId();
  }
  return cloned;
}

function getAssignmentGroupId(assignment) {
  const group = assignment && assignment.group ? assignment.group : null;
  if (group && typeof group === 'object') {
    return group._id ? String(group._id) : '';
  }
  return group ? String(group) : '';
}

function getAssignmentAccountId(assignment) {
  const account = assignment && assignment.account ? assignment.account : null;
  if (account && typeof account === 'object') {
    return account._id ? String(account._id) : '';
  }
  return account ? String(account) : '';
}

function buildAccountListPagination(items, query) {
  const list = Array.isArray(items) ? items : [];
  const total = list.length;

  return {
    data: list,
    pagination: {
      page: 1,
      limit: total,
      total: total,
      totalPages: 1,
      hasMore: false,
      search: String(query && (query.search || query.q) || '').trim(),
      includeShell: ['1', 'true', 'yes', 'on'].includes(String(query && query.includeShell || '').trim().toLowerCase())
    }
  };
}

async function fetchAccountsList(headers, query) {
  const params = Object.assign({}, query || {});
  delete params.page;
  delete params.limit;

  return requestAdmin({
    method: 'get',
    path: '/accounts',
    params: params,
    headers: headers
  });
}

async function resolveScopedSecurityMetadata(headers) {
  const expectedTypeTitle = config.security && config.security.permissionTypeTitle
    ? String(config.security.permissionTypeTitle).trim()
    : '';
  const configuredPermissionPaths = getConfiguredPermissionPaths();
  if (!expectedTypeTitle) {
    return {
      expectedTypeTitle: '',
      allowedGroupIds: new Set(),
      allowedMenuPaths: new Set()
    };
  }

  const [groupsResult, menusResult] = await Promise.all([
    requestAdmin({
      method: 'get',
      path: '/security/group',
      params: {},
      headers: headers
    }),
    requestAdmin({
      method: 'get',
      path: '/security/menu',
      params: {},
      headers: headers
    })
  ]);

  const allowedGroups = ((groupsResult && groupsResult.data) || [])
    .filter(function (item) {
      const visibleType = item && item.visibleType ? item.visibleType : null;
      const visibleTitle = visibleType && typeof visibleType === 'object'
        ? (pickLangValue(visibleType.title) || String(visibleType.name || visibleType.key || ''))
        : '';
      return visibleTitle === expectedTypeTitle;
    });

  const allowedGroupIds = new Set(
    allowedGroups
      .map(function (item) { return item && item._id ? String(item._id) : ''; })
      .filter(Boolean)
  );

  const allowedGroupsById = allowedGroups.reduce(function (acc, item) {
    if (item && item._id) acc.set(String(item._id), item);
    return acc;
  }, new Map());

  const scopedMenuPaths = new Set(
    ((menusResult && menusResult.data) || [])
      .filter(function (item) {
        const type = item && item.type ? item.type : null;
        const typeTitle = type && typeof type === 'object'
          ? (pickLangValue(type.title) || String(type.name || type.key || ''))
          : '';
        const menuPath = normalizePermissionPath(item && item.path ? item.path : '');
        const withinConfiguredScope = !configuredPermissionPaths.size || configuredPermissionPaths.has(menuPath);
        return typeTitle === expectedTypeTitle && menuPath && withinConfiguredScope;
      })
      .map(function (item) { return normalizePermissionPath(item && item.path ? item.path : ''); })
      .filter(Boolean)
  );

  const allowedMenuPaths = configuredPermissionPaths.size
    ? new Set(Array.from(configuredPermissionPaths))
    : scopedMenuPaths;

  return {
    expectedTypeTitle: expectedTypeTitle,
    allowedGroupIds: allowedGroupIds,
    allowedGroupsById: allowedGroupsById,
    allowedMenuPaths: allowedMenuPaths
  };
}

function createAdminRequestOptions(request, options) {
  return {
    method: options.method,
    path: options.path,
    params: options.params || request.query || {},
    data: options.data || request.body || {},
    headers: {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    }
  };
}

function createUserRequestOptions(request, options) {
  const requestHeaders = request && request.headers ? request.headers : {};
  return {
    method: options.method,
    path: options.path,
    params: options.params || request.query || {},
    data: options.data || request.body || {},
    headers: {
      lang: requestHeaders.lang || 'th',
      'x-access-token': requestHeaders['x-access-token'] || '',
      'user-agent': requestHeaders['user-agent'] || '',
      'x-forwarded-for': requestHeaders['x-forwarded-for'] || request.ip || '',
      cookie: requestHeaders.cookie || '',
      'x-client-id': config.iam && config.iam.clientId
        ? config.iam.clientId
        : (config.iamAdmin && config.iamAdmin.clientId ? config.iamAdmin.clientId : ''),
      'x-audience': config.iam && config.iam.requiredAudience ? config.iam.requiredAudience : '',
      'x-system': config.project && config.project.code ? String(config.project.code) : 'newSystem'
    }
  };
}

function createUserRequestOptionsWithToken(request, options, accessToken) {
  const userOptions = createUserRequestOptions(request, options);
  userOptions.headers['x-access-token'] = accessToken ? String(accessToken) : '';
  return userOptions;
}

async function loadCurrentNewSystemAccount(request) {
  if (request && request.authAccount) {
    return request.authAccount;
  }
  const accountId = request && request.body && request.body.accounts ? String(request.body.accounts) : '';
  if (!accountId) return null;
  return AccountModel.onQuery({ _id: accountId });
}

async function loadNewSystemAccountById(accountId) {
  if (!accountId) return null;
  try {
    return await AccountModel.onQuery({ _id: accountId });
  } catch (error) {
    return null;
  }
}

async function resolveIamAccountIdByEmail(email) {
  if (!email) return '';
  ensureAdminConfig();
  const iamSdk = createNewSystemSdk();
  const result = await iamSdk.admin.lookupAccountByEmail(String(email).trim().toLowerCase());
  const data = result && result.data ? result.data : null;
  return data && data._id ? String(data._id) : '';
}

async function resolveIamAccountIdByNewSystemAccountId(accountId) {
  const newSystemAccount = await loadNewSystemAccountById(accountId);
  if (!newSystemAccount) return String(accountId || '');
  const email = newSystemAccount && newSystemAccount.email ? newSystemAccount.email : '';
  return resolveIamAccountIdByEmail(email);
}

async function requestAdmin(options) {
  ensureAdminConfig();
  const iamSdk = createNewSystemSdk();
  return iamSdk.admin.request(options || {});
}

async function requestUser(options) {
  ensureAdminConfig();
  const response = await axios.request({
    baseURL: config.iam && config.iam.baseUrl,
    url: `${USER_API_BASE_PATH}${options.path}`,
    method: options.method,
    headers: Object.assign({}, options.headers || {}),
    params: options.params || undefined,
    data: options.data || undefined,
    timeout: config.iam && config.iam.timeout ? config.iam.timeout : 5000
  });
  return {
    statusCode: response.status,
    payload: response.data || {},
    headers: response.headers || {}
  };
}

async function forwardAdminRequest(request, response, options) {
  try {
    const result = await requestAdmin(createAdminRequestOptions(request, options));
    return response.status(options.successStatus || 200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_admin_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function loadScopedSecurityCatalog(headers) {
  const expectedTypeTitle = config.security && config.security.permissionTypeTitle
    ? String(config.security.permissionTypeTitle).trim()
    : '';
  const allowedMenuPaths = getConfiguredPermissionPaths();
  const [typesResult, groupsResult, menusResult] = await Promise.all([
    requestAdmin({ method: 'get', path: '/security/type', headers: headers || {} }),
    requestAdmin({ method: 'get', path: '/security/group', headers: headers || {} }),
    requestAdmin({ method: 'get', path: '/security/menu', headers: headers || {} })
  ]);

  const scopedTypes = (Array.isArray(typesResult && typesResult.data) ? typesResult.data : [])
    .filter(function (item) {
      return !expectedTypeTitle || getItemTitle(item) === expectedTypeTitle;
    });
  const scopedType = scopedTypes[0] || null;
  const scopedTypeIds = new Set(scopedTypes.map(function (item) { return getRefId(item); }).filter(Boolean));

  const scopedGroups = (Array.isArray(groupsResult && groupsResult.data) ? groupsResult.data : [])
    .filter(function (item) {
      return !expectedTypeTitle || isExpectedTypeRef(item && item.visibleType, expectedTypeTitle);
    });
  const scopedGroupIds = new Set(scopedGroups.map(function (item) { return getRefId(item); }).filter(Boolean));

  const scopedMenus = (Array.isArray(menusResult && menusResult.data) ? menusResult.data : [])
    .filter(function (item) {
      const menuPath = normalizePermissionPath(item && item.path ? item.path : '');
      return (
        (menuPath && allowedMenuPaths.has(menuPath)) ||
        scopedTypeIds.has(getRefId(item && item.type)) ||
        isExpectedTypeRef(item && item.type, expectedTypeTitle)
      );
    })
    .map(function (item) {
      return withScopedMenuType(item, scopedType, expectedTypeTitle, allowedMenuPaths);
    });
  const scopedMenuIds = new Set(scopedMenus.map(function (item) { return getRefId(item); }).filter(Boolean));

  return {
    typesResult: typesResult,
    groupsResult: groupsResult,
    menusResult: menusResult,
    scopedTypes: scopedTypes,
    scopedType: scopedType,
    scopedGroups: scopedGroups,
    scopedGroupIds: scopedGroupIds,
    scopedMenus: scopedMenus,
    scopedMenuIds: scopedMenuIds,
    allowedMenuPaths: allowedMenuPaths
  };
}

async function forwardScopedSecurityTypes(request, response) {
  try {
    const catalog = await loadScopedSecurityCatalog({
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    });
    return response.status(200).json(Object.assign({}, catalog.typesResult, {
      data: catalog.scopedTypes
    }));
  } catch (err) {
    const normalized = normalizeError(err, 'iam_security_type_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardScopedSecurityMenus(request, response) {
  try {
    const catalog = await loadScopedSecurityCatalog({
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    });
    return response.status(200).json(Object.assign({}, catalog.menusResult, {
      data: catalog.scopedMenus
    }));
  } catch (err) {
    const normalized = normalizeError(err, 'iam_security_menu_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardScopedSecurityGroups(request, response) {
  try {
    const catalog = await loadScopedSecurityCatalog({
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    });
    return response.status(200).json(Object.assign({}, catalog.groupsResult, {
      data: catalog.scopedGroups
    }));
  } catch (err) {
    const normalized = normalizeError(err, 'iam_security_group_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardScopedSecurityPermissions(request, response) {
  try {
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const [catalog, permissionsResult] = await Promise.all([
      loadScopedSecurityCatalog(headers),
      requestAdmin({ method: 'get', path: '/security/permission', headers: headers })
    ]);
    const rows = (Array.isArray(permissionsResult && permissionsResult.data) ? permissionsResult.data : [])
      .filter(function (item) {
        const groupId = getRefId(item && item.group);
        const menuId = getRefId(item && item.menu);
        return catalog.scopedGroupIds.has(groupId) && catalog.scopedMenuIds.has(menuId);
      });
    return response.status(200).json(Object.assign({}, permissionsResult, {
      data: rows
    }));
  } catch (err) {
    const normalized = normalizeError(err, 'iam_security_permission_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardUserRequest(request, response, options) {
  try {
    const result = await requestUser(createUserRequestOptions(request, options));
    relaySetCookie(response, result);
    return response.status(result.statusCode || options.successStatus || 200).json(result.payload);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_user_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function resolveCurrentAccount(request) {
  const result = await requestUser(createUserRequestOptions(request, {
    method: 'get',
    path: '/auth/me',
    params: {},
    data: {}
  }));
  const payload = result && result.payload ? result.payload : {};
  const data = payload && payload.data ? payload.data : null;
  return {
    statusCode: result.statusCode,
    payload: payload,
    account: data
  };
}

async function resolveCurrentAccountWithToken(request, accessToken) {
  const result = await requestUser(createUserRequestOptionsWithToken(request, {
    method: 'get',
    path: '/auth/me',
    params: {},
    data: {}
  }, accessToken));
  const payload = result && result.payload ? result.payload : {};
  const data = payload && payload.data ? payload.data : null;
  return {
    statusCode: result.statusCode,
    payload: payload,
    account: data
  };
}

async function revokeUserSession(request, accessToken) {
  if (!accessToken) return;
  try {
    await requestUser(createUserRequestOptionsWithToken(request, {
      method: 'post',
      path: '/auth/logout',
      params: {},
      data: {}
    }, accessToken));
  } catch (err) {
    // Best effort revoke. The original signin rejection should still be returned.
  }
}

async function forwardScopedSignin(request, response) {
  try {
    const signinResult = await requestUser(createUserRequestOptions(request, {
      method: 'post',
      path: '/signin'
    }));
    const payload = signinResult && signinResult.payload ? signinResult.payload : {};
    const accessToken = payload && payload.data && payload.data.xAccessToken
      ? String(payload.data.xAccessToken)
      : '';

    if (!accessToken) {
      relaySetCookie(response, signinResult);
      return response.status(signinResult.statusCode || 200).json(payload);
    }

    const current = await resolveCurrentAccountWithToken(request, accessToken);
    const accountId = current && current.account && current.account._id
      ? String(current.account._id)
      : '';
    const allowed = await isAccountInCurrentScope(accountId, {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    });

    if (!allowed) {
      await revokeUserSession(request, accessToken);
      return response.status(403).json({
        status: false,
        error: 'account_not_in_newSystem_scope'
      });
    }

    relaySetCookie(response, signinResult);
    return response.status(signinResult.statusCode || 200).json(payload);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_user_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardMyPermissions(request, response) {
  try {
    const newSystemAccount = await loadCurrentNewSystemAccount(request);
    const email = newSystemAccount && newSystemAccount.email ? newSystemAccount.email : '';
    if (!email) {
      return response.status(200).json({
        status: true,
        data: {
          accountId: null,
          assignments: [],
          permissions: [],
          matrix: {},
          allowed: false
        }
      });
    }

    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const iamAccountId = await resolveIamAccountIdByEmail(email);
    if (!iamAccountId) {
      return response.status(200).json({
        status: true,
        data: {
          accountId: null,
          assignments: [],
          permissions: [],
          matrix: {},
          allowed: false
        }
      });
    }

    const [result, scopedMetadata] = await Promise.all([
      requestAdmin({
        method: 'get',
        path: '/security/permission/my',
        params: Object.assign({}, request.query || {}, { accountId: iamAccountId }),
        headers: headers
      }),
      resolveScopedSecurityMetadata(headers)
    ]);
    if (result && result.data && scopedMetadata.expectedTypeTitle) {
      const allowedGroupIds = scopedMetadata.allowedGroupIds;
      const allowedMenuPaths = scopedMetadata.allowedMenuPaths;
      if (Array.isArray(result.data.assignments)) {
        result.data.assignments = dedupeByGroupTitle(result.data.assignments, function (item) {
          return item && item.group ? item.group : null;
        }).filter(function (item) {
          const groupId = getAssignmentGroupId(item);
          return groupId && allowedGroupIds.has(groupId);
        });
      }
      let scopedPermissionRows = [];
      if (Array.isArray(result.data.permissions)) {
        scopedPermissionRows = filterPermissionRows(result.data.permissions, allowedGroupIds, allowedMenuPaths);
        result.data.permissions = scopedPermissionRows;
      }
      result.data.matrix = buildPermissionMatrixFromRows(scopedPermissionRows);
      result.data.effectivePermissions = buildEffectivePermissionsFromMatrix(result.data.matrix);
      const requestedPath = normalizePermissionPath(request.query && request.query.path ? request.query.path : '');
      const requestedAction = String(request.query && request.query.action ? request.query.action : '').trim();
      if (requestedPath && requestedAction) {
        const rule = result.data.matrix[requestedPath] || {};
        result.data.allowed = allowedMenuPaths.has(requestedPath) && !!(rule.all || rule[requestedAction]);
      }
    }
    return response.status(200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_permission_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardAccountsList(request, response) {
  try {
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const [scopedMetadata, assignmentsResult] = await Promise.all([
      resolveScopedSecurityMetadata(headers),
      requestAdmin({
        method: 'get',
        path: '/security/assignment',
        params: { active: true },
        headers: headers
      })
    ]);

    let result = null;
    const allowedGroupIds = scopedMetadata.allowedGroupIds || new Set();
    const allowedGroupsById = scopedMetadata.allowedGroupsById || new Map();
    const scopedGroupsByAccountId = {};
    const assignmentRows = Array.isArray(assignmentsResult && assignmentsResult.data) ? assignmentsResult.data : [];
    assignmentRows.forEach(function (item) {
      const groupId = getAssignmentGroupId(item);
      if (!groupId || (scopedMetadata.expectedTypeTitle && !allowedGroupIds.has(groupId))) return;
      const accountId = getAssignmentAccountId(item);
      if (!accountId) return;
      const group = item && item.group && typeof item.group === 'object'
        ? item.group
        : allowedGroupsById.get(groupId);
      if (!group) return;
      if (!scopedGroupsByAccountId[accountId]) scopedGroupsByAccountId[accountId] = [];
      scopedGroupsByAccountId[accountId].push(group);
    });

    const allowedAccountIds = new Set(
      assignmentRows
        .filter(function (item) {
          const groupId = getAssignmentGroupId(item);
          return !scopedMetadata.expectedTypeTitle || (groupId && allowedGroupIds.has(groupId));
        })
        .map(getAssignmentAccountId)
        .filter(Boolean)
    );

    if (scopedMetadata.expectedTypeTitle) {
      if (allowedAccountIds.size) {
        result = await fetchAccountsList(headers, Object.assign({}, request.query || {}, {
          accountIds: Array.from(allowedAccountIds).join(',')
        }));
      } else {
        result = { status: true, data: [] };
      }
    } else {
      result = await fetchAccountsList(headers, request.query || {});
    }

    if (result && Array.isArray(result.data) && scopedMetadata.expectedTypeTitle) {
      result.data = result.data
        .filter(function (item) {
          const accountId = item && item._id ? String(item._id) : '';
          return accountId && allowedAccountIds.has(accountId);
        })
        .map(function (item) {
          const accountId = item && item._id ? String(item._id) : '';
          const scopedSecurityGroups = Array.isArray(item && item.securityGroups)
            ? item.securityGroups.filter(function (group) {
              const groupId = group && group._id ? String(group._id) : String(group || '');
              return groupId && allowedGroupIds.has(groupId);
            })
            : [];
          const resolvedGroups = scopedSecurityGroups.length ? scopedSecurityGroups : (scopedGroupsByAccountId[accountId] || []);
          return Object.assign({}, item, {
            securityGroups: dedupeByGroupTitle(resolvedGroups, function (group) { return group; })
          });
        });
    }
    const paginated = buildAccountListPagination(result && result.data, request.query || {});
    result.data = paginated.data;
    result.pagination = paginated.pagination;
    return response.status(200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_accounts_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function isAccountInCurrentScope(accountId, headers) {
  const normalizedAccountId = String(accountId || '').trim();
  if (!normalizedAccountId) return false;
  const scopedMetadata = await resolveScopedSecurityMetadata(headers || {});
  if (!scopedMetadata.expectedTypeTitle) return true;
  if (!scopedMetadata.allowedGroupIds.size) return false;
  const assignmentsResult = await requestAdmin({
    method: 'get',
    path: '/security/assignment',
    params: {
      accountId: normalizedAccountId,
      active: true
    },
    headers: headers || {}
  });
  return (Array.isArray(assignmentsResult && assignmentsResult.data) ? assignmentsResult.data : []).some(function (item) {
    const groupId = getAssignmentGroupId(item);
    return groupId && scopedMetadata.allowedGroupIds.has(groupId);
  });
}

async function requireScopedAccount(request, response, next) {
  try {
    const accountId = request && request.params && request.params.id ? String(request.params.id) : '';
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const allowed = await isAccountInCurrentScope(accountId, headers);
    if (!allowed) {
      return response.status(404).json({
        status: false,
        error: 'account_not_in_newSystem_scope'
      });
    }
    return next();
  } catch (err) {
    const normalized = normalizeError(err, 'iam_account_scope_check_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function removeAccountFromScope(accountId, headers) {
  const normalizedAccountId = String(accountId || '').trim();
  if (!normalizedAccountId) {
    return {
      accountId: null,
      removed: 0,
      assignments: []
    };
  }

  const requestHeaders = headers || {};
  const scopedMetadata = await resolveScopedSecurityMetadata(requestHeaders);
  if (!scopedMetadata.expectedTypeTitle || !scopedMetadata.allowedGroupIds.size) {
    return {
      accountId: normalizedAccountId,
      removed: 0,
      assignments: []
    };
  }

  const assignmentsResult = await requestAdmin({
    method: 'get',
    path: '/security/assignment',
    params: {
      accountId: normalizedAccountId,
      active: true
    },
    headers: requestHeaders
  });
  const scopedAssignments = (Array.isArray(assignmentsResult && assignmentsResult.data) ? assignmentsResult.data : [])
    .filter(function (item) {
      const groupId = getAssignmentGroupId(item);
      return groupId && scopedMetadata.allowedGroupIds.has(groupId);
    });

  for (const item of scopedAssignments) {
    if (!item || !item._id) continue;
    await requestAdmin({
      method: 'delete',
      path: '/security/assignment',
      data: {
        _id: item._id
      },
      headers: requestHeaders
    });
  }

  return {
    accountId: normalizedAccountId,
    removed: scopedAssignments.length,
    assignments: scopedAssignments
  };
}

async function forwardRemoveAccountFromScope(request, response) {
  try {
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const accountId = request && request.params && request.params.id ? String(request.params.id) : '';
    const data = await removeAccountFromScope(accountId, headers);
    return response.status(200).json({
      status: true,
      data: data
    });
  } catch (err) {
    const normalized = normalizeError(err, 'iam_remove_account_from_scope_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function inviteAccountToScope(payload, headers) {
  const body = payload || {};
  const email = body.email ? String(body.email).trim().toLowerCase() : '';
  if (!email) {
    const error = new Error('email_required');
    error.statusCode = 400;
    error.payload = { status: false, error: 'email_required' };
    throw error;
  }

  const groupIds = Array.isArray(body.groupIds)
    ? body.groupIds.map(function (id) { return String(id || '').trim(); }).filter(Boolean)
    : [];
  if (!groupIds.length) {
    const error = new Error('newSystem_group_required');
    error.statusCode = 400;
    error.payload = { status: false, error: 'newSystem_group_required' };
    throw error;
  }

  const requestHeaders = headers || {};
  const scopedMetadata = await resolveScopedSecurityMetadata(requestHeaders);
  const allowedGroupIds = scopedMetadata.allowedGroupIds || new Set();
  const scopedGroupIds = groupIds.filter(function (groupId) {
    return !scopedMetadata.expectedTypeTitle || allowedGroupIds.has(groupId);
  });
  if (!scopedGroupIds.length) {
    const error = new Error('newSystem_group_required');
    error.statusCode = 400;
    error.payload = { status: false, error: 'newSystem_group_required' };
    throw error;
  }

  const iamSdk = createNewSystemSdk();
  const inviteResult = await iamSdk.admin.inviteAccount({
    email: email,
    firstName: body.firstName || '',
    lastName: body.lastName || '',
    source: 'newSystem'
  });
  const account = inviteResult && inviteResult.data && inviteResult.data.account
    ? inviteResult.data.account
    : inviteResult && inviteResult.data
      ? inviteResult.data
      : null;
  const accountId = account && account._id ? String(account._id) : '';
  if (!accountId) {
    const error = new Error('iam_account_invite_failed');
    error.statusCode = 502;
    error.payload = { status: false, error: 'iam_account_invite_failed' };
    throw error;
  }

  const assignmentSnapshot = await syncAccountAssignments(accountId, scopedGroupIds);
  return {
    account: account,
    invited: !!(inviteResult && inviteResult.data && inviteResult.data.invited),
    assignments: assignmentSnapshot.assignments,
    groups: assignmentSnapshot.groups
  };
}

async function forwardInviteAccountToScope(request, response) {
  try {
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const data = await inviteAccountToScope(request.body || {}, headers);
    return response.status(data.invited ? 201 : 200).json({
      status: true,
      data: data
    });
  } catch (err) {
    const normalized = normalizeError(err, 'iam_invite_account_to_scope_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardAccountGroupOptions(request, response) {
  try {
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const [result, scopedMetadata] = await Promise.all([
      requestAdmin({
        method: 'get',
        path: '/accounts/group/options',
        params: request.query || {},
        headers: headers
      }),
      resolveScopedSecurityMetadata(headers)
    ]);
    const expectedTypeTitle = scopedMetadata.expectedTypeTitle;
    if (expectedTypeTitle && result && result.data && Array.isArray(result.data.groups)) {
      result.data.groups = dedupeByGroupTitle(result.data.groups.filter(function (item) {
        const itemId = item && item._id ? String(item._id) : '';
        if (itemId && scopedMetadata.allowedGroupIds.has(itemId)) return true;
        const raw = item && item.raw && typeof item.raw === 'object' ? item.raw : null;
        return getVisibleTypeTitle(raw) === expectedTypeTitle;
      }), function (item) {
        return item && item.raw && typeof item.raw === 'object' ? item.raw : item;
      });
    }
    return response.status(200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_account_group_options_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardAccountStatusOptions(request, response) {
  try {
    const result = await requestAdmin({
      method: 'get',
      path: '/accounts/status/options',
      params: request.query || {},
      headers: {
        lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
      }
    });
    return response.status(200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_account_status_options_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardEffectivePermissions(request, response) {
  try {
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const [result, scopedMetadata] = await Promise.all([
      requestAdmin({
        method: 'get',
        path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/effective-permissions`,
        params: request.query || {},
        headers: headers
      }),
      resolveScopedSecurityMetadata(headers)
    ]);
    if (result && result.data && scopedMetadata.expectedTypeTitle) {
      const allowedGroupIds = scopedMetadata.allowedGroupIds;
      const allowedMenuPaths = scopedMetadata.allowedMenuPaths;
      if (Array.isArray(result.data.groups)) {
        result.data.groups = dedupeByGroupTitle(result.data.groups.filter(function (item) {
          const group = item && item.group ? item.group : null;
          const groupId = group && group._id ? String(group._id) : '';
          return groupId && allowedGroupIds.has(groupId);
        }), function (item) {
          return item && item.group ? item.group : null;
        });
      }
      let scopedPermissionRows = null;
      if (Array.isArray(result.data.permissionRows)) {
        scopedPermissionRows = filterPermissionRows(result.data.permissionRows, allowedGroupIds, allowedMenuPaths);
        result.data.permissionRows = scopedPermissionRows;
      }
      if (Array.isArray(result.data.permissions)) {
        if (Array.isArray(scopedPermissionRows)) {
          result.data.permissions = scopedPermissionRows
            .map(function (item) { return item && item.name ? String(item.name) : ''; })
            .filter(Boolean);
        } else {
          scopedPermissionRows = filterPermissionRows(result.data.permissions, allowedGroupIds, allowedMenuPaths);
          result.data.permissions = scopedPermissionRows;
        }
      }
      result.data.matrix = Array.isArray(scopedPermissionRows)
        ? buildPermissionMatrixFromRows(scopedPermissionRows)
        : filterPermissionMatrix(result.data.matrix, allowedMenuPaths);
      result.data.effectivePermissions = buildEffectivePermissionsFromMatrix(result.data.matrix);
    }
    return response.status(200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_effective_permissions_proxy_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

function extractScopedGroupIds(body) {
  if (!body || typeof body !== 'object') return null;
  if (Array.isArray(body.groupIds)) return body.groupIds;
  if (Array.isArray(body.securityGroupIds)) return body.securityGroupIds;
  return null;
}

function sanitizeAccountUpdatePayload(body) {
  const payload = Object.assign({}, body || {});
  delete payload._id;
  delete payload.id;
  delete payload.groupIds;
  delete payload.securityGroupIds;
  delete payload.statusKey;
  return payload;
}

async function resolveScopedGroupIdsForUpdate(groupIds, headers) {
  if (!Array.isArray(groupIds)) return null;

  const normalizedGroupIds = Array.from(new Set(groupIds.map(function (id) {
    return String(id || '').trim();
  }).filter(Boolean)));
  const scopedMetadata = await resolveScopedSecurityMetadata(headers || {});
  const allowedGroupIds = scopedMetadata.allowedGroupIds || new Set();
  const scopedGroupIds = normalizedGroupIds.filter(function (groupId) {
    return !scopedMetadata.expectedTypeTitle || allowedGroupIds.has(groupId);
  });

  if (!scopedGroupIds.length) {
    const error = new Error('newSystem_group_required');
    error.statusCode = 400;
    error.payload = { status: false, error: 'newSystem_group_required' };
    throw error;
  }

  return scopedGroupIds;
}

async function forwardUpdateAccountToScope(request, response) {
  try {
    const accountId = String(request.params && request.params.id ? request.params.id : '');
    const headers = {
      lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
    };
    const body = request.body || {};
    const rawGroupIds = extractScopedGroupIds(body);
    const scopedGroupIds = await resolveScopedGroupIdsForUpdate(rawGroupIds, headers);
    const updateResult = await requestAdmin({
      method: 'put',
      path: `/accounts/${accountId}`,
      data: sanitizeAccountUpdatePayload(body),
      headers: headers
    });

    if (Array.isArray(scopedGroupIds)) {
      const assignmentSnapshot = await syncAccountAssignments(accountId, scopedGroupIds);
      if (updateResult && updateResult.data && typeof updateResult.data === 'object') {
        updateResult.data.securityAssignments = assignmentSnapshot.assignments;
        updateResult.data.securityGroups = assignmentSnapshot.groups;
      }
    }

    return response.status(200).json(updateResult);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_update_account_to_scope_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function forwardChangeAccountStatusToScope(request, response) {
  try {
    const accountId = String(request.params && request.params.id ? request.params.id : '');
    const result = await requestAdmin({
      method: 'put',
      path: `/accounts/${accountId}/status`,
      data: request.body || {},
      headers: {
        lang: request.headers && request.headers.lang ? request.headers.lang : 'th'
      }
    });
    return response.status(200).json(result);
  } catch (err) {
    const normalized = normalizeError(err, 'iam_change_account_status_to_scope_failed');
    return response.status(normalized.statusCode).json(normalized.payload);
  }
}

async function syncAccountAssignments(accountId, groupIds) {
  const iamAccountId = await resolveIamAccountIdByNewSystemAccountId(accountId);
  if (!iamAccountId) {
    return {
      accountId: null,
      assignments: [],
      groups: []
    };
  }

  const currentAssignmentsResult = await requestAdmin({
    method: 'get',
    path: '/security/assignment',
    params: {
      accountId: iamAccountId,
      active: true
    }
  });
  const currentAssignments = Array.isArray(currentAssignmentsResult && currentAssignmentsResult.data)
    ? currentAssignmentsResult.data
    : [];
  const scopedMetadata = await resolveScopedSecurityMetadata({});
  const allowedGroupIds = scopedMetadata.allowedGroupIds || new Set();
  const normalizedGroupIds = Array.isArray(groupIds)
    ? Array.from(new Set(groupIds.map(function (id) { return String(id || '').trim(); }).filter(Boolean)))
      .filter(function (groupId) {
        return !scopedMetadata.expectedTypeTitle || allowedGroupIds.has(groupId);
      })
    : [];

  const currentByGroupId = currentAssignments.reduce(function (acc, item) {
    const groupId = getAssignmentGroupId(item);
    if (scopedMetadata.expectedTypeTitle && (!groupId || !allowedGroupIds.has(groupId))) return acc;
    if (groupId) acc[groupId] = item;
    return acc;
  }, {});

  for (const groupId of normalizedGroupIds) {
    const existing = currentByGroupId[groupId];
    if (existing) {
      if (existing.active === false || existing.dataScope !== 'org') {
        await requestAdmin({
          method: 'put',
          path: '/security/assignment',
          data: {
            _id: existing._id,
            account: iamAccountId,
            group: groupId,
            active: true,
            dataScope: 'org',
            scopeUnits: []
          }
        });
      }
      delete currentByGroupId[groupId];
      continue;
    }

    await requestAdmin({
      method: 'post',
      path: '/security/assignment',
      data: {
        account: iamAccountId,
        group: groupId,
        active: true,
        dataScope: 'org',
        scopeUnits: []
      }
    });
  }

  const staleAssignments = Object.keys(currentByGroupId).map(function (groupId) {
    return currentByGroupId[groupId];
  });

  for (const item of staleAssignments) {
    if (!item || !item._id) continue;
    await requestAdmin({
      method: 'delete',
      path: '/security/assignment',
      data: {
        _id: item._id
      }
    });
  }

  const refreshedResult = await requestAdmin({
    method: 'get',
    path: '/security/assignment',
    params: {
      accountId: iamAccountId,
      active: true
    }
  });
  const assignments = (Array.isArray(refreshedResult && refreshedResult.data) ? refreshedResult.data : [])
    .filter(function (item) {
      const groupId = getAssignmentGroupId(item);
      return !scopedMetadata.expectedTypeTitle || (groupId && allowedGroupIds.has(groupId));
    });

  return {
    accountId: iamAccountId,
    assignments: assignments,
    groups: assignments.map(function (item) {
      return item && item.group ? item.group : null;
    }).filter(Boolean)
  };
}

module.exports = {
  ensureAdminConfig,
  resolveIamAccountIdByEmail,
  resolveIamAccountIdByNewSystemAccountId,
  requestAdmin,
  requestUser,
  forwardAdminRequest,
  forwardScopedSecurityTypes,
  forwardScopedSecurityMenus,
  forwardScopedSecurityGroups,
  forwardScopedSecurityPermissions,
  forwardScopedSignin,
  forwardUserRequest,
  resolveCurrentAccount,
  forwardMyPermissions,
  forwardAccountsList,
  requireScopedAccount,
  removeAccountFromScope,
  forwardRemoveAccountFromScope,
  inviteAccountToScope,
  forwardInviteAccountToScope,
  forwardAccountGroupOptions,
  forwardAccountStatusOptions,
  forwardEffectivePermissions,
  forwardUpdateAccountToScope,
  forwardChangeAccountStatusToScope,
  syncAccountAssignments
};
