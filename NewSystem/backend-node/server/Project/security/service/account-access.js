'use strict';

const mongo = require('mongodb');
const config = require('../../../../config/config');
const SecurityAssignment = require('../models/assignment.model');
const SecurityGroup = require('../models/group.model');
const SecurityPermission = require('../controller/permission');
const AccountModel = require('../../accounts/controller/account');
const { createNewSystemSdk } = require('../../../integrations/iam/sdk');

function toObjectId(id) {
  if (!id || !mongo.ObjectId.isValid(id)) return null;
  return new mongo.ObjectId(id);
}

function pickLangValue(items) {
  if (!Array.isArray(items)) return '';
  const found = items.find(function (item) {
    return item && item.value;
  });
  return found ? String(found.value) : '';
}

function getSecurityGroupLabel(group) {
  if (!group) return '-';
  return pickLangValue(group.title) || String(group.key || '') || '-';
}

function normalizePermissionPath(path) {
  if (!path) return '';
  let normalized = String(path).trim();
  const queryIndex = normalized.indexOf('?');
  if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex);
  const hashIndex = normalized.indexOf('#');
  if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex);
  normalized = normalized.replace(/\/{2,}/g, '/');
  if (!normalized.startsWith('/')) normalized = '/' + normalized;
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

function buildPermissionMatrix(permissions) {
  const map = {};
  for (let i = 0; i < permissions.length; i++) {
    const row = permissions[i] || {};
    const path = normalizePermissionPath(row.menu && row.menu.path ? row.menu.path : '');
    if (!path) continue;
    if (!map[path]) {
      map[path] = { all: false, view: false, edit: false, delete: false, action: false, logs: false };
    }
    map[path].all = map[path].all || !!row.all;
    map[path].view = map[path].view || !!row.view;
    map[path].edit = map[path].edit || !!row.edit;
    map[path].delete = map[path].delete || !!row.delete;
    map[path].action = map[path].action || !!row.action;
    map[path].logs = map[path].logs || !!row.logs;
  }
  return map;
}

function getRefId(ref) {
  if (ref && typeof ref === 'object') {
    return ref._id ? String(ref._id) : '';
  }
  return ref ? String(ref) : '';
}

function getRefTitle(ref) {
  if (!ref || typeof ref !== 'object') return '';
  return pickLangValue(ref.title) || String(ref.name || ref.key || ref.label || '');
}

function getVisibleTypeTitle(group) {
  if (!group || typeof group !== 'object') return '';
  return getRefTitle(group.visibleType);
}

function getAssignmentGroupId(assignment) {
  return getRefId(assignment && assignment.group ? assignment.group : null);
}

function getPermissionGroupId(permission) {
  return getRefId(permission && permission.group ? permission.group : null);
}

function getPermissionMenuPath(permission) {
  const menu = permission && permission.menu ? permission.menu : null;
  if (menu && typeof menu === 'object' && menu.path) {
    return normalizePermissionPath(menu.path);
  }
  if (permission && permission.path) {
    return normalizePermissionPath(permission.path);
  }
  return '';
}

function getConfiguredPermissionPaths() {
  const paths = config.security && Array.isArray(config.security.permissionPaths)
    ? config.security.permissionPaths
    : [];
  return new Set(paths.map(normalizePermissionPath).filter(Boolean));
}

async function resolveScopedPermissionMetadata(sdk) {
  const expectedTypeTitle = config.security && config.security.permissionTypeTitle
    ? String(config.security.permissionTypeTitle).trim()
    : '';
  const configuredPaths = getConfiguredPermissionPaths();

  if (!expectedTypeTitle) {
    return {
      expectedTypeTitle: '',
      allowedGroupIds: new Set(),
      allowedMenuPaths: configuredPaths
    };
  }

  const groupsResult = await sdk.admin.request({
    method: 'get',
    path: '/security/group',
    params: {}
  });
  const groups = Array.isArray(groupsResult && groupsResult.data) ? groupsResult.data : [];
  const allowedGroupIds = new Set(groups
    .filter(function (group) {
      return getVisibleTypeTitle(group) === expectedTypeTitle;
    })
    .map(function (group) {
      return getRefId(group);
    })
    .filter(Boolean));

  if (configuredPaths.size) {
    return {
      expectedTypeTitle: expectedTypeTitle,
      allowedGroupIds: allowedGroupIds,
      allowedMenuPaths: configuredPaths
    };
  }

  const menusResult = await sdk.admin.request({
    method: 'get',
    path: '/security/menu',
    params: {}
  });
  const allowedMenuPaths = new Set((Array.isArray(menusResult && menusResult.data) ? menusResult.data : [])
    .filter(function (menu) {
      return getRefTitle(menu && menu.type ? menu.type : null) === expectedTypeTitle;
    })
    .map(function (menu) {
      return normalizePermissionPath(menu && menu.path ? menu.path : '');
    })
    .filter(Boolean));

  return {
    expectedTypeTitle: expectedTypeTitle,
    allowedGroupIds: allowedGroupIds,
    allowedMenuPaths: allowedMenuPaths
  };
}

function hasIamScopeAccess(assignments, accountId, targetAccountId) {
  return (assignments || []).some(function (assignment) {
    if (!assignment || assignment.active === false) return false;
    const scope = assignment.dataScope || 'self';
    if (scope === 'org') return true;
    if (scope === 'self') {
      return !targetAccountId || String(targetAccountId) === String(accountId);
    }
    return false;
  });
}

function filterScopedIamPermissionData(data, metadata, iamAccountId, targetIamAccountId, options) {
  const allowedGroupIds = metadata.allowedGroupIds || new Set();
  const allowedMenuPaths = metadata.allowedMenuPaths || new Set();
  const assignments = (Array.isArray(data.assignments) ? data.assignments : [])
    .filter(function (assignment) {
      const groupId = getAssignmentGroupId(assignment);
      return !metadata.expectedTypeTitle || (groupId && allowedGroupIds.has(groupId));
    });
  const permissions = (Array.isArray(data.permissions) ? data.permissions : [])
    .filter(function (permission) {
      const groupId = getPermissionGroupId(permission);
      const menuPath = getPermissionMenuPath(permission);
      return (!metadata.expectedTypeTitle || (groupId && allowedGroupIds.has(groupId))) &&
        (!allowedMenuPaths.size || allowedMenuPaths.has(menuPath));
    });
  const matrix = buildPermissionMatrix(permissions);
  const effectivePermissions = Object.keys(matrix)
    .sort()
    .map(function (path) {
      return Object.assign({ path: path }, matrix[path] || {});
    });

  let allowed = null;
  if (options && options.path && options.action) {
    const paths = Array.isArray(options.path) ? options.path : [options.path];
    const hasMenuPermission = paths.some(function (path) {
      const normalizedPath = normalizePermissionPath(path);
      const rule = matrix[normalizedPath];
      return !!(rule && (rule.all || rule[options.action]));
    });
    allowed = hasMenuPermission && hasIamScopeAccess(assignments, iamAccountId, targetIamAccountId);
  }

  return {
    accountId: data.accountId || iamAccountId,
    assignments: assignments,
    groups: assignments,
    permissions: permissions,
    matrix: matrix,
    effectivePermissions: effectivePermissions,
    allowed: allowed,
    source: 'iam'
  };
}

function useIamPermissionSource() {
  const source = String(config.security && config.security.permissionSource || 'iam').trim().toLowerCase();
  if (source === 'local') return false;
  const iamAdmin = config.iamAdmin || {};
  return !!(iamAdmin.baseUrl && iamAdmin.tokenPath && iamAdmin.basePath && iamAdmin.clientId && iamAdmin.clientSecret);
}

async function findNewSystemAccountById(accountId) {
  if (!accountId) return null;
  try {
    if (mongo.ObjectId.isValid(accountId)) {
      return await AccountModel.onQuery({ _id: new mongo.ObjectId(accountId) });
    }
    return await AccountModel.onQuery({ _id: accountId });
  } catch (error) {
    return null;
  }
}

async function resolveIamAccountIdByNewSystemAccountId(accountId) {
  const newSystemAccount = await findNewSystemAccountById(accountId);
  if (!newSystemAccount) return String(accountId || '');
  const email = newSystemAccount && newSystemAccount.email ? String(newSystemAccount.email).trim().toLowerCase() : '';
  if (!email) return String(accountId || '');
  const sdk = createNewSystemSdk();
  const result = await sdk.admin.lookupAccountByEmail(email);
  const data = result && result.data ? result.data : null;
  return data && data._id ? String(data._id) : String(accountId || '');
}

async function getIamPermissionData(accountId, options) {
  if (!useIamPermissionSource()) return null;

  const iamAccountId = await resolveIamAccountIdByNewSystemAccountId(accountId);
  if (!iamAccountId) return {
    accountId: null,
    assignments: [],
    groups: [],
    permissions: [],
    matrix: {},
    effectivePermissions: [],
    allowed: false,
    source: 'iam'
  };

  const params = {
    accountId: iamAccountId
  };

  if (options && options.path) params.path = options.path;
  if (options && options.action) params.action = options.action;

  let targetIamAccountId = '';
  if (options && options.targetAccountId) {
    targetIamAccountId = await resolveIamAccountIdByNewSystemAccountId(options.targetAccountId);
    if (!targetIamAccountId && options.path && options.action) {
      return {
        accountId: iamAccountId,
        assignments: [],
        groups: [],
        permissions: [],
        matrix: {},
        effectivePermissions: [],
        allowed: false,
        source: 'iam'
      };
    }
    if (targetIamAccountId) params.targetAccountId = targetIamAccountId;
  }

  const sdk = createNewSystemSdk();
  const [result, metadata] = await Promise.all([
    sdk.admin.request({
      method: 'get',
      path: '/security/permission/my',
      params: params
    }),
    resolveScopedPermissionMetadata(sdk)
  ]);
  const data = result && result.data ? result.data : {};
  return filterScopedIamPermissionData(data, metadata, iamAccountId, targetIamAccountId, options || {});
}

async function loadAssignmentsByAccountIds(accountIds) {
  const ids = Array.isArray(accountIds) ? accountIds.filter(Boolean) : [];
  if (ids.length === 0) return {};

  if (useIamPermissionSource()) {
    const sdk = createNewSystemSdk();
    const rows = await Promise.all(ids.map(async function (newSystemAccountId) {
      try {
        const iamAccountId = await resolveIamAccountIdByNewSystemAccountId(newSystemAccountId);
        if (!iamAccountId) {
          return [String(newSystemAccountId), []];
        }
        const result = await sdk.admin.request({
          method: 'get',
          path: '/security/assignment',
          params: {
            accountId: iamAccountId,
            active: true
          }
        });
        const assignments = Array.isArray(result && result.data) ? result.data : [];
        return [String(newSystemAccountId), assignments];
      } catch (error) {
        return [String(newSystemAccountId), null];
      }
    }));

    const failed = rows.some(function (entry) {
      return entry[1] === null;
    });
    if (!failed) {
      return rows.reduce(function (acc, entry) {
        acc[entry[0]] = entry[1];
        return acc;
      }, {});
    }
    throw new Error('iam_assignment_snapshot_failed');
  }

  const rows = await SecurityAssignment.find({
    account: { $in: ids.map(function (id) { return toObjectId(id); }).filter(Boolean) },
    active: true
  })
    .populate({ path: 'group', select: 'title description visibleType' })
    .lean();

  return rows.reduce(function (acc, row) {
    const accountId = row && row.account ? String(row.account) : '';
    if (!accountId) return acc;
    if (!acc[accountId]) acc[accountId] = [];
    if (row.group) acc[accountId].push(row);
    return acc;
  }, {});
}

async function syncAccountAssignments(accountId, groupIds) {
  const normalizedAccountId = toObjectId(accountId);
  if (!normalizedAccountId) return;

  const normalizedGroupIds = Array.isArray(groupIds)
    ? Array.from(new Set(groupIds.map(function (id) {
      const objectId = toObjectId(id);
      return objectId ? String(objectId) : '';
    }).filter(Boolean)))
    : [];

  const existingAssignments = await SecurityAssignment.find({ account: normalizedAccountId }).lean();
  const activeAssignmentMap = existingAssignments.reduce(function (acc, item) {
    const key = item && item.group ? String(item.group) : '';
    if (key) acc[key] = item;
    return acc;
  }, {});

  for (let i = 0; i < normalizedGroupIds.length; i++) {
    const groupId = normalizedGroupIds[i];
    const existing = activeAssignmentMap[groupId];
    if (existing) {
      if (existing.active === false) {
        await SecurityAssignment.updateOne({ _id: existing._id }, { $set: { active: true } });
      }
      delete activeAssignmentMap[groupId];
      continue;
    }

    await SecurityAssignment.create({
      account: normalizedAccountId,
      group: toObjectId(groupId),
      active: true,
      dataScope: 'self',
      scopeUnits: []
    });
  }

  const remainingIds = Object.keys(activeAssignmentMap);
  if (remainingIds.length > 0) {
    await SecurityAssignment.updateMany(
      {
        _id: {
          $in: remainingIds
            .map(function (id) { return toObjectId(activeAssignmentMap[id] && activeAssignmentMap[id]._id); })
            .filter(Boolean)
        }
      },
      { $set: { active: false } }
    );
  }
}

async function getGroupOptions() {
  if (useIamPermissionSource()) {
    const sdk = createNewSystemSdk();
    const result = await sdk.admin.request({
      method: 'get',
      path: '/accounts/group/options',
      params: {}
    });
    const data = result && result.data ? result.data : {};
    const groups = Array.isArray(data.groups) ? data.groups : (Array.isArray(data) ? data : []);
    return groups.map(function (item) {
      return {
        _id: item && item._id ? item._id : null,
        label: item && item.label ? item.label : getSecurityGroupLabel(item && item.raw ? item.raw : item),
        raw: item && item.raw ? item.raw : item
      };
    });
  }

  const docs = await SecurityGroup.find({})
    .select('title description visibleType')
    .lean();

  return (docs || []).map(function (item) {
    return {
      _id: item && item._id ? item._id : null,
      label: getSecurityGroupLabel(item),
      raw: item
    };
  });
}

async function getLocalEffectivePermissions(accountId) {
  const accountObjectId = toObjectId(accountId);
  if (!accountObjectId) {
    return {
      accountId: null,
      assignments: [],
      groups: [],
      permissions: [],
      matrix: {},
      effectivePermissions: []
    };
  }

  const assignments = await SecurityAssignment.find({ account: accountObjectId, active: true })
    .populate({ path: 'group', select: 'title description visibleType' })
    .lean();

  const groupIds = assignments
    .map(function (item) { return item.group && item.group._id ? item.group._id : item.group; })
    .filter(Boolean);

  let permissionRows = [];
  if (groupIds.length > 0) {
    permissionRows = await SecurityPermission.onQuerys({ group: { $in: groupIds } });
  }

  const matrix = buildPermissionMatrix(permissionRows);
  const effectivePermissions = Object.keys(matrix)
    .sort()
    .map(function (path) {
      return Object.assign({ path: path }, matrix[path] || {});
    });

  return {
    accountId: accountObjectId,
    assignments: assignments,
    groups: assignments.map(function (item) {
      return {
        assignmentId: item && item._id ? item._id : null,
        scope: item && item.dataScope ? item.dataScope : 'self',
        active: item ? item.active !== false : true,
        group: item && item.group ? item.group : null,
        label: getSecurityGroupLabel(item && item.group ? item.group : null)
      };
    }),
    permissions: permissionRows,
    matrix: matrix,
    effectivePermissions: effectivePermissions
  };
}

async function getEffectivePermissions(accountId, options) {
  if (useIamPermissionSource()) {
    return getIamPermissionData(accountId, options || {});
  }
  const localData = await getLocalEffectivePermissions(accountId);
  return Object.assign({}, localData, { source: 'local' });
}

async function evaluatePermission(accountId, paths, action, options) {
  const candidates = Array.isArray(paths) ? paths.filter(Boolean) : [paths].filter(Boolean);
  const targetAccountId = options && options.targetAccountId ? options.targetAccountId : null;
  let iamEvaluated = false;
  let lastIamData = null;

  if (useIamPermissionSource() && candidates.length > 0) {
    for (let index = 0; index < candidates.length; index += 1) {
      const candidate = normalizePermissionPath(candidates[index]);
      if (!candidate) continue;
      iamEvaluated = true;
      const data = await getIamPermissionData(accountId, {
        path: candidate,
        action: action,
        targetAccountId: targetAccountId
      });
      lastIamData = data;
      if (data && data.allowed === true) {
        return {
          allowed: true,
          matchedPath: candidate,
          permissionData: data,
          source: 'iam'
        };
      }
    }

    if (iamEvaluated) {
      return {
        allowed: false,
        matchedPath: '',
        permissionData: lastIamData || {
          accountId: null,
          assignments: [],
          permissions: [],
          matrix: {},
          effectivePermissions: [],
          source: 'iam'
        },
        source: 'iam'
      };
    }
  }

  const permissionData = await getLocalEffectivePermissions(accountId);
  const matrix = permissionData && permissionData.matrix ? permissionData.matrix : {};
  const allowed = candidates.some(function (path) {
    const normalizedPath = normalizePermissionPath(path);
    const rule = matrix[normalizedPath];
    return !!(rule && (rule.all || rule[action]));
  });

  return {
    allowed: allowed,
    matchedPath: allowed
      ? candidates.find(function (path) {
        const normalizedPath = normalizePermissionPath(path);
        const rule = matrix[normalizedPath];
        return !!(rule && (rule.all || rule[action]));
      })
      : '',
    permissionData: Object.assign({}, permissionData, { source: 'local' }),
    source: 'local'
  };
}

function collectAccountScopeKeys(account) {
  const keys = new Set();
  if (!account || typeof account !== 'object') return [];

  const snapshot = account.hrContext && account.hrContext.snapshot ? account.hrContext.snapshot : {};
  [
    snapshot.orgUnitCode,
    snapshot.orgUnitName,
    snapshot.orgGroupName,
    snapshot.subUnitName
  ].filter(Boolean).forEach(function (item) {
    keys.add(String(item));
  });

  const affiliations = account.lifecycle && Array.isArray(account.lifecycle.affiliations)
    ? account.lifecycle.affiliations
    : [];
  affiliations.forEach(function (item) {
    if (!item) return;
    if (item.orgCode) keys.add(String(item.orgCode));
    if (Array.isArray(item.orgPath)) {
      item.orgPath.filter(Boolean).forEach(function (pathItem) {
        keys.add(String(pathItem));
      });
    }
  });

  return Array.from(keys);
}

function hasAssignmentScope(assignments, actorAccountId, targetAccount) {
  const targetAccountId = targetAccount && targetAccount._id ? String(targetAccount._id) : '';
  const targetScopeKeys = collectAccountScopeKeys(targetAccount);

  return (assignments || []).some(function (assignment) {
    if (!assignment || assignment.active === false) return false;
    var scope = assignment.dataScope || 'self';
    if (scope === 'org') return true;
    if (scope === 'self') {
      return !!(targetAccountId && String(actorAccountId) === targetAccountId);
    }
    if (scope === 'unit') {
      var units = Array.isArray(assignment.scopeUnits) ? assignment.scopeUnits.map(String) : [];
      return units.some(function (unit) {
        return targetScopeKeys.indexOf(unit) !== -1;
      });
    }
    return false;
  });
}

module.exports = {
  getGroupOptions,
  getEffectivePermissions,
  evaluatePermission,
  loadAssignmentsByAccountIds,
  syncAccountAssignments,
  collectAccountScopeKeys,
  hasAssignmentScope
};
