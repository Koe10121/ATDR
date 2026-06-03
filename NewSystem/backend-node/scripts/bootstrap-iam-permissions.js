'use strict';

const projectConfig = require('../config/project.config');
const { createProjectIamService } = require('../server/integrations/iam/project-iam-service');

function toLocalizedText(value) {
  return [{ key: 'en', value: String(value || '').trim() }];
}

function getIamService() {
  return createProjectIamService({
    baseUrl: projectConfig.iam.baseUrl,
    clientId: projectConfig.iamAdmin.clientId,
    clientSecret: projectConfig.iamAdmin.clientSecret,
    timeoutMs: projectConfig.iamAdmin.timeoutMs,
    token: {
      path: projectConfig.iamAdmin.tokenPath,
      scope: projectConfig.iamAdmin.scope,
      audience: projectConfig.iam.requiredAudience
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

function listRows(payload) {
  return Array.isArray(payload && payload.data) ? payload.data : [];
}

function hasLocalizedTitle(item, expectedTitle) {
  return Array.isArray(item && item.title) && item.title.some(function (entry) {
    return entry && entry.value === expectedTitle;
  });
}

async function ensureType(iamService) {
  const list = await iamService.listSecurityTypes();
  const rows = listRows(list);
  const existing = rows.find(function (row) {
    return hasLocalizedTitle(row, projectConfig.security.permissionTypeTitle);
  });

  if (existing) return existing;

  const created = await iamService.sdk.admin.request({
    method: 'post',
    path: '/security/type',
    data: {
      title: toLocalizedText(projectConfig.security.permissionTypeTitle),
      description: toLocalizedText('Delegated administration type managed by the IAM project template.'),
      state: true
    }
  });

  return created.data;
}

async function ensureGroup(iamService, typeId) {
  const list = await iamService.listSecurityGroups();
  const rows = listRows(list);
  const existing = rows.find(function (row) {
    return hasLocalizedTitle(row, projectConfig.security.permissionGroupTitle);
  });

  if (existing) return existing;

  const created = await iamService.sdk.admin.request({
    method: 'post',
    path: '/security/group',
    data: {
      title: toLocalizedText(projectConfig.security.permissionGroupTitle),
      description: toLocalizedText('Delegated administration group managed by the IAM project template.'),
      visibleType: typeId,
      state: true
    }
  });

  return created.data;
}

async function ensureMenus(iamService, typeId) {
  const list = await iamService.listSecurityMenus();
  const rows = listRows(list);
  const menus = [];

  for (const path of projectConfig.security.permissionPaths) {
    let item = rows.find(function (row) {
      return row && row.path === path;
    });

    if (!item) {
      const created = await iamService.sdk.admin.request({
        method: 'post',
        path: '/security/menu',
        data: {
          title: toLocalizedText(path),
          description: toLocalizedText('Template-managed permission path for ' + path),
          path: path,
          type: typeId,
          state: true
        }
      });
      item = created.data;
    }

    menus.push(item);
  }

  return menus;
}

async function ensurePermissions(iamService, groupId, menus) {
  let list = await iamService.listSecurityPermissions();
  let rows = listRows(list);

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
      await iamService.sdk.admin.request({
        method: 'put',
        path: '/security/permission',
        data: Object.assign({ _id: existing._id }, payload)
      });
      continue;
    }

    try {
      await iamService.sdk.admin.request({
        method: 'post',
        path: '/security/permission',
        data: payload
      });
    } catch (error) {
      list = await iamService.listSecurityPermissions();
      rows = listRows(list);
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

async function main() {
  ensureConfig();

  const iamService = getIamService();
  const type = await ensureType(iamService);
  const menus = await ensureMenus(iamService, type._id);
  const group = await ensureGroup(iamService, type._id);
  await ensurePermissions(iamService, group._id, menus);

  console.log(JSON.stringify({
    ok: true,
    compatProfile: projectConfig.iam.compatProfile,
    typeId: type._id,
    groupId: group._id,
    menuCount: menus.length,
    paths: menus.map(function (item) { return item.path; })
  }, null, 2));
}

main().catch(function (error) {
  console.error(JSON.stringify({
    message: error.message,
    response: error.response && error.response.data ? error.response.data : null
  }, null, 2));
  process.exit(1);
});
