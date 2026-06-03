'use strict';

const mongo = require('mongodb');
const config = require('../../../../config/config');
const TypeModel = require('../models/type.model');
const MenuModel = require('../models/menu.model');
const GroupModel = require('../models/group.model');
const PermissionModel = require('../models/permission.model');
const AssignmentModel = require('../models/assignment.model');

const securityConfig = config.security || {};
const DEFAULT_TYPE_TITLE = securityConfig.permissionTypeTitle || 'New System Administration';
const DEFAULT_GROUP_TITLE = securityConfig.permissionGroupTitle || 'New System Admin';
const DEFAULT_MENU_PATHS = (
  Array.isArray(securityConfig.permissionPaths) && securityConfig.permissionPaths.length > 1
    ? securityConfig.permissionPaths
    : [
  securityConfig.permissionRootPath || '/new-system/security/permission',
  '/dashboard',
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

function useLocalBootstrapAccess() {
  const mode = String(config.security && config.security.permissionBootstrapMode || '').trim().toLowerCase();
  if (mode === 'local') return true;
  if (mode === 'disabled' || mode === 'iam') return false;

  const iamAdmin = config.iamAdmin || {};
  return !(iamAdmin.baseUrl && iamAdmin.tokenPath && iamAdmin.basePath && iamAdmin.clientId && iamAdmin.clientSecret);
}

function toLang(value) {
  return [{ key: 'en', value: String(value || '').trim() }];
}

async function ensureType() {
  let type = await TypeModel.findOne({ 'title.value': DEFAULT_TYPE_TITLE });
  if (type) return type;

  type = await TypeModel.create({
    title: toLang(DEFAULT_TYPE_TITLE),
    description: toLang('Bootstrap type for NewSystem administration'),
    state: true
  });
  return type;
}

async function ensureMenus(typeId) {
  const menus = [];
  for (const path of DEFAULT_MENU_PATHS) {
    let menu = await MenuModel.findOne({ path: path });
    if (!menu) {
      menu = await MenuModel.create({
        title: toLang(path),
        description: toLang(`Bootstrap access for ${path}`),
        state: true,
        path: path,
        type: new mongo.ObjectId(typeId)
      });
    }
    menus.push(menu);
  }
  return menus;
}

async function ensureGroup(typeId) {
  let group = await GroupModel.findOne({ 'title.value': DEFAULT_GROUP_TITLE });
  if (group) return group;

  group = await GroupModel.create({
    title: toLang(DEFAULT_GROUP_TITLE),
    description: toLang('Bootstrap owner group for NewSystem'),
    state: true,
    visibleType: new mongo.ObjectId(typeId)
  });
  return group;
}

async function ensurePermissions(groupId, menus) {
  for (const menu of menus) {
    await PermissionModel.findOneAndUpdate(
      { group: new mongo.ObjectId(groupId), menu: new mongo.ObjectId(menu._id) },
      {
        $set: {
          all: true,
          view: true,
          edit: true,
          delete: true,
          action: true,
          logs: true
        }
      },
      { upsert: true, new: true }
    );
  }
}

exports.ensureBootstrapAccessForAccount = async function (accountId) {
  if (!accountId || !mongo.ObjectId.isValid(accountId)) return;
  if (!useLocalBootstrapAccess()) return;

  const type = await ensureType();
  const menus = await ensureMenus(type._id);
  const group = await ensureGroup(type._id);
  await ensurePermissions(group._id, menus);

  const accountObjectId = new mongo.ObjectId(accountId);
  const groupObjectId = new mongo.ObjectId(group._id);

  await AssignmentModel.findOneAndUpdate(
    { account: accountObjectId, group: groupObjectId },
    {
      $set: {
        active: true,
        dataScope: 'org',
        scopeUnits: []
      }
    },
    { upsert: true, new: true }
  );
};
