'use strict';

const express = require('express');
const router = express.Router();

const account = require('../accounts/service/account');
const iamAdminClient = require('./service/iam-admin-client');
const authorization = require('./service/authorization');

const APP_SCOPE = 'newSystem';
const SECURITY_TYPE_PATHS = [
  '/security/permissions/menu',
  '/security/permissions/group',
  '/security/permissions/matrix',
  '/security/permission'
];
const SECURITY_MENU_PATHS = ['/security/permissions/menu', '/security/permission'];
const SECURITY_GROUP_PATHS = ['/security/permissions/group', '/security/permission'];
const SECURITY_MATRIX_PATHS = ['/security/permissions/matrix', '/security/permission'];

const canViewType = authorization.requirePermission(SECURITY_TYPE_PATHS, 'view');
const canEditType = authorization.requirePermission(SECURITY_TYPE_PATHS, 'edit');
const canDeleteType = authorization.requirePermission(SECURITY_TYPE_PATHS, 'delete');
const canViewMenu = authorization.requirePermission(SECURITY_MENU_PATHS, 'view');
const canEditMenu = authorization.requirePermission(SECURITY_MENU_PATHS, 'edit');
const canDeleteMenu = authorization.requirePermission(SECURITY_MENU_PATHS, 'delete');
const canViewGroup = authorization.requirePermission(SECURITY_GROUP_PATHS, 'view');
const canEditGroup = authorization.requirePermission(SECURITY_GROUP_PATHS, 'edit');
const canDeleteGroup = authorization.requirePermission(SECURITY_GROUP_PATHS, 'delete');
const canViewPermission = authorization.requirePermission(SECURITY_MATRIX_PATHS, 'view');
const canEditPermission = authorization.requirePermission(SECURITY_MATRIX_PATHS, 'edit');
const canDeletePermission = authorization.requirePermission(SECURITY_MATRIX_PATHS, 'delete');
const canViewAssignment = authorization.requirePermission(SECURITY_MATRIX_PATHS, 'view');
const canEditAssignment = authorization.requirePermission(SECURITY_MATRIX_PATHS, 'edit');
const canDeleteAssignment = authorization.requirePermission(SECURITY_MATRIX_PATHS, 'delete');
const canViewAudit = authorization.requirePermission('/security/audit', 'view');

function withNewSystemScope(body) {
  return Object.assign({}, body || {}, {
    appId: APP_SCOPE,
    source: APP_SCOPE
  });
}

router.use(account.onCheckAuthorization);

router.get('/type', canViewType, function (request, response) {
  return iamAdminClient.forwardScopedSecurityTypes(request, response);
});
router.post('/type', canEditType, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'post',
    path: '/security/type',
    data: withNewSystemScope(request.body),
    successStatus: 201
  });
});
router.put('/type', canEditType, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'put',
    path: '/security/type',
    data: withNewSystemScope(request.body)
  });
});
router.delete('/type', canDeleteType, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'delete',
    path: '/security/type'
  });
});

router.get('/menu', canViewMenu, function (request, response) {
  return iamAdminClient.forwardScopedSecurityMenus(request, response);
});
router.post('/menu', canEditMenu, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'post',
    path: '/security/menu',
    data: withNewSystemScope(request.body),
    successStatus: 201
  });
});
router.put('/menu', canEditMenu, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'put',
    path: '/security/menu',
    data: withNewSystemScope(request.body)
  });
});
router.delete('/menu', canDeleteMenu, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'delete',
    path: '/security/menu'
  });
});

router.get('/group', canViewGroup, function (request, response) {
  return iamAdminClient.forwardScopedSecurityGroups(request, response);
});
router.post('/group', canEditGroup, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'post',
    path: '/security/group',
    successStatus: 201
  });
});
router.put('/group', canEditGroup, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'put',
    path: '/security/group'
  });
});
router.delete('/group', canDeleteGroup, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'delete',
    path: '/security/group'
  });
});

router.get('/permission', canViewPermission, function (request, response) {
  return iamAdminClient.forwardScopedSecurityPermissions(request, response);
});
router.get('/permission/my', iamAdminClient.forwardMyPermissions);
router.post('/permission', canEditPermission, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'post',
    path: '/security/permission',
    successStatus: 201
  });
});
router.put('/permission', canEditPermission, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'put',
    path: '/security/permission'
  });
});
router.delete('/permission', canDeletePermission, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'delete',
    path: '/security/permission'
  });
});
router.post('/permission/create/batch', canEditPermission, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'post',
    path: '/security/permission/create/batch'
  });
});
router.put('/permission/update/batch', canEditPermission, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'put',
    path: '/security/permission/update/batch'
  });
});

router.get('/assignment', canViewAssignment, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'get',
    path: '/security/assignment'
  });
});
router.post('/assignment', canEditAssignment, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'post',
    path: '/security/assignment',
    successStatus: 201
  });
});
router.put('/assignment', canEditAssignment, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'put',
    path: '/security/assignment'
  });
});
router.delete('/assignment', canDeleteAssignment, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'delete',
    path: '/security/assignment'
  });
});

router.get('/audit/events', canViewAudit, function (request, response) {
  return iamAdminClient.forwardAdminRequest(request, response, {
    method: 'get',
    path: '/security/audit/events'
  });
});

module.exports = router;
