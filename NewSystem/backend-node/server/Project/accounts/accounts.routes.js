'use strict';

const express = require('express');
const router = express.Router();

const Account = require("./service/account");
const authorization = require("../security/service/authorization");
const iamAdminClient = require("../security/service/iam-admin-client");

// const google = require("../../../helpers/google/oAuth2");

const canViewAccounts = authorization.requirePermission('/accounts/directory', 'view');
const canEditAccounts = authorization.requirePermission('/accounts/directory', 'edit', {
  targetAccountId: (request) => request.params && request.params.id ? String(request.params.id) : ''
});
const canActionAccounts = authorization.requirePermission('/accounts/directory', 'action', {
  targetAccountId: (request) => request.params && request.params.id ? String(request.params.id) : ''
});
const canViewLifecycle = authorization.requirePermission('/accounts/lifecycle', 'view', {
  targetAccountId: (request) => request.params && request.params.id ? String(request.params.id) : ''
});
const canEditLifecycle = authorization.requirePermission('/accounts/lifecycle', 'edit', {
  targetAccountId: (request) => request.params && request.params.id ? String(request.params.id) : ''
});
const canActionLifecycle = authorization.requirePermission('/accounts/lifecycle', 'action', {
  targetAccountId: (request) => request.params && request.params.id ? String(request.params.id) : ''
});

router.post("/signin", function (request, response) {
  return iamAdminClient.forwardScopedSignin(request, response);
});
router.get("/auth/me", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'get',
    path: '/auth/me'
  });
});
router.get("/auth/sessions", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'get',
    path: '/auth/sessions'
  });
});
router.delete("/auth/sessions/:id", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'delete',
    path: `/auth/sessions/${String(request.params && request.params.id ? request.params.id : '')}`
  });
});
router.post("/auth/logout", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: '/auth/logout'
  });
});
router.post("/auth/logout-all", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: '/auth/logout-all'
  });
});
router.post("/auth/2fa/request", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: '/auth/2fa/request'
  });
});
router.post("/auth/2fa/verify", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: '/auth/2fa/verify'
  });
});
router.get("/auth/trusted-devices", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'get',
    path: '/auth/trusted-devices'
  });
});
router.post("/auth/trust-device", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: '/auth/trust-device'
  });
});
router.delete("/auth/trusted-devices/:id", Account.onCheckAuthorization, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'delete',
    path: `/auth/trusted-devices/${String(request.params && request.params.id ? request.params.id : '')}`
  });
});
router.get("/accounts", Account.onCheckAuthorization, canViewAccounts, function (request, response) {
  return iamAdminClient.forwardAccountsList(request, response);
});
router.post("/accounts/invite", Account.onCheckAuthorization, canActionAccounts, function (request, response) {
  return iamAdminClient.forwardInviteAccountToScope(request, response);
});
router.put("/accounts/:id", Account.onCheckAuthorization, canEditAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUpdateAccountToScope(request, response);
});
router.delete("/accounts/:id/newSystem-access", Account.onCheckAuthorization, canActionAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardRemoveAccountFromScope(request, response);
});
router.get("/accounts/:id/sessions", Account.onCheckAuthorization, canViewAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'get',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/sessions`
  });
});
router.delete("/accounts/:id/sessions/:sessionId", Account.onCheckAuthorization, canActionAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'delete',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/sessions/${String(request.params && request.params.sessionId ? request.params.sessionId : '')}`
  });
});
router.get("/accounts/:id/trusted-devices", Account.onCheckAuthorization, canViewAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'get',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/trusted-devices`
  });
});
router.delete("/accounts/:id/trusted-devices/:trustedDeviceId", Account.onCheckAuthorization, canActionAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'delete',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/trusted-devices/${String(request.params && request.params.trustedDeviceId ? request.params.trustedDeviceId : '')}`
  });
});
router.get("/accounts/:id/lifecycle", Account.onCheckAuthorization, canViewLifecycle, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'get',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/lifecycle`
  });
});
router.put("/accounts/:id/lifecycle", Account.onCheckAuthorization, canEditLifecycle, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'put',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/lifecycle`
  });
});
router.post("/accounts/:id/provision", Account.onCheckAuthorization, canActionLifecycle, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/provision`
  });
});
router.post("/accounts/:id/deprovision", Account.onCheckAuthorization, canActionLifecycle, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardUserRequest(request, response, {
    method: 'post',
    path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/deprovision`
  });
});
router.get("/accounts/group/options", Account.onCheckAuthorization, canViewAccounts, function (request, response) {
  return iamAdminClient.forwardAccountGroupOptions(request, response);
});
router.get("/accounts/:id/effective-permissions", Account.onCheckAuthorization, canViewAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardEffectivePermissions(request, response);
});
router.get("/accounts/status/options", Account.onCheckAuthorization, canViewAccounts, function (request, response) {
  return iamAdminClient.forwardAccountStatusOptions(request, response);
});
router.put("/accounts/:id/status", Account.onCheckAuthorization, canActionAccounts, iamAdminClient.requireScopedAccount, function (request, response) {
  return iamAdminClient.forwardChangeAccountStatusToScope(request, response);
});



// router.post( "/d", google.onDistance);
// app.post(path + "/singin", Infomation_Accounts.verifyIdTokenGoogle, Infomation_Accounts.SingIn);


module.exports = router;
