'use strict';

const config = require('../../../config/config');
const { createIamSdkAdapter } = require('./iam-sdk-adapter');

function mergeSection(baseSection, overrideSection) {
  return Object.assign({}, baseSection || {}, overrideSection || {});
}

function buildSdkConfig(overrides) {
  const source = overrides || {};

  return {
    baseUrl: source.baseUrl || config.iam && config.iam.baseUrl,
    clientId: source.clientId || config.iamAdmin && config.iamAdmin.clientId,
    clientSecret: source.clientSecret || config.iamAdmin && config.iamAdmin.clientSecret,
    timeout: source.timeout || config.iamAdmin && config.iamAdmin.timeout,
    token: mergeSection({
      path: config.iamAdmin && config.iamAdmin.tokenPath,
      scope: config.iamAdmin && config.iamAdmin.scope,
      audience: config.iamAdmin && config.iamAdmin.audience
    }, source.token),
    admin: mergeSection({
      path: config.iamAdmin && config.iamAdmin.basePath,
      scope: config.iamAdmin && config.iamAdmin.scope,
      audience: config.iamAdmin && config.iamAdmin.audience
    }, source.admin),
    endpoints: mergeSection({
      introspectPath: config.iam && config.iam.introspectPath,
      mePath: config.iam && config.iam.profilePath
    }, source.endpoints)
  };
}

function createAdminConvenienceApi(sdk) {
  return Object.assign({}, sdk.admin, {
    inviteAccount(payload, options) {
      return sdk.admin.request({
        method: 'post',
        path: '/accounts/invite',
        data: payload || {},
        scope: options && options.scope
      });
    },
    listAccountGroupOptions(options) {
      return sdk.admin.request({
        method: 'get',
        path: '/accounts/group/options',
        params: options && options.params,
        scope: options && options.scope,
        retries: 1
      });
    },
    listAccountStatusOptions(options) {
      return sdk.admin.request({
        method: 'get',
        path: '/accounts/status/options',
        params: options && options.params,
        scope: options && options.scope,
        retries: 1
      });
    }
  });
}

function createB2bConvenienceApi(admin) {
  return {
    listClients(options) {
      return admin.listApplicationClients(options || {});
    },
    createClient(payload, options) {
      return admin.createApplicationClient(payload || {}, options || {});
    },
    updateClient(payload, options) {
      return admin.updateApplicationClient(payload || {}, options || {});
    },
    rotateClientSecret(clientId, options) {
      return admin.rotateApplicationClientSecret(clientId, options || {});
    },
    deleteClient(clientId, options) {
      return admin.deleteApplicationClient(clientId, options || {});
    }
  };
}

function createNewSystemSdk(overrides) {
  const sdk = createIamSdkAdapter(buildSdkConfig(overrides));
  const admin = createAdminConvenienceApi(sdk);

  return Object.assign({}, sdk, {
    admin: admin,
    b2b: createB2bConvenienceApi(admin)
  });
}

module.exports = {
  createNewSystemSdk: createNewSystemSdk
};
