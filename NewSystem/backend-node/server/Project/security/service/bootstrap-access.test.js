'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const config = require('../../../../config/config');
const bootstrapAccess = require('./bootstrap-access');
const TypeModel = require('../models/type.model');

let originalFindOne;
let originalCreate;

test.before(function () {
  config.iamAdmin.baseUrl = 'https://iam.mfu.ac.th';
  config.iamAdmin.tokenPath = '/api/v1/b2b/token';
  config.iamAdmin.basePath = '/api/v1/b2b/admin';
  config.iamAdmin.clientId = 'new-system-sdk';
  config.iamAdmin.clientSecret = 'super-secret';

  originalFindOne = TypeModel.findOne;
  originalCreate = TypeModel.create;
});

test.after(function () {
  TypeModel.findOne = originalFindOne;
  TypeModel.create = originalCreate;
});

test('bootstrap-access is a no-op when NewSystem runs with IAM-backed permissions', async function () {
  let touched = false;
  TypeModel.findOne = async function () {
    touched = true;
    return null;
  };
  TypeModel.create = async function () {
    touched = true;
    return { _id: 'type-1' };
  };

  await bootstrapAccess.ensureBootstrapAccessForAccount('507f191e810c19729de860ea');

  assert.equal(touched, false);
});
