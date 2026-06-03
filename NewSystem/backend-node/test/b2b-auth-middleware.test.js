'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createB2BAuthMiddleware } = require('../server/integrations/iam/b2b-auth-middleware');

function createResponseRecorder() {
  return {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    }
  };
}

test('b2b auth middleware accepts a valid token and attaches context', async function () {
  const middleware = createB2BAuthMiddleware({
    requiredAudience: 'new-system-api',
    createIamService() {
      return {
        async introspectToken() {
          return {
            active: true,
            aud: 'new-system-api',
            scope: 'sample.read sample.write'
          };
        },
        async getClientProfile() {
          return {
            client_id: 'sample-client'
          };
        }
      };
    }
  });

  const request = {
    headers: {
      authorization: 'Bearer token-1'
    }
  };
  const response = createResponseRecorder();
  let nextCalled = false;

  await middleware.onCheckB2BAuthorization(request, response, function () {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(request.b2b.profile.client_id, 'sample-client');
  assert.deepEqual(request.b2b.scopes, ['sample.read', 'sample.write']);
});

test('b2b auth middleware rejects wrong audience', async function () {
  const middleware = createB2BAuthMiddleware({
    requiredAudience: 'new-system-api',
    createIamService() {
      return {
        async introspectToken() {
          return {
            active: true,
            aud: 'other-api',
            scope: 'sample.read'
          };
        },
        async getClientProfile() {
          return {
            client_id: 'sample-client'
          };
        }
      };
    }
  });

  const request = {
    headers: {
      authorization: 'Bearer token-1'
    }
  };
  const response = createResponseRecorder();
  let nextCalled = false;

  await middleware.onCheckB2BAuthorization(request, response, function () {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.payload.error, 'invalid_audience');
});

test('b2b auth middleware requireScope enforces expected scope', function () {
  const middleware = createB2BAuthMiddleware();
  const request = {
    b2b: {
      scopes: ['sample.read']
    }
  };
  const response = createResponseRecorder();
  let nextCalled = false;

  middleware.requireScope('sample.write')(request, response, function () {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.payload.required_scope, 'sample.write');
});
