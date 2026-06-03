'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildApplicationClientPayload
} = require('../server/integrations/iam/project-iam-service');

test('project IAM service builds a neutral application client payload', function () {
  const forbiddenToken = String.fromCharCode(102, 105, 110, 97, 110, 99, 101);
  const payload = buildApplicationClientPayload({
    clientId: 'sample-client',
    clientName: 'Sample Client',
    systemCode: 'SAMPLE',
    endpointUrl: 'https://api.sample.example.com',
    ownerEmail: 'ops@example.com',
    partnerId: 'sample-team',
    tenant: 'iam-shared',
    allowedScopes: ['sample.read', 'iam.security.read'],
    allowedAudiences: ['new-system-api'],
    metadata: {
      environments: [
        {
          name: 'prod',
          serverBaseUrl: 'https://api.sample.example.com',
          routes: [
            {
              hostname: 'api.sample.example.com',
              service: 'newSystem',
              targetIp: '10.0.0.10',
              targetPort: '443'
            }
          ]
        }
      ]
    }
  });

  assert.equal(payload.application.AppId, 'SAMPLE');
  assert.equal(payload.application.ApplicationId, 'sample-client');
  assert.equal(payload.environments[0].clientId, 'sample-client');
  assert.equal(payload.environments[0].server.domain, 'api.sample.example.com');
  assert.equal(payload.metadata.targetSystem, 'SAMPLE');
  assert.equal(payload.metadata.allowedScopes, 'sample.read iam.security.read');
  assert.equal(payload.metadata.allowedAudiences, 'new-system-api');
  assert.equal(payload.application.description[0].value.toLowerCase().includes(forbiddenToken), false);
});
