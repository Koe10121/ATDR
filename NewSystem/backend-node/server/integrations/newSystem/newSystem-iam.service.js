'use strict';

const { createProjectIamService } = require('../iam/project-iam-service');
const { normalizeAudience, normalizeScope } = require('../iam/iam-sdk-adapter');

const DEFAULT_NEW_SYSTEM_SCOPES = [
  'new.system.registry.read',
  'new.system.registry.write',
  'new.system.report.read',
  'iam.security.read',
  'iam.security.write',
  'iam.audit.read',
  'iam.accounts.read'
];

function applyNewSystemDefaults(payload) {
  const source = payload || {};
  const metadata = Object.assign({}, source.metadata || {});

  const targetSystem = String(source.targetSystem || metadata.targetSystem || 'newSystem').trim();
  const ownerEmail = String(source.ownerEmail || metadata.ownerEmail || 'new-system.integration@example.com').trim();
  const partnerId = String(source.partnerId || metadata.partnerId || 'new-system-team').trim();
  const tenant = String(source.tenant || metadata.tenant || 'iam-shared').trim();
  const systemCode = source.systemCode || metadata.systemCode || null;

  return Object.assign({}, source, {
    targetSystem: targetSystem,
    ownerEmail: ownerEmail,
    partnerId: partnerId,
    tenant: tenant,
    allowedScopes: normalizeScope(source.allowedScopes || metadata.allowedScopes || DEFAULT_NEW_SYSTEM_SCOPES),
    allowedAudiences: normalizeAudience(source.allowedAudiences || metadata.allowedAudiences || 'new-system-api'),
    metadata: Object.assign({}, metadata, systemCode ? {
      systemCode: String(systemCode).trim()
    } : {}, {
      targetSystem: targetSystem,
      ownerEmail: ownerEmail,
      partnerId: partnerId,
      tenant: tenant
    })
  });
}

function createNewSystemIamService(config) {
  const projectIamService = createProjectIamService(config);

  return Object.assign({}, projectIamService, {
    async registerManagedClient(payload, options) {
      return projectIamService.registerManagedClient(applyNewSystemDefaults(payload), options || {});
    },
    async updateManagedClient(payload, options) {
      return projectIamService.updateManagedClient(applyNewSystemDefaults(payload), options || {});
    }
  });
}

module.exports = {
  createNewSystemIamService: createNewSystemIamService
};
