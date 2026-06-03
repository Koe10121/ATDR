'use strict';

const { URL } = require('url');

const {
  createIamSdkAdapter,
  normalizeAudience,
  normalizeScope
} = require('./iam-sdk-adapter');

function toLocalizedText(value) {
  const normalized = String(value || '').trim();
  return normalized ? [{ key: 'en', value: normalized }] : [];
}

function slugifyValue(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

function safeUrl(value) {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function parseHostFromUrl(value) {
  try {
    return new URL(String(value || '').trim()).hostname || null;
  } catch (error) {
    return null;
  }
}

function isIpOrLocalhost(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === 'localhost' || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized);
}

function buildEnvironmentPayload(environmentSource, source) {
  const environmentName = String(
    environmentSource.name ||
    environmentSource.environmentName ||
    source.targetEnv ||
    source.environmentName ||
    'prod'
  ).trim();
  const endpoint = safeUrl(environmentSource.serverBaseUrl || environmentSource.endpoint || source.endpointUrl);
  const endpointHost = parseHostFromUrl(endpoint);
  const explicitClientId = String(environmentSource.clientId || source.clientId || '').trim();
  const fallbackClientId = [slugifyValue(source.clientId), slugifyValue(environmentName)].filter(Boolean).join('-');

  return {
    title: toLocalizedText(environmentName),
    endpoint: endpoint,
    status: String(environmentSource.status || source.environmentStatus || 'live').trim(),
    clientId: explicitClientId || fallbackClientId || null,
    clientSecret: String(environmentSource.clientSecret || '').trim() || null,
    server: {
      type: String(environmentSource.serverType || source.serverType || 'container').trim(),
      location: String(environmentSource.location || source.location || '').trim() || null,
      domain: isIpOrLocalhost(endpointHost) ? null : endpointHost,
      ip: String(environmentSource.ip || '').trim() || (isIpOrLocalhost(endpointHost) ? endpointHost : null),
      port: String(environmentSource.port || '').trim() || null,
      username: String(environmentSource.username || '').trim() || null,
      password: String(environmentSource.password || '').trim() || null
    },
    routes: Array.isArray(environmentSource.routes) ? environmentSource.routes : [],
    database: {
      type: null,
      host: null,
      name: null,
      port: null,
      username: null,
      password: null
    },
    devOps: {
      healthCheckUrl: safeUrl(environmentSource.healthCheckUrl || null),
      docsUrl: safeUrl(environmentSource.docsUrl || null),
      vpn: String(environmentSource.vpn || 'no').trim(),
      ssl: String(environmentSource.ssl || 'yes').trim(),
      git: {
        repository: String(environmentSource.repository || environmentSource.gitRepository || '').trim() || null,
        branch: String(environmentSource.branch || environmentSource.gitBranch || '').trim() || null
      },
      harbor: {
        project: String(environmentSource.harborProject || '').trim() || null,
        repository: String(environmentSource.harborRepository || '').trim() || null,
        tag: String(environmentSource.harborTag || '').trim() || null
      },
      pipeline: {
        script: String(environmentSource.pipelineScript || '').trim() || null
      }
    }
  };
}

function normalizeRotateRequest(clientOrPayload, options) {
  if (clientOrPayload && typeof clientOrPayload === 'object') {
    return {
      clientId: clientOrPayload.clientId || clientOrPayload._id || '',
      options: Object.assign({}, options || {}, {
        environmentClientId: clientOrPayload.environmentClientId || options && options.environmentClientId
      })
    };
  }

  return {
    clientId: clientOrPayload,
    options: Object.assign({}, options || {})
  };
}

function buildApplicationClientPayload(payload) {
  const source = payload || {};
  const environments = Array.isArray(source.metadata && source.metadata.environments) && source.metadata.environments.length
    ? source.metadata.environments.map(function (environment) {
      return buildEnvironmentPayload(environment || {}, source);
    })
    : [buildEnvironmentPayload({}, source)];

  const applicationId = String(
    source.applicationId ||
    source.metadata && source.metadata.applicationId ||
    source.clientId ||
    source.systemCode ||
    'sample-client'
  ).trim();
  const appId = String(
    source.appId ||
    source.systemCode ||
    source.metadata && source.metadata.systemCode ||
    source.clientId ||
    applicationId
  ).trim();
  const targetSystem = String(
    source.targetSystem ||
    source.metadata && source.metadata.targetSystem ||
    source.systemCode ||
    appId
  ).trim();

  return {
    _id: source._id,
    application: {
      ApplicationId: applicationId,
      AppId: appId,
      version: String(source.version || '').trim() || null,
      title: toLocalizedText(source.clientName || source.clientId || applicationId),
      description: toLocalizedText(source.description || 'Project service integration managed by the IAM adapter.'),
      types: [String(source.type || 'app').trim()],
      policyUrl: safeUrl(source.policyUrl || null),
      privacyUrl: safeUrl(source.privacyUrl || null)
    },
    environments: environments.map(function (environment) {
      return Object.assign({}, environment, {
        clientId: environment.clientId || String(source.clientId || '').trim() || null
      });
    }),
    status: source.status || 'active',
    metadata: Object.assign({}, source.metadata || {}, {
      targetSystem: targetSystem,
      systemCode: source.systemCode || source.metadata && source.metadata.systemCode || appId,
      ownerEmail: source.ownerEmail || source.metadata && source.metadata.ownerEmail || null,
      partnerId: source.partnerId || source.metadata && source.metadata.partnerId || null,
      tenant: source.tenant || source.metadata && source.metadata.tenant || null,
      allowedScopes: normalizeScope(source.allowedScopes || source.metadata && source.metadata.allowedScopes || ''),
      allowedAudiences: normalizeAudience(source.allowedAudiences || source.metadata && source.metadata.allowedAudiences || '')
    })
  };
}

function resolveGroupName(group) {
  if (!group || typeof group !== 'object') return null;
  if (group.name) return String(group.name).trim() || null;
  if (group.label) return String(group.label).trim() || null;
  if (Array.isArray(group.title)) {
    const localized = group.title.find(function (item) {
      return item && String(item.value || '').trim();
    });
    if (localized) return String(localized.value).trim();
  }
  return null;
}

function normalizeGroupsResponse(payload) {
  const source = payload || {};
  const items = Array.isArray(source.data) ? source.data : [];

  return Object.assign({}, source, {
    data: items.map(function (group) {
      return Object.assign({}, group, {
        name: resolveGroupName(group)
      });
    })
  });
}

function createProjectIamService(config) {
  const sdk = createIamSdkAdapter(config);

  return {
    sdk: sdk,
    async bootstrap() {
      const accessToken = await sdk.getAccessToken();
      const profile = await sdk.getClientProfile({ token: accessToken });
      const introspection = await sdk.introspectToken(accessToken);

      return {
        accessToken: accessToken,
        profile: profile,
        introspection: introspection
      };
    },
    async getAccessToken(options) {
      return sdk.getAccessToken(options || {});
    },
    async introspectToken(token) {
      return sdk.introspectToken(token);
    },
    async getClientProfile(options) {
      return sdk.getClientProfile(options || {});
    },
    async listManagedClients(options) {
      return sdk.admin.listApplicationClients(options || {});
    },
    async registerManagedClient(payload, options) {
      return sdk.admin.createApplicationClient(buildApplicationClientPayload(payload), options || {});
    },
    async updateManagedClient(payload, options) {
      return sdk.admin.updateApplicationClient(buildApplicationClientPayload(payload), options || {});
    },
    async rotateManagedClientSecret(clientId, options) {
      const normalized = normalizeRotateRequest(clientId, options);
      return sdk.admin.rotateApplicationClientSecret(normalized.clientId, normalized.options);
    },
    async deleteManagedClient(clientId, options) {
      return sdk.admin.deleteApplicationClient(clientId, options || {});
    },
    async lookupAccountByEmail(email, options) {
      return sdk.admin.lookupAccountByEmail(email, options || {});
    },
    async listSecurityTypes(options) {
      return sdk.admin.listSecurityTypes(options || {});
    },
    async listSecurityMenus(options) {
      return sdk.admin.listSecurityMenus(options || {});
    },
    async listSecurityPermissions(options) {
      return sdk.admin.listSecurityPermissions(options || {});
    },
    async listSecurityGroups(options) {
      const response = await sdk.admin.listSecurityGroups(options || {});
      return normalizeGroupsResponse(response);
    },
    async listAuditEvents(options) {
      return sdk.admin.listAuditEvents(options || {});
    },
    async listAssignments(options) {
      return sdk.admin.listSecurityAssignments(options || {});
    },
    async listAccounts(options) {
      return sdk.admin.listAccounts(options || {});
    },
    async getEffectivePermissions(accountId, options) {
      return sdk.admin.getEffectivePermissions(accountId, options || {});
    }
  };
}

module.exports = {
  buildApplicationClientPayload: buildApplicationClientPayload,
  createProjectIamService: createProjectIamService
};
