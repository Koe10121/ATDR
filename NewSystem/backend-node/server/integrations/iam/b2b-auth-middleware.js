'use strict';

const projectConfig = require('../../../config/project.config');
const { createProjectIamService } = require('./project-iam-service');

function getAuthorizationToken(request) {
  const raw = String(request && request.headers && request.headers.authorization || '');
  return raw.replace(/^Bearer\s+/i, '').trim();
}

function parseScopes(value) {
  return String(value || '').split(/[\s,]+/).filter(Boolean);
}

function createDefaultIamService() {
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

function createB2BAuthMiddleware(options) {
  const runtimeOptions = Object.assign({
    requiredAudience: projectConfig.iam.requiredAudience,
    createIamService: createDefaultIamService
  }, options || {});

  async function loadB2BContext(token) {
    const iamService = runtimeOptions.createIamService();
    const introspection = await iamService.introspectToken(token);

    if (!introspection || !introspection.active) {
      return {
        introspection: introspection || { active: false },
        profile: null,
        scopes: []
      };
    }

    const profile = await iamService.getClientProfile({ token: token });
    return {
      introspection: introspection,
      profile: profile,
      scopes: parseScopes(introspection.scope)
    };
  }

  async function onCheckB2BAuthorization(request, response, next) {
    try {
      const token = getAuthorizationToken(request);
      if (!token) {
        return response.status(401).json({ error: 'missing_bearer_token' });
      }

      const context = await loadB2BContext(token);
      if (!context.introspection.active) {
        return response.status(401).json({ error: 'invalid_token' });
      }

      const audience = String(context.introspection.aud || '');
      if (runtimeOptions.requiredAudience && audience !== runtimeOptions.requiredAudience) {
        return response.status(403).json({ error: 'invalid_audience' });
      }

      request.b2b = {
        token: token,
        introspection: context.introspection,
        profile: context.profile,
        scopes: context.scopes
      };
      return next();
    } catch (error) {
      return response.status(502).json({
        error: 'iam_integration_failed',
        details: error && error.response ? error.response.data : error.message
      });
    }
  }

  function requireScope(scope) {
    return function (request, response, next) {
      const scopes = request.b2b && Array.isArray(request.b2b.scopes) ? request.b2b.scopes : [];
      if (scopes.indexOf(scope) === -1) {
        return response.status(403).json({
          error: 'insufficient_scope',
          required_scope: scope
        });
      }
      return next();
    };
  }

  return {
    onCheckB2BAuthorization: onCheckB2BAuthorization,
    requireScope: requireScope,
    _private: {
      getAuthorizationToken: getAuthorizationToken,
      parseScopes: parseScopes,
      loadB2BContext: loadB2BContext
    }
  };
}

const defaultMiddleware = createB2BAuthMiddleware();

module.exports = Object.assign({}, defaultMiddleware, {
  createB2BAuthMiddleware: createB2BAuthMiddleware
});
