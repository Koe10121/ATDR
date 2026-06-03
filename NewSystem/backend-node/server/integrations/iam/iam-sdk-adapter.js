'use strict';

const { URL, URLSearchParams } = require('url');

const DEFAULT_TIMEOUT_MS = Number(process.env.IAM_SDK_TIMEOUT_MS || 10000);
const DEFAULT_TOKEN_SKEW_SECONDS = Number(process.env.IAM_SDK_TOKEN_SKEW_SECONDS || 15);

function normalizeBaseUrl(baseUrl) {
  const normalized = String(baseUrl || '').trim().replace(/\/+$/, '');
  if (!normalized) {
    throw new Error('IAM SDK baseUrl is required');
  }
  return normalized;
}

function normalizeScope(scope) {
  if (Array.isArray(scope)) {
    return Array.from(new Set(scope.map(function (item) {
      return String(item || '').trim();
    }).filter(Boolean))).join(' ');
  }

  return String(scope || '')
    .split(/[\s,]+/)
    .map(function (item) { return String(item || '').trim(); })
    .filter(Boolean)
    .filter(function (item, index, list) { return list.indexOf(item) === index; })
    .join(' ');
}

function normalizeAudience(audience) {
  if (Array.isArray(audience)) {
    return String(audience[0] || '').trim();
  }
  return String(audience || '').trim();
}

function buildBasicAuthorization(clientId, clientSecret) {
  return 'Basic ' + Buffer.from(String(clientId || '') + ':' + String(clientSecret || ''), 'utf8').toString('base64');
}

function buildTokenCacheKey(scope, audience) {
  return JSON.stringify({
    scope: normalizeScope(scope),
    audience: normalizeAudience(audience)
  });
}

function isRetriableError(error) {
  if (!error) return false;
  if (error.name === 'AbortError') return true;
  if (error.code === 'ECONNABORTED' || error.code === 'ECONNRESET' || error.code === 'ENOTFOUND') {
    return true;
  }

  const status = error.statusCode || error.status || error.response && error.response.status;
  return Number(status) >= 500;
}

function shouldRetry(method, retries) {
  const normalized = String(method || 'get').trim().toLowerCase();
  if (retries <= 0) return false;
  return normalized === 'get';
}

async function withRetry(executor, options) {
  const retries = Number(options && options.retries || 0);
  const method = options && options.method ? options.method : 'get';
  let attempt = 0;

  while (true) {
    try {
      return await executor();
    } catch (error) {
      if (!shouldRetry(method, retries - attempt) || !isRetriableError(error)) {
        throw error;
      }
      attempt += 1;
    }
  }
}

function buildUrl(baseUrl, path, params) {
  const url = new URL(String(path || ''), baseUrl + '/');
  const query = new URLSearchParams();

  Object.keys(params || {}).forEach(function (key) {
    const value = params[key];
    if (value === undefined || value === null || value === '') return;
    query.append(key, String(value));
  });

  const rawQuery = query.toString();
  if (rawQuery) {
    url.search = rawQuery;
  }

  return url;
}

async function requestJson(baseUrl, options) {
  const url = buildUrl(baseUrl, options.url, options.params);
  const timeoutMs = Number(options.timeout || DEFAULT_TIMEOUT_MS);
  const controller = new AbortController();
  const timeoutRef = setTimeout(function () {
    controller.abort();
  }, timeoutMs);

  const headers = Object.assign({}, options.headers || {});
  const normalizedMethod = String(options.method || 'get').toUpperCase();
  const hasBody = options.data !== undefined && normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD';
  const responseOptions = {
    method: normalizedMethod,
    headers: headers,
    signal: controller.signal
  };

  if (hasBody) {
    responseOptions.body = JSON.stringify(options.data);
    if (!responseOptions.headers['Content-Type']) {
      responseOptions.headers['Content-Type'] = 'application/json';
    }
  }

  try {
    const response = await fetch(url, responseOptions);
    const text = await response.text();
    const payload = text ? JSON.parse(text) : {};

    if (!response.ok) {
      const error = new Error(responseOptions.method + ' ' + url.pathname + ' failed');
      error.statusCode = response.status;
      error.response = {
        status: response.status,
        data: payload
      };
      throw error;
    }

    return payload;
  } catch (error) {
    if (error.name === 'AbortError') {
      error.code = 'ECONNABORTED';
    }
    throw error;
  } finally {
    clearTimeout(timeoutRef);
  }
}

function createIamSdkAdapter(config) {
  const baseUrl = normalizeBaseUrl(config && config.baseUrl);
  const clientId = String(config && config.clientId || '').trim();
  const clientSecret = String(config && config.clientSecret || '').trim();
  const timeoutMs = Number(config && config.timeoutMs || config && config.timeout || DEFAULT_TIMEOUT_MS);
  const tokenSkewSeconds = Number(config && config.tokenSkewSeconds || DEFAULT_TOKEN_SKEW_SECONDS);

  const tokenConfig = Object.assign({
    path: '/api/v1/b2b/token',
    scope: '',
    audience: ''
  }, config && config.token || {});

  const adminConfig = Object.assign({
    path: '/api/v1/b2b/admin',
    scope: '',
    audience: ''
  }, config && config.admin || {});

  const endpointConfig = Object.assign({
    introspectPath: '/api/v1/b2b/introspect',
    mePath: '/api/v1/b2b/clients/me'
  }, config && config.endpoints || {});

  const tokenCache = new Map();

  function ensureClientCredentials() {
    if (!clientId || !clientSecret) {
      throw new Error('IAM SDK clientId and clientSecret are required');
    }
  }

  async function request(options) {
    const method = String(options && options.method || 'get').toLowerCase();
    return withRetry(function () {
      return requestJson(baseUrl, {
        url: options.url,
        method: method,
        headers: Object.assign({}, options.headers || {}),
        params: options.params || {},
        data: options.data,
        timeout: options.timeout || timeoutMs
      });
    }, {
      method: method,
      retries: Number(options && options.retries || 0)
    });
  }

  async function fetchToken(params) {
    ensureClientCredentials();

    const scope = normalizeScope(params && params.scope != null ? params.scope : tokenConfig.scope);
    const audience = normalizeAudience(params && params.audience != null ? params.audience : tokenConfig.audience);
    const cacheKey = buildTokenCacheKey(scope, audience);
    const forceRefresh = !!(params && params.forceRefresh);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const cached = tokenCache.get(cacheKey);

    if (!forceRefresh && cached && cached.expiresAt > nowSeconds + tokenSkewSeconds) {
      return Object.assign({}, cached.payload);
    }

    const payload = await request({
      method: 'post',
      url: tokenConfig.path,
      retries: 1,
      headers: {
        Authorization: buildBasicAuthorization(clientId, clientSecret),
        'Content-Type': 'application/json'
      },
      data: {
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        scope: scope || undefined,
        audience: audience || undefined
      }
    });

    const expiresIn = Number(payload.expires_in || 0);
    tokenCache.set(cacheKey, {
      payload: payload,
      expiresAt: nowSeconds + expiresIn
    });

    return Object.assign({}, payload);
  }

  async function getAccessToken(params) {
    const tokenPayload = await fetchToken(params || {});
    return tokenPayload.access_token || '';
  }

  async function getAuthorizationHeader(params) {
    const accessToken = await getAccessToken(params || {});
    return 'Bearer ' + accessToken;
  }

  async function introspectToken(token) {
    return request({
      method: 'post',
      url: endpointConfig.introspectPath,
      headers: {
        'Content-Type': 'application/json'
      },
      data: {
        token: token
      }
    });
  }

  async function getClientProfile(params) {
    const token = params && params.token ? params.token : await getAccessToken(params || {});
    return request({
      method: 'get',
      url: endpointConfig.mePath,
      retries: 1,
      headers: {
        Authorization: 'Bearer ' + token
      }
    });
  }

  async function callAdmin(options) {
    ensureClientCredentials();

    const scope = normalizeScope(options && options.scope != null ? options.scope : adminConfig.scope || tokenConfig.scope);
    const audience = normalizeAudience(options && options.audience != null ? options.audience : adminConfig.audience || tokenConfig.audience);

    return request({
      method: options.method,
      url: String(adminConfig.path || '') + String(options.path || ''),
      retries: Number(options && options.retries || 0),
      headers: Object.assign({}, options.headers || {}, {
        Authorization: await getAuthorizationHeader({
          scope: scope,
          audience: audience,
          forceRefresh: !!(options && options.forceRefresh)
        })
      }),
      params: options.params,
      data: options.data
    });
  }

  return {
    getAccessToken: getAccessToken,
    getAuthorizationHeader: getAuthorizationHeader,
    introspectToken: introspectToken,
    getClientProfile: getClientProfile,
    clearTokenCache: function () {
      tokenCache.clear();
    },
    admin: {
      request: function (options) {
        return callAdmin(options || {});
      },
      listApplicationClients: function (options) {
        return callAdmin({ method: 'get', path: '/apps', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      createApplicationClient: function (payload, options) {
        return callAdmin({ method: 'post', path: '/apps', data: payload || {}, scope: options && options.scope });
      },
      updateApplicationClient: function (payload, options) {
        return callAdmin({ method: 'put', path: '/apps', data: payload || {}, scope: options && options.scope });
      },
      rotateApplicationClientSecret: function (clientId, options) {
        return callAdmin({
          method: 'post',
          path: '/apps/' + clientId + '/rotate-secret',
          data: {
            environmentClientId: options && options.environmentClientId
          },
          scope: options && options.scope
        });
      },
      deleteApplicationClient: function (clientId, options) {
        return callAdmin({ method: 'delete', path: '/apps/' + clientId, scope: options && options.scope });
      },
      listSecurityTypes: function (options) {
        return callAdmin({ method: 'get', path: '/security/type', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      listSecurityMenus: function (options) {
        return callAdmin({ method: 'get', path: '/security/menu', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      listSecurityGroups: function (options) {
        return callAdmin({ method: 'get', path: '/security/group', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      listSecurityPermissions: function (options) {
        return callAdmin({ method: 'get', path: '/security/permission', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      listSecurityAssignments: function (options) {
        return callAdmin({ method: 'get', path: '/security/assignment', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      listAuditEvents: function (options) {
        return callAdmin({ method: 'get', path: '/security/audit/events', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      lookupAccountByEmail: function (email, options) {
        return callAdmin({
          method: 'get',
          path: '/accounts/lookup',
          params: { email: email },
          scope: options && options.scope,
          retries: 1
        });
      },
      listAccounts: function (options) {
        return callAdmin({ method: 'get', path: '/accounts', params: options && options.params, scope: options && options.scope, retries: 1 });
      },
      getEffectivePermissions: function (accountId, options) {
        return callAdmin({
          method: 'get',
          path: '/accounts/' + accountId + '/effective-permissions',
          params: options && options.params,
          scope: options && options.scope,
          retries: 1
        });
      }
    }
  };
}

module.exports = {
  buildBasicAuthorization: buildBasicAuthorization,
  createIamSdkAdapter: createIamSdkAdapter,
  normalizeAudience: normalizeAudience,
  normalizeScope: normalizeScope
};
