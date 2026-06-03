'use strict';

const http = require('http');
const { URL } = require('url');

function readJsonBody(request) {
  return new Promise(function (resolve) {
    let raw = '';

    request.on('data', function (chunk) {
      raw += chunk;
    });

    request.on('end', function () {
      if (!raw) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        resolve({});
      }
    });
  });
}

function writeJson(response, statusCode, payload) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(payload));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function pickLangValue(items) {
  if (!Array.isArray(items)) return '';

  const found = items.find(function (item) {
    return item && item.key === 'en' && item.value;
  }) || items.find(function (item) {
    return item && item.value;
  });

  return found ? String(found.value) : '';
}

function createMockIamServer() {
  const state = {
    tokenRequests: 0,
    counters: {
      app: 2,
      type: 3,
      menu: 4,
      group: 4,
      permission: 4,
      audit: 2,
      account: 3,
      assignment: 2,
      trusted: 2,
      session: 2
    },
    tokens: new Map(),
    serviceClients: [
      {
        clientId: 'sample-sdk',
        clientSecret: 'super-secret',
        clientName: 'Sample IAM SDK',
        partnerId: 'sample-team',
        tenant: 'iam-shared',
        allowedScopes: 'sample.read sample.write iam.security.read iam.security.write iam.audit.read iam.accounts.read',
        allowedAudiences: ['new-system-api'],
        metadata: {
          targetSystem: 'newSystem',
          ownerEmail: 'ops@example.com'
        }
      },
      {
        clientId: 'new-system-sdk',
        clientSecret: 'super-secret',
        clientName: 'NewSystem IAM SDK',
        partnerId: 'new-system-team',
        tenant: 'iam-shared',
        allowedScopes: 'new.system.registry.read new.system.registry.write new.system.report.read iam.security.read iam.security.write iam.audit.read iam.accounts.read',
        allowedAudiences: ['new-system-api'],
        metadata: {
          targetSystem: 'newSystem',
          ownerEmail: 'new-system.integration@example.com'
        }
      }
    ],
    apps: [
      {
        _id: 'app-1',
        application: {
          ApplicationId: 'sample-seed-client',
          AppId: 'SAMPLE',
          title: [{ key: 'en', value: 'Sample Seed Client' }],
          description: [{ key: 'en', value: 'Seed client' }],
          types: ['app']
        },
        environments: [
          {
            title: [{ key: 'en', value: 'prod' }],
            endpoint: 'https://api.sample.example.com',
            status: 'live',
            clientId: 'sample-seed-client',
            clientSecret: 'seed-secret-123',
            server: {
              type: 'container'
            }
          }
        ],
        status: 'active',
        metadata: {
          targetSystem: 'newSystem',
          systemCode: 'SAMPLE',
          ownerEmail: 'ops@example.com',
          partnerId: 'sample-team',
          tenant: 'iam-shared',
          allowedScopes: 'sample.read sample.write',
          allowedAudiences: 'new-system-api'
        }
      }
    ],
    types: [
      {
        _id: 'type-iam',
        title: [{ key: 'en', value: 'IAM Administration' }],
        description: [{ key: 'en', value: 'IAM controls' }],
        state: true
      },
      {
        _id: 'type-newSystem',
        title: [{ key: 'en', value: 'New System Administration' }],
        description: [{ key: 'en', value: 'NewSystem controls' }],
        state: true
      }
    ],
    menus: [
      {
        _id: 'menu-iam',
        title: [{ key: 'en', value: '/security/permission' }],
        description: [{ key: 'en', value: 'IAM permissions' }],
        path: '/security/permission',
        type: {
          _id: 'type-iam',
          title: [{ key: 'en', value: 'IAM Administration' }]
        },
        state: true
      },
      {
        _id: 'menu-accounts-directory',
        title: [{ key: 'en', value: '/accounts/directory' }],
        description: [{ key: 'en', value: 'NewSystem account directory' }],
        path: '/accounts/directory',
        type: {
          _id: 'type-newSystem',
          title: [{ key: 'en', value: 'New System Administration' }]
        },
        state: true
      },
      {
        _id: 'menu-accounts-lifecycle',
        title: [{ key: 'en', value: '/accounts/lifecycle' }],
        description: [{ key: 'en', value: 'NewSystem account lifecycle' }],
        path: '/accounts/lifecycle',
        type: {
          _id: 'type-newSystem',
          title: [{ key: 'en', value: 'New System Administration' }]
        },
        state: true
      }
    ],
    groups: [
      {
        _id: 'group-1',
        title: [{ key: 'en', value: 'IAM Governance' }],
        visibleType: {
          _id: 'type-iam',
          title: [{ key: 'en', value: 'IAM Administration' }]
        },
        state: true
      },
      {
        _id: 'group-2',
        title: [{ key: 'en', value: 'New System Admin' }],
        visibleType: {
          _id: 'type-newSystem',
          title: [{ key: 'en', value: 'New System Administration' }]
        },
        state: true
      },
      {
        _id: 'group-3',
        title: [{ key: 'en', value: 'NewSystem Operator' }],
        visibleType: {
          _id: 'type-newSystem',
          title: [{ key: 'en', value: 'New System Administration' }]
        },
        state: true
      }
    ],
    permissions: [
      {
        _id: 'perm-1',
        name: 'iam.security.write',
        group: { _id: 'group-1', name: 'IAM Governance' },
        menu: { _id: 'menu-iam', path: '/security/permission' },
        all: true,
        view: true,
        edit: true,
        delete: true,
        action: true,
        logs: true
      },
      {
        _id: 'perm-2',
        name: 'newSystem.accounts.manage',
        group: { _id: 'group-2', name: 'New System Admin' },
        menu: { _id: 'menu-accounts-directory', path: '/accounts/directory' },
        all: true,
        view: true,
        edit: true,
        delete: true,
        action: true,
        logs: true
      },
      {
        _id: 'perm-3',
        name: 'newSystem.lifecycle.manage',
        group: { _id: 'group-2', name: 'New System Admin' },
        menu: { _id: 'menu-accounts-lifecycle', path: '/accounts/lifecycle' },
        all: true,
        view: true,
        edit: true,
        delete: true,
        action: true,
        logs: true
      }
    ],
    assignments: [
      {
        _id: 'assign-1',
        subject: 'sample-team',
        permission: 'iam.security.write'
      }
    ],
    auditEvents: [
      {
        _id: 'audit-1',
        action: 'created',
        resourceId: 'app-1'
      }
    ],
    accounts: [
      {
        _id: 'acc-1',
        email: 'newSystem.ops@example.com',
        status: { key: 'ACTIVE' },
        securityGroups: [{ _id: 'group-2', title: [{ key: 'en', value: 'New System Admin' }] }],
        control: { device: [], trustedDevices: [] }
      },
      {
        _id: 'acc-2',
        email: 'ops@example.com',
        status: { key: 'ACTIVE' },
        securityGroups: [],
        control: { device: [], trustedDevices: [] }
      }
    ],
    permissionMatrix: {
      '/accounts/directory': { all: true, view: true, edit: true, delete: true, action: true, logs: true },
      '/accounts/lifecycle': { all: true, view: true, edit: true, delete: true, action: true, logs: true }
    },
    userSessions: new Map([
      ['user-token-1', {
        account: {
          _id: 'acc-1',
          email: 'newSystem.ops@example.com',
          status: { key: 'ACTIVE' },
          control: { device: [], trustedDevices: [] }
        },
        sessions: [
          {
            _id: 'session-1',
            current: true,
            deviceId: 'browser-1',
            clientId: 'new-system-sdk',
            audience: 'new-system-api',
            system: 'newSystem'
          }
        ],
        trustedDevices: [
          {
            _id: 'trusted-1',
            deviceId: 'browser-1',
            clientId: 'new-system-sdk',
            audience: 'new-system-api',
            system: 'newSystem'
          }
        ]
      }]
    ]),
    accountAssignments: [
      {
        _id: 'acct-assign-1',
        account: 'acc-1',
        group: { _id: 'group-2', name: 'New System Admin' },
        active: true,
        dataScope: 'org',
        scopeUnits: []
      }
    ]
  };

  let server;

  function nextId(type) {
    const current = state.counters[type] || 1;
    state.counters[type] = current + 1;
    return type + '-' + current;
  }

  function withStatus(payload) {
    if (payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'status')) {
      return payload;
    }

    return Object.assign({ status: true }, payload || {});
  }

  function findRegisteredClient(clientId) {
    for (const item of state.apps) {
      const environments = Array.isArray(item && item.environments) ? item.environments : [];
      const environment = environments.find(function (entry) {
        return entry && entry.clientId === clientId;
      });

      if (environment) {
        return {
          clientId: environment.clientId,
          clientSecret: environment.clientSecret,
          clientName: environment.title && environment.title[0] && environment.title[0].value
            ? environment.title[0].value
            : (item.application && item.application.title && item.application.title[0] && item.application.title[0].value) || environment.clientId,
          partnerId: item.metadata && item.metadata.partnerId,
          tenant: item.metadata && item.metadata.tenant,
          allowedScopes: item.metadata && item.metadata.allowedScopes,
          allowedAudiences: item.metadata && item.metadata.allowedAudiences,
          metadata: item.metadata || {}
        };
      }
    }

    return state.serviceClients.find(function (item) {
      return item.clientId === clientId;
    }) || null;
  }

  function buildToken(client, scope, audience) {
    const token = 'mock-token-' + state.tokenRequests;
    const normalizedScope = String(scope || client.allowedScopes || '').trim();
    const normalizedAudience = audience || (
      Array.isArray(client.allowedAudiences)
        ? client.allowedAudiences[0]
        : client.allowedAudiences
    ) || 'new-system-api';
    const payload = {
      active: true,
      access_token: token,
      token_type: 'Bearer',
      expires_in: 300,
      scope: normalizedScope,
      aud: normalizedAudience,
      client_id: client.clientId,
      client_name: client.clientName || client.clientId,
      partner_id: client.partnerId || 'new-system-team',
      tenant: client.tenant || 'iam-shared'
    };

    state.tokens.set(token, payload);
    return payload;
  }

  function requireBearer(request, response) {
    const authorization = String(request.headers.authorization || '');
    const token = authorization.replace(/^Bearer\s+/i, '').trim();
    const payload = state.tokens.get(token);

    if (!payload) {
      writeJson(response, 401, { error: 'invalid_token' });
      return null;
    }

    return payload;
  }

  function requireUserToken(request, response) {
    const token = String(request.headers['x-access-token'] || '').trim();
    const session = state.userSessions.get(token);

    if (!session) {
      writeJson(response, 401, { status: false, code: 40100, message: 'Unauthorized' });
      return null;
    }

    return {
      token: token,
      session: session
    };
  }

  function withClientContext(request, item) {
    return Object.assign({}, item || {}, {
      clientId: request.headers['x-client-id'] || null,
      audience: request.headers['x-audience'] || null,
      system: request.headers['x-system'] || null
    });
  }

  function matchesClientContext(request, item) {
    const clientId = request.headers['x-client-id'] || '';
    const audience = request.headers['x-audience'] || '';
    const system = request.headers['x-system'] || '';

    if (clientId && String(item && item.clientId || '') !== String(clientId)) return false;
    if (audience && String(item && item.audience || '') !== String(audience)) return false;
    if (system && String(item && item.system || '') !== String(system)) return false;

    return true;
  }

  function getTypeById(typeId) {
    return state.types.find(function (item) {
      return item && item._id === typeId;
    }) || null;
  }

  function getGroupById(groupId) {
    return state.groups.find(function (item) {
      return item && item._id === groupId;
    }) || null;
  }

  function getMenuById(menuId) {
    return state.menus.find(function (item) {
      return item && item._id === menuId;
    }) || null;
  }

  function getAssignmentAccountId(item) {
    const account = item && item.account ? item.account : null;
    if (account && typeof account === 'object') {
      return account._id ? String(account._id) : '';
    }
    return account ? String(account) : '';
  }

  function getAssignmentGroupId(item) {
    const group = item && item.group ? item.group : null;
    if (group && typeof group === 'object') {
      return group._id ? String(group._id) : '';
    }
    return group ? String(group) : '';
  }

  function buildGroupLabel(group) {
    if (!group || typeof group !== 'object') return '';
    return pickLangValue(group.title) || String(group.name || group.key || '');
  }

  function buildGroupOption(group) {
    return {
      _id: group && group._id ? group._id : null,
      label: buildGroupLabel(group),
      raw: clone(group)
    };
  }

  function normalizeAssignmentGroup(groupRef) {
    if (groupRef && typeof groupRef === 'object') {
      return groupRef;
    }

    const fromState = getGroupById(groupRef);
    if (fromState) {
      return {
        _id: fromState._id,
        name: buildGroupLabel(fromState),
        title: clone(fromState.title),
        visibleType: clone(fromState.visibleType)
      };
    }

    return groupRef ? { _id: String(groupRef), name: 'Group ' + String(groupRef) } : null;
  }

  function buildAccountEffectivePermissions(accountId) {
    const assignments = state.accountAssignments.filter(function (item) {
      return getAssignmentAccountId(item) === String(accountId) && item.active !== false;
    });
    const groupIds = new Set(assignments.map(getAssignmentGroupId).filter(Boolean));
    const permissionRows = state.permissions.filter(function (item) {
      const groupId = item && item.group && item.group._id ? String(item.group._id) : '';
      return groupId && groupIds.has(groupId);
    });
    const matrix = permissionRows.reduce(function (acc, item) {
      const path = item && item.menu && item.menu.path ? String(item.menu.path) : '';
      if (!path) return acc;
      if (!acc[path]) {
        acc[path] = { all: false, view: false, edit: false, delete: false, action: false, logs: false };
      }
      acc[path].all = acc[path].all || !!item.all;
      acc[path].view = acc[path].view || !!item.view;
      acc[path].edit = acc[path].edit || !!item.edit;
      acc[path].delete = acc[path].delete || !!item.delete;
      acc[path].action = acc[path].action || !!item.action;
      acc[path].logs = acc[path].logs || !!item.logs;
      return acc;
    }, {});

    return {
      accountId: accountId,
      groups: assignments.map(function (item) {
        const group = normalizeAssignmentGroup(item.group);
        return {
          assignmentId: item._id,
          scope: item.dataScope || 'org',
          active: item.active !== false,
          group: group,
          label: buildGroupLabel(group)
        };
      }),
      permissions: permissionRows.map(function (item) { return item.name; }),
      permissionRows: clone(permissionRows),
      matrix: matrix,
      effectivePermissions: Object.keys(matrix).sort().map(function (path) {
        return Object.assign({ path: path }, matrix[path]);
      })
    };
  }

  async function handler(request, response) {
    const requestUrl = new URL(request.url, 'http://127.0.0.1');
    const pathname = requestUrl.pathname;

    if (request.method === 'POST' && pathname === '/api/v1/b2b/token') {
      state.tokenRequests += 1;

      const body = await readJsonBody(request);
      const authorization = String(request.headers.authorization || '');
      const encoded = authorization.replace(/^Basic\s+/i, '').trim();
      const decoded = encoded ? Buffer.from(encoded, 'base64').toString('utf8') : '';
      const separatorIndex = decoded.indexOf(':');
      const basicClientId = separatorIndex >= 0 ? decoded.slice(0, separatorIndex) : '';
      const basicClientSecret = separatorIndex >= 0 ? decoded.slice(separatorIndex + 1) : '';
      const requestClientId = body.client_id || basicClientId || '';
      const requestClientSecret = body.client_secret || basicClientSecret || '';
      const client = findRegisteredClient(requestClientId);

      if (!client || String(client.clientSecret || '') !== String(requestClientSecret)) {
        writeJson(response, 401, { error: 'invalid_client' });
        return;
      }

      writeJson(response, 200, buildToken(client, body.scope, body.audience));
      return;
    }

    if (request.method === 'POST' && pathname === '/api/v1/b2b/introspect') {
      const body = await readJsonBody(request);
      writeJson(response, 200, state.tokens.get(body.token) || { active: false });
      return;
    }

    if (request.method === 'GET' && pathname === '/api/v1/b2b/clients/me') {
      const payload = requireBearer(request, response);
      if (!payload) return;

      writeJson(response, 200, {
        client_id: payload.client_id,
        client_name: payload.client_name,
        partner_id: payload.partner_id,
        tenant: payload.tenant,
        scope: payload.scope,
        audience: payload.aud,
        allowed_scopes: String(payload.scope || '').split(/\s+/).filter(Boolean),
        allowed_audiences: [payload.aud],
        metadata: {
          targetSystem: payload.client_id === 'sample-sdk' ? 'newSystem' : 'newSystem'
        }
      });
      return;
    }

    if (request.method === 'POST' && pathname === '/api/v1/signin') {
      const session = state.userSessions.get('user-token-1');
      if (session) {
        session.sessions = [
          withClientContext(request, {
            _id: nextId('session'),
            current: true,
            deviceId: 'browser-1',
            userAgent: request.headers['user-agent'] || 'mock-browser',
            lastIp: request.headers['x-forwarded-for'] || '127.0.0.1',
            dateTime: new Date().toISOString()
          })
        ];
      }

      writeJson(response, 200, {
        status: true,
        data: {
          xAccessToken: 'user-token-1',
          require2FA: false,
          trustedDeviceMatched: true
        }
      });
      return;
    }

    if (pathname.indexOf('/api/v1/auth/') === 0 || pathname === '/api/v1/auth/logout' || pathname === '/api/v1/auth/logout-all') {
      const auth = requireUserToken(request, response);
      if (!auth) return;

      if (request.method === 'GET' && pathname === '/api/v1/auth/me') {
        writeJson(response, 200, { status: true, data: auth.session.account });
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/auth/sessions') {
        writeJson(response, 200, {
          status: true,
          data: {
            sessions: auth.session.sessions.filter(function (item) {
              return matchesClientContext(request, item);
            })
          }
        });
        return;
      }

      if (request.method === 'DELETE' && /^\/api\/v1\/auth\/sessions\/[^/]+$/.test(pathname)) {
        const sessionId = pathname.split('/').pop();
        auth.session.sessions = auth.session.sessions.filter(function (item) {
          return item._id !== sessionId || !matchesClientContext(request, item);
        });
        writeJson(response, 200, {
          status: true,
          data: {
            revoked: true,
            sessions: auth.session.sessions.slice()
          }
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/auth/logout') {
        state.userSessions.delete(auth.token);
        writeJson(response, 200, { status: true, data: { loggedOut: true } });
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/auth/logout-all') {
        state.userSessions.delete(auth.token);
        writeJson(response, 200, { status: true, data: { loggedOutAll: true } });
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/auth/2fa/request') {
        writeJson(response, 200, { status: true, data: { requested: true } });
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/auth/2fa/verify') {
        writeJson(response, 200, { status: true, data: { verified: true } });
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/auth/trusted-devices') {
        writeJson(response, 200, {
          status: true,
          data: {
            trustedDevices: auth.session.trustedDevices.filter(function (item) {
              return matchesClientContext(request, item);
            })
          }
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/auth/trust-device') {
        auth.session.trustedDevices.push(withClientContext(request, {
          _id: nextId('trusted'),
          deviceId: 'browser-1',
          userAgent: request.headers['user-agent'] || 'mock-browser',
          lastIp: request.headers['x-forwarded-for'] || '127.0.0.1',
          trustedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 86400000).toISOString()
        }));
        writeJson(response, 200, { status: true, data: { trusted: true } });
        return;
      }

      if (request.method === 'DELETE' && /^\/api\/v1\/auth\/trusted-devices\/[^/]+$/.test(pathname)) {
        const trustedDeviceId = pathname.split('/').pop();
        auth.session.trustedDevices = auth.session.trustedDevices.filter(function (item) {
          return item._id !== trustedDeviceId || !matchesClientContext(request, item);
        });
        writeJson(response, 200, {
          status: true,
          data: {
            revoked: true,
            trustedDevices: auth.session.trustedDevices.slice()
          }
        });
        return;
      }
    }

    if (pathname.indexOf('/api/v1/accounts') === 0) {
      const auth = requireUserToken(request, response);
      if (!auth) return;

      if (request.method === 'GET' && pathname === '/api/v1/accounts') {
        writeJson(response, 200, { status: true, data: clone(state.accounts) });
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/accounts/group/options') {
        writeJson(response, 200, {
          status: true,
          data: {
            groups: state.groups.map(buildGroupOption)
          }
        });
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/accounts/status/options') {
        writeJson(response, 200, {
          status: true,
          data: {
            statuses: [{ key: 'ACTIVE' }, { key: 'PENDING' }, { key: 'SUSPENDED' }]
          }
        });
        return;
      }

      if (request.method === 'PUT' && /^\/api\/v1\/accounts\/[^/]+$/.test(pathname)) {
        const accountId = pathname.split('/').pop();
        const body = await readJsonBody(request);
        const index = state.accounts.findIndex(function (item) {
          return item && item._id === accountId;
        });

        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        state.accounts[index] = Object.assign({}, state.accounts[index], body);
        writeJson(response, 200, { status: true, data: clone(state.accounts[index]) });
        return;
      }

      if (request.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/sessions$/.test(pathname)) {
        writeJson(response, 200, {
          status: true,
          data: {
            sessions: auth.session.sessions.filter(function (item) {
              return matchesClientContext(request, item);
            })
          }
        });
        return;
      }

      if (request.method === 'DELETE' && /^\/api\/v1\/accounts\/[^/]+\/sessions\/[^/]+$/.test(pathname)) {
        const sessionId = pathname.split('/').pop();
        auth.session.sessions = auth.session.sessions.filter(function (item) {
          return item._id !== sessionId || !matchesClientContext(request, item);
        });
        writeJson(response, 200, {
          status: true,
          data: {
            revoked: true,
            sessions: auth.session.sessions.slice()
          }
        });
        return;
      }

      if (request.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/trusted-devices$/.test(pathname)) {
        writeJson(response, 200, {
          status: true,
          data: {
            trustedDevices: auth.session.trustedDevices.filter(function (item) {
              return matchesClientContext(request, item);
            })
          }
        });
        return;
      }

      if (request.method === 'DELETE' && /^\/api\/v1\/accounts\/[^/]+\/trusted-devices\/[^/]+$/.test(pathname)) {
        const trustedDeviceId = pathname.split('/').pop();
        auth.session.trustedDevices = auth.session.trustedDevices.filter(function (item) {
          return item._id !== trustedDeviceId || !matchesClientContext(request, item);
        });
        writeJson(response, 200, {
          status: true,
          data: {
            revoked: true,
            trustedDevices: auth.session.trustedDevices.slice()
          }
        });
        return;
      }

      if (request.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/lifecycle$/.test(pathname)) {
        writeJson(response, 200, {
          status: true,
          data: {
            accountId: pathname.split('/')[4],
            lifecycle: {}
          }
        });
        return;
      }

      if (request.method === 'PUT' && /^\/api\/v1\/accounts\/[^/]+\/lifecycle$/.test(pathname)) {
        writeJson(response, 200, { status: true, data: { updated: true } });
        return;
      }

      if (request.method === 'POST' && /^\/api\/v1\/accounts\/[^/]+\/provision$/.test(pathname)) {
        writeJson(response, 200, { status: true, data: { provisioned: true } });
        return;
      }

      if (request.method === 'POST' && /^\/api\/v1\/accounts\/[^/]+\/deprovision$/.test(pathname)) {
        writeJson(response, 200, { status: true, data: { deprovisioned: true } });
        return;
      }

      if (request.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/effective-permissions$/.test(pathname)) {
        const accountId = pathname.split('/')[4];
        writeJson(response, 200, withStatus({ data: buildAccountEffectivePermissions(accountId) }));
        return;
      }

      if (request.method === 'PUT' && /^\/api\/v1\/accounts\/[^/]+\/status$/.test(pathname)) {
        writeJson(response, 200, { status: true, data: { updated: true } });
        return;
      }
    }

    if (pathname.indexOf('/api/v1/b2b/admin/') === 0) {
      const payload = requireBearer(request, response);
      if (!payload) return;

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/apps') {
        writeJson(response, 200, withStatus({ data: clone(state.apps) }));
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/apps') {
        const body = await readJsonBody(request);
        const created = clone(body);
        created._id = nextId('app');
        created.environments = (created.environments || []).map(function (environment, index) {
          return Object.assign({}, environment, {
            clientSecret: environment.clientSecret || 'mock-secret-' + (index + 100)
          });
        });
        state.apps.push(created);
        state.auditEvents.unshift({
          _id: nextId('audit'),
          action: 'created',
          resourceId: created._id
        });
        writeJson(response, 201, withStatus({ data: clone(created) }));
        return;
      }

      if (request.method === 'PUT' && pathname === '/api/v1/b2b/admin/apps') {
        const body = await readJsonBody(request);
        const index = state.apps.findIndex(function (item) {
          return item && item._id === body._id;
        });

        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        state.apps[index] = clone(body);
        state.auditEvents.unshift({
          _id: nextId('audit'),
          action: 'updated',
          resourceId: body._id
        });
        writeJson(response, 200, withStatus({ data: clone(state.apps[index]) }));
        return;
      }

      if (request.method === 'POST' && /^\/api\/v1\/b2b\/admin\/apps\/[^/]+\/rotate-secret$/.test(pathname)) {
        const id = pathname.split('/')[6];
        const body = await readJsonBody(request);
        const app = state.apps.find(function (item) {
          return item && item._id === id;
        });

        if (!app) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        const environment = (app.environments || []).find(function (item) {
          return !body.environmentClientId || item.clientId === body.environmentClientId;
        }) || app.environments && app.environments[0];

        if (!environment) {
          writeJson(response, 404, { status: false, error: 'environment_not_found' });
          return;
        }

        environment.clientSecret = 'rotated-secret-456';
        state.auditEvents.unshift({
          _id: nextId('audit'),
          action: 'secret_rotated',
          resourceId: id
        });
        writeJson(response, 200, withStatus({
          data: {
            clientId: environment.clientId,
            clientSecret: environment.clientSecret
          }
        }));
        return;
      }

      if (request.method === 'DELETE' && /^\/api\/v1\/b2b\/admin\/apps\/[^/]+$/.test(pathname)) {
        const id = pathname.split('/')[6];
        const index = state.apps.findIndex(function (item) {
          return item && item._id === id;
        });

        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        const deleted = state.apps.splice(index, 1)[0];
        state.auditEvents.unshift({
          _id: nextId('audit'),
          action: 'deleted',
          resourceId: id
        });
        writeJson(response, 200, withStatus({ data: clone(deleted) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/type') {
        writeJson(response, 200, withStatus({ data: clone(state.types) }));
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/security/type') {
        const body = await readJsonBody(request);
        const created = Object.assign({}, body, { _id: nextId('type') });
        state.types.push(created);
        writeJson(response, 200, withStatus({ data: clone(created) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/menu') {
        writeJson(response, 200, withStatus({ data: clone(state.menus) }));
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/security/menu') {
        const body = await readJsonBody(request);
        const type = getTypeById(body.type);
        const created = Object.assign({}, body, {
          _id: nextId('menu'),
          type: type ? { _id: type._id, title: clone(type.title) } : body.type
        });
        state.menus.push(created);
        writeJson(response, 200, withStatus({ data: clone(created) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/group') {
        writeJson(response, 200, withStatus({ data: clone(state.groups) }));
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/security/group') {
        const body = await readJsonBody(request);
        const visibleType = getTypeById(body.visibleType);
        const created = Object.assign({}, body, {
          _id: nextId('group'),
          visibleType: visibleType ? { _id: visibleType._id, title: clone(visibleType.title) } : body.visibleType
        });
        state.groups.push(created);
        writeJson(response, 200, withStatus({ data: clone(created) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/permission') {
        writeJson(response, 200, withStatus({ data: clone(state.permissions) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/permission/my') {
        const accountId = String(requestUrl.searchParams.get('accountId') || '');
        const requestedPath = String(requestUrl.searchParams.get('path') || '').trim();
        const requestedAction = String(requestUrl.searchParams.get('action') || '').trim();
        const assignments = accountId
          ? state.accountAssignments.filter(function (item) {
            return getAssignmentAccountId(item) === accountId;
          })
          : state.assignments.slice();
        const groupIds = new Set(assignments.map(getAssignmentGroupId).filter(Boolean));
        const permissionRows = accountId
          ? state.permissions.filter(function (item) {
            const groupId = item && item.group && item.group._id ? String(item.group._id) : '';
            return !groupId || groupIds.has(groupId);
          })
          : state.permissions.slice();
        const matrix = clone(state.permissionMatrix || {});
        let allowed = true;

        if (requestedPath && requestedAction) {
          const rule = matrix[requestedPath] || {};
          allowed = !!(rule.all || rule[requestedAction]);
        }

        writeJson(response, 200, {
          status: true,
          data: {
            accountId: accountId,
            assignments: clone(assignments),
            permissions: clone(permissionRows),
            matrix: matrix,
            allowed: allowed
          }
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/security/permission') {
        const body = await readJsonBody(request);
        const created = Object.assign({}, body, {
          _id: nextId('permission'),
          group: normalizeAssignmentGroup(body.group),
          menu: getMenuById(body.menu) || body.menu
        });
        state.permissions.push(created);
        writeJson(response, 200, withStatus({ data: clone(created) }));
        return;
      }

      if (request.method === 'PUT' && pathname === '/api/v1/b2b/admin/security/permission') {
        const body = await readJsonBody(request);
        const index = state.permissions.findIndex(function (item) {
          return item && item._id === body._id;
        });

        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        state.permissions[index] = Object.assign({}, state.permissions[index], body, {
          group: body.group ? normalizeAssignmentGroup(body.group) : state.permissions[index].group,
          menu: body.menu ? (getMenuById(body.menu) || body.menu) : state.permissions[index].menu
        });
        writeJson(response, 200, withStatus({ data: clone(state.permissions[index]) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/assignment') {
        const accountId = String(requestUrl.searchParams.get('accountId') || '');
        const active = requestUrl.searchParams.get('active');

        if (!accountId && active == null) {
          writeJson(response, 200, withStatus({ data: clone(state.assignments) }));
          return;
        }

        let items = state.accountAssignments.slice();
        if (accountId) {
          items = items.filter(function (item) {
            return getAssignmentAccountId(item) === accountId;
          });
        }
        if (active === 'true') {
          items = items.filter(function (item) {
            return item.active !== false;
          });
        }
        if (active === 'false') {
          items = items.filter(function (item) {
            return item.active === false;
          });
        }

        writeJson(response, 200, withStatus({ data: clone(items) }));
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/security/assignment') {
        const body = await readJsonBody(request);
        const created = {
          _id: nextId('assignment'),
          account: body.account,
          group: normalizeAssignmentGroup(body.group),
          active: body.active !== false,
          dataScope: body.dataScope || 'org',
          scopeUnits: Array.isArray(body.scopeUnits) ? body.scopeUnits : []
        };
        state.accountAssignments.push(created);
        writeJson(response, 201, withStatus({ data: clone(created) }));
        return;
      }

      if (request.method === 'PUT' && pathname === '/api/v1/b2b/admin/security/assignment') {
        const body = await readJsonBody(request);
        const index = state.accountAssignments.findIndex(function (item) {
          return item && item._id === body._id;
        });

        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        state.accountAssignments[index] = Object.assign({}, state.accountAssignments[index], body, {
          group: body.group ? normalizeAssignmentGroup(body.group) : state.accountAssignments[index].group
        });
        writeJson(response, 200, withStatus({ data: clone(state.accountAssignments[index]) }));
        return;
      }

      if (request.method === 'DELETE' && pathname === '/api/v1/b2b/admin/security/assignment') {
        const body = await readJsonBody(request);
        state.accountAssignments = state.accountAssignments.filter(function (item) {
          return item._id !== body._id && item._id !== body.id;
        });
        writeJson(response, 200, withStatus({ data: { _id: body._id || body.id || null } }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/security/audit/events') {
        writeJson(response, 200, withStatus({ data: clone(state.auditEvents) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/accounts/lookup') {
        const email = String(requestUrl.searchParams.get('email') || '').trim().toLowerCase();
        const account = state.accounts.find(function (item) {
          return String(item && item.email || '').trim().toLowerCase() === email;
        }) || null;

        if (!account) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }

        writeJson(response, 200, withStatus({ data: clone(account) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/accounts') {
        writeJson(response, 200, withStatus({ data: clone(state.accounts) }));
        return;
      }

      if (request.method === 'POST' && pathname === '/api/v1/b2b/admin/accounts/invite') {
        const body = await readJsonBody(request);
        const email = String(body.email || '').trim().toLowerCase();

        if (!email) {
          writeJson(response, 400, { status: false, error: 'email_required' });
          return;
        }

        let account = state.accounts.find(function (item) {
          return String(item && item.email || '').trim().toLowerCase() === email;
        }) || null;
        const invited = !account;

        if (!account) {
          account = {
            _id: nextId('account'),
            code: 'INV-' + Date.now(),
            email: email,
            status: { key: 'PENDING' },
            securityGroups: [],
            userinfo: {
              firstName: body.firstName ? [{ key: 'en', value: String(body.firstName) }] : [],
              lastName: body.lastName ? [{ key: 'en', value: String(body.lastName) }] : []
            },
            control: { device: [], trustedDevices: [] }
          };
          state.accounts.push(account);
        }

        writeJson(response, invited ? 201 : 200, {
          status: true,
          data: {
            account: clone(account),
            invited: invited
          }
        });
        return;
      }

      if (request.method === 'PUT' && /^\/api\/v1\/b2b\/admin\/accounts\/[^/]+$/.test(pathname)) {
        const accountId = pathname.split('/').pop();
        const body = await readJsonBody(request);
        const index = state.accounts.findIndex(function (item) {
          return String(item && item._id) === accountId;
        });
        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }
        state.accounts[index] = Object.assign({}, state.accounts[index], body);
        writeJson(response, 200, withStatus({ data: clone(state.accounts[index]) }));
        return;
      }

      if (request.method === 'PUT' && /^\/api\/v1\/b2b\/admin\/accounts\/[^/]+\/status$/.test(pathname)) {
        const accountId = pathname.split('/')[6];
        const body = await readJsonBody(request);
        const index = state.accounts.findIndex(function (item) {
          return String(item && item._id) === accountId;
        });
        if (index === -1) {
          writeJson(response, 404, { status: false, error: 'not_found' });
          return;
        }
        const statusKey = body.toStatusKey || body.statusKey || body.status || 'ACTIVE';
        state.accounts[index] = Object.assign({}, state.accounts[index], {
          status: { key: String(statusKey) }
        });
        writeJson(response, 200, withStatus({ data: clone(state.accounts[index]) }));
        return;
      }

      if (request.method === 'GET' && /^\/api\/v1\/b2b\/admin\/accounts\/[^/]+\/effective-permissions$/.test(pathname)) {
        const accountId = pathname.split('/')[6];
        writeJson(response, 200, withStatus({ data: buildAccountEffectivePermissions(accountId) }));
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/accounts/group/options') {
        writeJson(response, 200, {
          status: true,
          data: {
            groups: state.groups.map(buildGroupOption)
          }
        });
        return;
      }

      if (request.method === 'GET' && pathname === '/api/v1/b2b/admin/accounts/status/options') {
        writeJson(response, 200, {
          status: true,
          data: {
            statuses: [{ key: 'ACTIVE' }, { key: 'PENDING' }, { key: 'SUSPENDED' }]
          }
        });
        return;
      }

      writeJson(response, 404, { error: 'not_found', path: pathname, client: payload.client_id });
      return;
    }

    writeJson(response, 404, { error: request.method + ' ' + pathname + ' not mocked' });
  }

  return {
    state: state,
    async start() {
      await new Promise(function (resolve) {
        server = http.createServer(function (request, response) {
          handler(request, response).catch(function (error) {
            writeJson(response, 500, { error: error.message });
          });
        });
        server.listen(0, '127.0.0.1', resolve);
      });

      const address = server.address();
      return {
        baseUrl: 'http://127.0.0.1:' + address.port
      };
    },
    async stop() {
      if (!server) return;
      await new Promise(function (resolve, reject) {
        server.close(function (error) {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      server = null;
    }
  };
}

module.exports = {
  createMockIamServer: createMockIamServer
};
