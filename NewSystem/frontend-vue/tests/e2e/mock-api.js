'use strict';

const http = require('http');
const { URL } = require('url');

const port = Number(process.env.MOCK_API_PORT || 8082);

const securityTypes = [
  {
    _id: 'type-1',
    title: [{ key: 'en', value: 'New System Administration' }],
    description: [{ key: 'en', value: 'NewSystem security type' }],
    state: true
  }
];

const securityMenus = [
  {
    _id: 'menu-1',
    title: [{ key: 'en', value: 'Dashboard' }],
    description: [{ key: 'en', value: 'Dashboard menu' }],
    path: '/dashboard',
    type: { _id: 'type-1', title: [{ key: 'en', value: 'New System Administration' }] },
    source: 'managed',
    state: true
  },
  {
    _id: 'menu-2',
    title: [{ key: 'en', value: 'Account Directory' }],
    description: [{ key: 'en', value: 'Account directory menu' }],
    path: '/accounts/directory',
    type: { _id: 'type-1', title: [{ key: 'en', value: 'New System Administration' }] },
    source: 'managed',
    state: true
  },
  {
    _id: 'menu-3',
    title: [{ key: 'en', value: 'Business Operations' }],
    description: [{ key: 'en', value: 'Business operations dashboard' }],
    path: '/operations/business',
    type: { _id: 'type-1', title: [{ key: 'en', value: 'New System Administration' }] },
    source: 'managed',
    state: true
  }
];

const securityGroups = [
  {
    _id: 'group-1',
    title: [{ key: 'en', value: 'New System Admin' }],
    description: [{ key: 'en', value: 'NewSystem admin group' }],
    visibleType: { _id: 'type-1', title: [{ key: 'en', value: 'New System Administration' }] },
    state: true
  }
];

const securityPermissions = [
  {
    _id: 'perm-1',
    group: { _id: 'group-1', title: [{ key: 'en', value: 'New System Admin' }] },
    menu: { _id: 'menu-1', title: [{ key: 'en', value: 'Dashboard' }], path: '/dashboard', type: { _id: 'type-1', title: [{ key: 'en', value: 'New System Administration' }] } },
    all: true,
    view: true,
    edit: true,
    delete: true,
    action: true,
    logs: true
  }
];

const accountStatuses = [
  {
    key: 'ACTIVE',
    title: [{ key: 'en', value: 'Active' }]
  },
  {
    key: 'PENDING',
    title: [{ key: 'en', value: 'Pending' }]
  }
];

const accountGroups = [
  { _id: 'newSystem-group-admin', label: 'New System Admin' },
  { _id: 'newSystem-group-ops', label: 'New System Operations' }
];

const accounts = [
  {
    _id: 'newSystem-account-1',
    code: 'M-0001',
    email: 'owner.newSystem@example.com',
    status: { key: 'ACTIVE', title: [{ key: 'en', value: 'Active' }] },
    securityGroups: [{ _id: 'newSystem-group-admin', title: [{ key: 'en', value: 'New System Admin' }] }],
    userinfo: {
      prefix: [{ key: 'en', value: 'Mr.' }],
      firstName: [{ key: 'en', value: 'Saksith' }],
      lastName: [{ key: 'en', value: 'Rittanasatheiyn' }],
      image: '',
      msisdn: '0812345678'
    },
    control: {
      device: [{ dateTime: '2026-04-20T08:30:00.000Z' }]
    },
    lifecycle: {
      affiliations: [],
      provisioning: { state: 'PROVISIONED' }
    }
  }
];

let emailNotificationSettings = {
  enabled: true,
  appName: 'NewSystem',
  appUrl: 'https://newSystem.example.com',
  from: 'no-reply@newSystem.example.com',
  fromName: 'NewSystem',
  replyTo: 'support@newSystem.example.com',
  smtp: {
    host: 'smtp.newSystem.example.com',
    port: 587,
    secure: false,
    user: 'mailer@newSystem.example.com',
    hasPass: true
  },
  activeTemplates: ['invite', 'twoFa'],
  invite: {
    subject: 'You are invited to NewSystem',
    text: 'Welcome to NewSystem',
    html: '<p>Welcome to NewSystem</p>'
  },
  twoFa: {
    subject: 'Your NewSystem verification code',
    text: '123456',
    html: '<p>123456</p>'
  }
};

let emailDeliverySettings = {
  key: 'delivery:newSystem',
  appId: 'newSystem',
  enabled: true,
  appName: 'NewSystem',
  appUrl: 'https://newSystem.example.com',
  from: 'no-reply@newSystem.example.com',
  fromName: 'NewSystem',
  replyTo: 'support@newSystem.example.com',
  smtp: {
    host: 'smtp.newSystem.example.com',
    port: 587,
    secure: false,
    user: 'mailer@newSystem.example.com',
    hasPass: true
  }
};

let emailWorkflowDefinitions = [
  {
    eventKey: 'account.invite',
    legacyType: 'invite',
    title: 'Account invite',
    description: 'Account invitation',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'invited']
  },
  {
    eventKey: 'auth.2fa.request',
    legacyType: 'twoFa',
    title: 'Two-factor verification',
    description: 'Sign-in verification',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'code', 'expiresMinutes']
  },
  {
    eventKey: 'account.locked',
    legacyType: '',
    title: 'Account locked',
    description: 'Identity security notification for locked accounts.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription'],
    defaultTemplate: {
      subject: 'Your {appName} account has been locked',
      text: 'Hello {fullName}, your account is locked.',
      html: '<p>Hello {fullName}, your account is locked.</p>'
    }
  },
  {
    eventKey: 'account.unlocked',
    legacyType: '',
    title: 'Account unlocked',
    description: 'Identity security notification for restored account access.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription'],
    defaultTemplate: {
      subject: 'Your {appName} account access has been restored',
      text: 'Hello {fullName}, your account is active again.',
      html: '<p>Hello {fullName}, your account is active again.</p>'
    }
  },
  {
    eventKey: 'account.activated',
    legacyType: '',
    title: 'Account activated',
    description: 'Identity notification when account status changes to active outside unlock flow.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription', 'changedBy'],
    defaultTemplate: {
      subject: 'Your {appName} account has been activated',
      text: 'Hello {fullName}, your account has been activated.',
      html: '<p>Hello {fullName}, your account has been activated.</p>'
    }
  },
  {
    eventKey: 'account.deactivated',
    legacyType: '',
    title: 'Account deactivated',
    description: 'Identity notification when account status changes to inactive.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription', 'changedBy'],
    defaultTemplate: {
      subject: 'Your {appName} account has been deactivated',
      text: 'Hello {fullName}, your account has been deactivated.',
      html: '<p>Hello {fullName}, your account has been deactivated.</p>'
    }
  },
  {
    eventKey: 'account.suspended',
    legacyType: '',
    title: 'Account suspended',
    description: 'Identity notification when account status changes to suspended.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription', 'changedBy'],
    defaultTemplate: {
      subject: 'Your {appName} account has been suspended',
      text: 'Hello {fullName}, your account has been suspended.',
      html: '<p>Hello {fullName}, your account has been suspended.</p>'
    }
  },
  {
    eventKey: 'account.archived',
    legacyType: '',
    title: 'Account archived',
    description: 'Identity notification when account status changes to archived.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription', 'changedBy'],
    defaultTemplate: {
      subject: 'Your {appName} account has been archived',
      text: 'Hello {fullName}, your account has been archived.',
      html: '<p>Hello {fullName}, your account has been archived.</p>'
    }
  },
  {
    eventKey: 'account.status.changed',
    legacyType: '',
    title: 'Account status changed',
    description: 'Identity notification for account status transitions outside lock and unlock.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'fromStatus', 'toStatus', 'statusTitle', 'statusDescription', 'changedBy'],
    defaultTemplate: {
      subject: 'Your {appName} account status has changed',
      text: 'Hello {fullName}, your account status is now {statusTitle}.',
      html: '<p>Hello {fullName}, your account status is now {statusTitle}.</p>'
    }
  },
  {
    eventKey: 'account.access.changed',
    legacyType: '',
    title: 'Account access changed',
    description: 'Identity security notification when assigned security groups change.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'groupCount', 'currentGroups', 'addedGroups', 'removedGroups', 'changedBy'],
    defaultTemplate: {
      subject: 'Your {appName} access has changed',
      text: 'Hello {fullName}, your access groups are now {currentGroups}.',
      html: '<p>Hello {fullName}, your access groups are now {currentGroups}.</p>'
    }
  },
  {
    eventKey: 'account.provisioned',
    legacyType: '',
    title: 'Account provisioned',
    description: 'Identity lifecycle notification when account access is provisioned.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'targetStatus', 'provisioningState', 'provisioningStrategy', 'recommendedProfiles', 'matchedRuleCount', 'warningCount', 'triggeredBy'],
    defaultTemplate: {
      subject: 'Your {appName} access has been provisioned',
      text: 'Hello {fullName}, provisioning state is {provisioningState}.',
      html: '<p>Hello {fullName}, provisioning state is {provisioningState}.</p>'
    }
  },
  {
    eventKey: 'account.deprovisioned',
    legacyType: '',
    title: 'Account deprovisioned',
    description: 'Identity lifecycle notification when account access is deprovisioned.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'targetStatus', 'provisioningState', 'deprovisionReason', 'revokeSessions', 'clearTrustedDevices', 'warningCount', 'triggeredBy'],
    defaultTemplate: {
      subject: 'Your {appName} access has been deprovisioned',
      text: 'Hello {fullName}, deprovision reason is {deprovisionReason}.',
      html: '<p>Hello {fullName}, deprovision reason is {deprovisionReason}.</p>'
    }
  },
  {
    eventKey: 'auth.sessions.cleared',
    legacyType: '',
    title: 'All sessions cleared',
    description: 'Security notification when all active sessions are signed out.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'sessionCount', 'deviceIds', 'currentSessionIncluded', 'clearedBy'],
    defaultTemplate: {
      subject: 'All active {appName} sessions have been signed out',
      text: 'Hello {fullName}, {sessionCount} sessions were signed out.',
      html: '<p>Hello {fullName}, {sessionCount} sessions were signed out.</p>'
    }
  },
  {
    eventKey: 'auth.trusted-device.added',
    legacyType: '',
    title: 'Trusted device remembered',
    description: 'Security confirmation when a device is remembered for future sign-ins.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'deviceId', 'clientId', 'audience', 'system', 'userAgent', 'lastIp', 'trustedAt', 'expiresAt'],
    defaultTemplate: {
      subject: 'A device is now trusted for {appName}',
      text: 'Hello {fullName}, device {deviceId} is now trusted.',
      html: '<p>Hello {fullName}, device {deviceId} is now trusted.</p>'
    }
  },
  {
    eventKey: 'auth.session.revoked',
    legacyType: '',
    title: 'Session revoked',
    description: 'Security notification when an active session is revoked.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'sessionId', 'deviceId', 'clientId', 'audience', 'system', 'userAgent', 'lastIp', 'revokedBy'],
    defaultTemplate: {
      subject: 'A {appName} session has been revoked',
      text: 'Hello {fullName}, session {sessionId} was revoked.',
      html: '<p>Hello {fullName}, session {sessionId} was revoked.</p>'
    }
  },
  {
    eventKey: 'auth.trusted-device.revoked',
    legacyType: '',
    title: 'Trusted device revoked',
    description: 'Security notification when a remembered device is removed.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'deviceId', 'clientId', 'audience', 'system', 'userAgent', 'lastIp', 'trustedAt', 'expiresAt', 'revokedBy'],
    defaultTemplate: {
      subject: 'A trusted device was removed from {appName}',
      text: 'Hello {fullName}, trusted device {deviceId} was removed.',
      html: '<p>Hello {fullName}, trusted device {deviceId} was removed.</p>'
    }
  }
];

const newSystemEmailWorkflowDefinitions = [
  {
    eventKey: 'payment.created',
    legacyType: '',
    title: 'Payment created',
    description: 'NewSystem notification when a payment request is created.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'paymentId', 'orderId', 'amount', 'currency', 'customerName', 'merchantName', 'paymentMethod', 'paymentUrl', 'createdAt'],
    defaultTemplate: {
      subject: 'Payment request {paymentId} was created',
      text: 'Hello {fullName}, payment request {paymentId} was created.',
      html: '<p>Hello {fullName}, payment request <b>{paymentId}</b> was created.</p>'
    }
  },
  {
    eventKey: 'payment.paid',
    legacyType: '',
    title: 'Payment paid',
    description: 'NewSystem notification when a payment is successfully paid.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'paymentId', 'orderId', 'transactionId', 'amount', 'currency', 'customerName', 'merchantName', 'paymentMethod', 'paidAt'],
    defaultTemplate: {
      subject: 'Payment {paymentId} was paid',
      text: 'Hello {fullName}, payment {paymentId} was paid.',
      html: '<p>Hello {fullName}, payment <b>{paymentId}</b> was paid.</p>'
    }
  },
  {
    eventKey: 'payment.failed',
    legacyType: '',
    title: 'Payment failed',
    description: 'NewSystem notification when a payment attempt fails.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'paymentId', 'orderId', 'amount', 'currency', 'customerName', 'merchantName', 'paymentMethod', 'failureReason', 'failedAt'],
    defaultTemplate: {
      subject: 'Payment {paymentId} failed',
      text: 'Hello {fullName}, payment {paymentId} failed.',
      html: '<p>Hello {fullName}, payment <b>{paymentId}</b> failed.</p>'
    }
  },
  {
    eventKey: 'payment.refunded',
    legacyType: '',
    title: 'Payment refunded',
    description: 'NewSystem notification when a payment refund is completed.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'paymentId', 'orderId', 'refundId', 'refundAmount', 'amount', 'currency', 'customerName', 'merchantName', 'refundReason', 'refundedAt'],
    defaultTemplate: {
      subject: 'Refund completed for payment {paymentId}',
      text: 'Hello {fullName}, payment {paymentId} was refunded.',
      html: '<p>Hello {fullName}, payment <b>{paymentId}</b> was refunded.</p>'
    }
  },
  {
    eventKey: 'merchant.approved',
    legacyType: '',
    title: 'Merchant approved',
    description: 'NewSystem notification when a merchant is approved.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'merchantId', 'merchantName', 'merchantEmail', 'approvedAt', 'approvedBy', 'dashboardUrl'],
    defaultTemplate: {
      subject: 'Merchant {merchantName} was approved',
      text: 'Hello {fullName}, merchant {merchantName} was approved.',
      html: '<p>Hello {fullName}, merchant <b>{merchantName}</b> was approved.</p>'
    }
  },
  {
    eventKey: 'merchant.rejected',
    legacyType: '',
    title: 'Merchant rejected',
    description: 'NewSystem notification when a merchant request is rejected.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'merchantId', 'merchantName', 'merchantEmail', 'rejectionReason', 'rejectedAt', 'rejectedBy', 'dashboardUrl'],
    defaultTemplate: {
      subject: 'Merchant {merchantName} was rejected',
      text: 'Hello {fullName}, merchant {merchantName} was rejected.',
      html: '<p>Hello {fullName}, merchant <b>{merchantName}</b> was rejected.</p>'
    }
  },
  {
    eventKey: 'settlement.completed',
    legacyType: '',
    title: 'Settlement completed',
    description: 'NewSystem notification when a settlement is completed.',
    placeholders: ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName', 'settlementId', 'merchantId', 'merchantName', 'amount', 'currency', 'bankAccountLast4', 'settlementDate', 'completedAt'],
    defaultTemplate: {
      subject: 'Settlement {settlementId} was completed',
      text: 'Hello {fullName}, settlement {settlementId} was completed.',
      html: '<p>Hello {fullName}, settlement <b>{settlementId}</b> was completed.</p>'
    }
  }
];

const newSystemSharedWorkflowEventKeys = [
  'account.invite',
  'auth.2fa.request',
  'auth.sessions.cleared',
  'auth.trusted-device.added',
  'auth.session.revoked',
  'auth.trusted-device.revoked'
];

const commonEmailPlaceholders = ['appId', 'appName', 'appUrl', 'email', 'firstName', 'lastName', 'fullName'];

function normalizePlaceholderList(values) {
  const unique = new Set();
  (Array.isArray(values) ? values : []).forEach(item => {
    const normalized = String(item || '').trim();
    if (/^[a-zA-Z0-9_]+$/.test(normalized)) unique.add(normalized);
  });
  return Array.from(unique);
}

function customWorkflowDefinitionFromRecord(record, appId, knownEventKeys) {
  if (!(record && record.eventKey && record.appId === appId)) return null;
  if (knownEventKeys.has(record.eventKey)) return null;
  const step = Array.isArray(record.steps) && record.steps.length ? record.steps[0] : null;
  const template = step && step.template ? step.template : {};
  return {
    appIds: [appId],
    eventKey: record.eventKey,
    legacyType: '',
    title: record.title || record.eventKey,
    description: record.description || '',
    placeholders: normalizePlaceholderList(commonEmailPlaceholders.concat(record.placeholders || [])),
    defaultTemplate: {
      subject: String(template.subject || ''),
      text: String(template.text || ''),
      html: String(template.html || '')
    },
    custom: true
  };
}

function emailWorkflowDefinitionsForApp(appId) {
  const normalizedAppId = String(appId || '').trim() || 'iam';
  const definitions = normalizedAppId === 'newSystem'
    ? emailWorkflowDefinitions
      .filter(item => newSystemSharedWorkflowEventKeys.indexOf(item.eventKey) !== -1)
      .concat(newSystemEmailWorkflowDefinitions)
    : emailWorkflowDefinitions.slice();
  const knownEventKeys = new Set(definitions.map(item => item.eventKey));
  emailWorkflowRecords.forEach(record => {
    const custom = customWorkflowDefinitionFromRecord(record, normalizedAppId, knownEventKeys);
    if (!custom) return;
    definitions.push(custom);
    knownEventKeys.add(custom.eventKey);
  });
  return definitions;
}

let emailWorkflowRecords = [];

let runtimeAccessSettings = {
  _id: 'runtime-access-1',
  key: 'default',
  source: 'database',
  persisted: true,
  trustProxy: false,
  rateLimitEnabled: false,
  corsAllowedOrigins: ['http://localhost:8083'],
  socketCorsOrigins: ['http://localhost:8083'],
  allowedIPs: [],
  defaults: {
    trustProxy: false,
    rateLimitEnabled: false,
    corsAllowedOrigins: [
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'http://localhost:8083',
      'http://127.0.0.1:8083',
      'http://localhost:5173',
      'http://127.0.0.1:5173'
    ],
    socketCorsOrigins: [
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'http://localhost:8083',
      'http://127.0.0.1:8083',
      'http://localhost:5173',
      'http://127.0.0.1:5173'
    ],
    allowedIPs: []
  },
  insights: {
    generatedAt: new Date().toISOString(),
    activeBlockedIps: [
      {
        ip: '203.0.113.10',
        reason: 'rate-limit',
        source: 'runtime-access',
        blockedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
        expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        remainingMs: 10 * 60 * 1000,
        method: 'POST',
        path: '/api/v1/signin',
        origin: 'http://localhost:8083'
      }
    ],
    recentEvents: [
      {
        occurredAt: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
        source: 'runtime-access',
        type: 'ip-blocked',
        decision: 'blocked',
        ip: '203.0.113.10',
        method: 'POST',
        path: '/api/v1/signin',
        origin: 'http://localhost:8083',
        statusCode: 429,
        message: 'IP temporarily blocked by rate limiting.',
        detail: {
          reason: 'rate-limit'
        }
      }
    ],
    stats: {
      activeBlockedIpCount: 1,
      recentEventCount: 1
    }
  },
  create: {
    by: null,
    datetime: new Date().toISOString()
  },
  update: {
    by: null,
    datetime: new Date().toISOString()
  }
};

let databaseBackupSettings = {
  key: 'default',
  autoEnabled: false,
  intervalHours: 24,
  retentionCount: 10,
  backupDir: '/var/backups/newSystem',
  lastRunAt: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
  nextRunAt: null
};

let databaseBackupRuns = [
  {
    _id: 'backup-run-1',
    mode: 'auto',
    status: 'completed',
    databaseName: 'newSystem-e2e',
    filename: 'newSystem-newSystem-e2e-sample.json.gz',
    sizeBytes: 18432,
    checksum: 'e2e-checksum',
    collectionCount: 3,
    documentCount: 42,
    collections: [
      { name: 'users', count: 12 },
      { name: 'payments', count: 20 },
      { name: 'settings', count: 10 }
    ],
    error: '',
    startedAt: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
    completedAt: new Date(Date.now() - 12 * 60 * 60 * 1000 + 1500).toISOString(),
    downloadable: true
  }
];
const databaseBackupCollections = [
  { name: 'users', type: 'collection', documentCount: 12 },
  { name: 'payments', type: 'collection', documentCount: 24 },
  { name: 'settings', type: 'collection', documentCount: 10 },
  { name: 'logs', type: 'collection', documentCount: 9 }
];

function normalizeLines(value) {
  if (Array.isArray(value)) {
    return Array.from(new Set(value.map(item => String(item || '').trim()).filter(Boolean)));
  }
  return String(value || '')
    .split(/[\n,]/)
    .map(item => item.trim())
    .filter(Boolean)
    .filter((item, index, items) => items.indexOf(item) === index);
}

function refreshRuntimeAccessInsights() {
  const blocked = Array.isArray(runtimeAccessSettings.insights && runtimeAccessSettings.insights.activeBlockedIps)
    ? runtimeAccessSettings.insights.activeBlockedIps
    : [];
  const events = Array.isArray(runtimeAccessSettings.insights && runtimeAccessSettings.insights.recentEvents)
    ? runtimeAccessSettings.insights.recentEvents
    : [];
  runtimeAccessSettings.insights = Object.assign({}, runtimeAccessSettings.insights, {
    generatedAt: new Date().toISOString(),
    activeBlockedIps: blocked,
    recentEvents: events,
    stats: {
      activeBlockedIpCount: blocked.length,
      recentEventCount: events.length
    }
  });
}

function clampNumber(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function buildDatabaseBackupPayload(active) {
  return {
    settings: clone(databaseBackupSettings),
    runs: clone(databaseBackupRuns),
    active: !!active
  };
}

function buildBackupFilePreview(run) {
  const sourceRun = run || databaseBackupRuns[0] || {};
  const collections = Array.isArray(sourceRun.collections)
    ? sourceRun.collections.map(item => ({
      name: item.name || '',
      documentCount: Number(item.documentCount || item.count) || 0
    }))
    : databaseBackupCollections.map(item => ({
      name: item.name,
      documentCount: item.documentCount
    }));
  return {
    run: clone(sourceRun),
    metadata: {
      app: 'newSystem',
      databaseName: sourceRun.databaseName || 'newSystem-e2e',
      mode: sourceRun.mode || 'manual',
      createdAt: sourceRun.completedAt || sourceRun.startedAt || new Date().toISOString()
    },
    collectionCount: collections.length,
    documentCount: collections.reduce((total, item) => total + item.documentCount, 0),
    collections
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function findWorkflowIndex(appId, eventKey) {
  return emailWorkflowRecords.findIndex(item => item.appId === appId && item.eventKey === eventKey)
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        resolve({});
      }
    });
  });
}

function writeJson(res, statusCode, payload) {
  const origin = String(res.req && res.req.headers && res.req.headers.origin || '*');
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Access-Token, x-access-token, lang',
    'Vary': 'Origin'
  });
  res.end(JSON.stringify(payload));
}

function getBearerToken(req) {
  const authorization = String(req.headers.authorization || '');
  return authorization.replace(/^Bearer\s+/i, '').trim();
}

function getSessionToken(req) {
  return String(req.headers['x-access-token'] || getBearerToken(req) || '').trim();
}

function requireNewSystemAuth(req, res) {
  const token = getSessionToken(req);
  if (!token || token !== 'newSystem-e2e-token') {
    writeJson(res, 401, { status: false, code: 40100, message: 'Unauthorized' });
    return false;
  }
  return true;
}

function withAudit(payload) {
  return Object.assign({}, payload, {
    createdAt: payload && payload.createdAt ? payload.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdByName: 'newSystem.owner@example.com',
    updatedByName: 'newSystem.owner@example.com'
  });
}


const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    const origin = String(req.headers.origin || '*');
    res.writeHead(204, {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Access-Token, x-access-token, lang',
      'Vary': 'Origin'
    });
    res.end();
    return;
  }

  const requestUrl = new URL(req.url, `http://127.0.0.1:${port}`);
  const path = requestUrl.pathname;

  if (req.method === 'GET' && path === '/api/v1/auth/me') {
    if (!requireNewSystemAuth(req, res)) return;
    writeJson(res, 200, {
      data: {
        _id: 'acc-1',
        email: 'newSystem.owner@example.com',
        role: 'owner'
      }
    });
    return;
  }

  if (req.method === 'GET' && path === '/api/v1/security/permission/my') {
    if (!requireNewSystemAuth(req, res)) return;
    writeJson(res, 200, {
      data: {
        matrix: {
          '/security/permission': { all: true, edit: true, view: true },
          '/security/permissions/menu': { all: true, edit: true, view: true, delete: true, action: true, logs: true },
          '/security/permissions/group': { all: true, edit: true, view: true, delete: true, action: true, logs: true },
          '/security/permissions/matrix': { all: true, edit: true, view: true, delete: true, action: true, logs: true },
          '/operations/business': { all: true, edit: true, view: true, delete: true, action: true, logs: true },
          '/config/email-notifications': { all: true, edit: true, view: true, action: true, delete: true, logs: true },
          '/config/workflow-actions': { all: true, edit: true, view: true, action: true, delete: true, logs: true },
          '/config/runtime-access': { all: true, edit: true, view: true, action: true, delete: true, logs: true },
          '/config/database-backup': { all: true, edit: true, view: true, action: true, delete: true, logs: true },
          '/accounts/directory': { all: true, edit: true, view: true, action: true, delete: true }
        },
        assignments: [],
        permissions: []
      }
    });
    return;
  }

  if (path.indexOf('/api/v1/accounts') === 0) {
    if (!requireNewSystemAuth(req, res)) return;

    if (req.method === 'GET' && path === '/api/v1/accounts') {
      writeJson(res, 200, { data: accounts.slice() });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/accounts/status/options') {
      writeJson(res, 200, { data: { statuses: accountStatuses.slice() } });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/accounts/group/options') {
      writeJson(res, 200, { data: { groups: accountGroups.slice() } });
      return;
    }

    if (req.method === 'POST' && path === '/api/v1/accounts/invite') {
      readBody(req).then((body) => {
        const item = {
          _id: `newSystem-account-${Date.now()}`,
          code: `M-${String(accounts.length + 1).padStart(4, '0')}`,
          email: String(body && body.email || ''),
          status: { key: 'PENDING', title: [{ key: 'en', value: 'Pending' }] },
          securityGroups: accountGroups
            .filter(group => Array.isArray(body && body.groupIds) && body.groupIds.includes(group._id))
            .map(group => ({ _id: group._id, title: [{ key: 'en', value: group.label }] })),
          userinfo: {
            prefix: [],
            firstName: [{ key: 'en', value: String(body && body.firstName || '') }],
            lastName: [{ key: 'en', value: String(body && body.lastName || '') }],
            image: '',
            msisdn: ''
          },
          control: { device: [] },
          lifecycle: {
            affiliations: [],
            provisioning: { state: 'UNPROVISIONED' }
          }
        };
        accounts.unshift(item);
        writeJson(res, 200, { data: item });
      });
      return;
    }

    if (req.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/effective-permissions$/.test(path)) {
      writeJson(res, 200, { data: { groups: [], effectivePermissions: [] } });
      return;
    }

    if (req.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/sessions$/.test(path)) {
      writeJson(res, 200, { data: { sessions: [] } });
      return;
    }

    if (req.method === 'GET' && /^\/api\/v1\/accounts\/[^/]+\/trusted-devices$/.test(path)) {
      writeJson(res, 200, { data: { trustedDevices: [] } });
      return;
    }
  }

  if (path.indexOf('/api/v1/security/') === 0) {
    if (!requireNewSystemAuth(req, res)) return;

    if (req.method === 'GET' && path === '/api/v1/security/type') {
      writeJson(res, 200, { data: securityTypes.slice() });
      return;
    }
    if (req.method === 'POST' && path === '/api/v1/security/type') {
      readBody(req).then((body) => {
        const item = withAudit(Object.assign({
          _id: `type-${Date.now()}`,
          appId: 'newSystem',
          source: 'newSystem',
          description: [],
          state: true
        }, body || {}));
        securityTypes.push(item);
        writeJson(res, 200, { data: item });
      });
      return;
    }
    if (req.method === 'PUT' && path === '/api/v1/security/type') {
      readBody(req).then((body) => {
        const index = securityTypes.findIndex(item => item._id === body._id);
        if (index === -1) return writeJson(res, 404, { error: 'not_found' });
        securityTypes[index] = withAudit(Object.assign({}, securityTypes[index], body || {}));
        writeJson(res, 200, { data: securityTypes[index] });
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/security/menu') {
      writeJson(res, 200, { data: securityMenus.slice() });
      return;
    }
    if (req.method === 'POST' && path === '/api/v1/security/menu') {
      readBody(req).then((body) => {
        const type = securityTypes.find(item => item._id === body.type) || null;
        const item = withAudit(Object.assign({
          _id: `menu-${Date.now()}`,
          appId: 'newSystem',
          source: 'newSystem',
          state: true
        }, body || {}, {
          type: type ? { _id: type._id, title: type.title } : body.type
        }));
        securityMenus.push(item);
        writeJson(res, 200, { data: item });
      });
      return;
    }
    if (req.method === 'PUT' && path === '/api/v1/security/menu') {
      readBody(req).then((body) => {
        const index = securityMenus.findIndex(item => item._id === body._id);
        if (index === -1) return writeJson(res, 404, { error: 'not_found' });
        const type = securityTypes.find(item => item._id === body.type) || null;
        securityMenus[index] = withAudit(Object.assign({}, securityMenus[index], body || {}, {
          type: type ? { _id: type._id, title: type.title } : securityMenus[index].type
        }));
        writeJson(res, 200, { data: securityMenus[index] });
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/security/group') {
      writeJson(res, 200, { data: securityGroups.slice() });
      return;
    }
    if (req.method === 'POST' && path === '/api/v1/security/group') {
      readBody(req).then((body) => {
        const type = securityTypes.find(item => item._id === body.visibleType) || null;
        const item = withAudit(Object.assign({
          _id: `group-${Date.now()}`,
          state: true
        }, body || {}, {
          visibleType: type ? { _id: type._id, title: type.title } : body.visibleType
        }));
        securityGroups.push(item);
        writeJson(res, 200, { data: item });
      });
      return;
    }
    if (req.method === 'PUT' && path === '/api/v1/security/group') {
      readBody(req).then((body) => {
        const index = securityGroups.findIndex(item => item._id === body._id);
        if (index === -1) return writeJson(res, 404, { error: 'not_found' });
        const type = securityTypes.find(item => item._id === body.visibleType) || null;
        securityGroups[index] = withAudit(Object.assign({}, securityGroups[index], body || {}, {
          visibleType: type ? { _id: type._id, title: type.title } : securityGroups[index].visibleType
        }));
        writeJson(res, 200, { data: securityGroups[index] });
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/security/permission') {
      writeJson(res, 200, { data: securityPermissions.slice() });
      return;
    }
    if (req.method === 'POST' && path === '/api/v1/security/permission') {
      readBody(req).then((body) => {
        const group = securityGroups.find(item => item._id === body.group) || null;
        const menu = securityMenus.find(item => item._id === body.menu) || null;
        const item = withAudit(Object.assign({
          _id: `perm-${Date.now()}`,
          all: false,
          view: false,
          edit: false,
          delete: false,
          action: false,
          logs: false
        }, body || {}, {
          group: group ? { _id: group._id, title: group.title } : body.group,
          menu: menu ? { _id: menu._id, title: menu.title, path: menu.path, type: menu.type } : body.menu
        }));
        securityPermissions.push(item);
        writeJson(res, 200, { data: item });
      });
      return;
    }
    if (req.method === 'PUT' && path === '/api/v1/security/permission') {
      readBody(req).then((body) => {
        const index = securityPermissions.findIndex(item => item._id === body._id);
        if (index === -1) return writeJson(res, 404, { error: 'not_found' });
        const group = securityGroups.find(item => item._id === body.group) || null;
        const menu = securityMenus.find(item => item._id === body.menu) || null;
        securityPermissions[index] = withAudit(Object.assign({}, securityPermissions[index], body || {}, {
          group: group ? { _id: group._id, title: group.title } : securityPermissions[index].group,
          menu: menu ? { _id: menu._id, title: menu.title, path: menu.path, type: menu.type } : securityPermissions[index].menu
        }));
        writeJson(res, 200, { data: securityPermissions[index] });
      });
      return;
    }
  }


  if (path.indexOf('/api/v1/setting/') === 0) {
    if (!requireNewSystemAuth(req, res)) return;

    if (req.method === 'GET' && path === '/api/v1/setting/email-workflows/definitions') {
      writeJson(res, 200, { data: clone(emailWorkflowDefinitionsForApp(requestUrl.searchParams.get('appId'))) });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/setting/email-delivery') {
      writeJson(res, 200, { data: clone(emailDeliverySettings) });
      return;
    }

    if (req.method === 'PUT' && path === '/api/v1/setting/email-delivery') {
      readBody(req).then((body) => {
        const nextBody = body || {};
        emailDeliverySettings = Object.assign({}, emailDeliverySettings, nextBody, {
          appId: 'newSystem',
          smtp: Object.assign({}, emailDeliverySettings.smtp, nextBody.smtp || {})
        });
        if (emailDeliverySettings.smtp && emailDeliverySettings.smtp.pass) {
          delete emailDeliverySettings.smtp.pass;
          emailDeliverySettings.smtp.hasPass = true;
        }
        writeJson(res, 200, { data: clone(emailDeliverySettings) });
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/setting/email-workflows') {
      const appId = requestUrl.searchParams.get('appId') || '';
      const eventKey = requestUrl.searchParams.get('eventKey') || '';
      const items = emailWorkflowRecords.filter(item => {
        if (appId && item.appId !== appId) return false;
        if (eventKey && item.eventKey !== eventKey) return false;
        return true;
      });
      writeJson(res, 200, { data: clone(items) });
      return;
    }

    if (req.method === 'POST' && path === '/api/v1/setting/email-workflows') {
      readBody(req).then((body) => {
        const nextBody = clone(body || {});
        const definition = emailWorkflowDefinitionsForApp(nextBody.appId).find(item => item.eventKey === nextBody.eventKey) || null;
        const record = Object.assign({}, nextBody, {
          _id: `email-workflow-${Date.now()}`,
          version: 1,
          availablePlaceholders: definition ? definition.placeholders.slice() : normalizePlaceholderList(commonEmailPlaceholders.concat(nextBody.placeholders || [])),
          legacyType: definition && definition.legacyType ? definition.legacyType : '',
          systemEvent: !!(definition && !definition.custom)
        });
        const index = findWorkflowIndex(record.appId, record.eventKey);
        if (index !== -1) {
          emailWorkflowRecords[index] = withAudit(Object.assign({}, emailWorkflowRecords[index], record, {
            version: Number(emailWorkflowRecords[index].version || 0) + 1
          }));
          writeJson(res, 200, { data: clone(emailWorkflowRecords[index]) });
          return;
        }
        emailWorkflowRecords.push(withAudit(record));
        writeJson(res, 200, { data: clone(emailWorkflowRecords[emailWorkflowRecords.length - 1]) });
      });
      return;
    }

    if (req.method === 'PUT' && path === '/api/v1/setting/email-workflows') {
      readBody(req).then((body) => {
        const nextBody = clone(body || {});
        const index = findWorkflowIndex(nextBody.appId, nextBody.eventKey);
        if (index === -1) {
          writeJson(res, 404, { error: 'not_found' });
          return;
        }
        const definition = emailWorkflowDefinitionsForApp(nextBody.appId).find(item => item.eventKey === nextBody.eventKey) || null;
        emailWorkflowRecords[index] = withAudit(Object.assign({}, emailWorkflowRecords[index], nextBody, {
          version: Number(emailWorkflowRecords[index].version || 0) + 1,
          availablePlaceholders: definition ? definition.placeholders.slice() : normalizePlaceholderList(commonEmailPlaceholders.concat(nextBody.placeholders || [])),
          legacyType: definition && definition.legacyType ? definition.legacyType : '',
          systemEvent: !!(definition && !definition.custom)
        }));
        writeJson(res, 200, { data: clone(emailWorkflowRecords[index]) });
      });
      return;
    }

    if (req.method === 'DELETE' && path === '/api/v1/setting/email-workflows') {
      readBody(req).then((body) => {
        const nextBody = body || {};
        const index = findWorkflowIndex(nextBody.appId, nextBody.eventKey);
        if (index === -1) {
          writeJson(res, 200, { data: { acknowledged: true, deletedCount: 0 } });
          return;
        }
        emailWorkflowRecords.splice(index, 1);
        writeJson(res, 200, { data: { acknowledged: true, deletedCount: 1 } });
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/setting/email-notifications') {
      writeJson(res, 200, { data: emailNotificationSettings });
      return;
    }

    if (req.method === 'PUT' && path === '/api/v1/setting/email-notifications') {
      readBody(req).then((body) => {
        const nextBody = body || {};
        emailNotificationSettings = Object.assign({}, emailNotificationSettings, nextBody, {
          smtp: Object.assign({}, emailNotificationSettings.smtp, nextBody.smtp || {}),
          invite: Object.assign({}, emailNotificationSettings.invite, nextBody.invite || {}),
          twoFa: Object.assign({}, emailNotificationSettings.twoFa, nextBody.twoFa || {})
        });
        if (emailNotificationSettings.smtp && emailNotificationSettings.smtp.pass) {
          delete emailNotificationSettings.smtp.pass;
          emailNotificationSettings.smtp.hasPass = true;
        }
        writeJson(res, 200, { data: emailNotificationSettings });
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/setting/database-backup') {
      writeJson(res, 200, { data: buildDatabaseBackupPayload(false) });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/setting/database-backup/collections') {
      writeJson(res, 200, {
        data: {
          generatedAt: new Date().toISOString(),
          collectionCount: databaseBackupCollections.length,
          documentCount: databaseBackupCollections.reduce((total, item) => total + item.documentCount, 0),
          collections: clone(databaseBackupCollections)
        }
      });
      return;
    }

    if (req.method === 'PUT' && path === '/api/v1/setting/database-backup') {
      readBody(req).then((body) => {
        const nextBody = body || {};
        const intervalHours = clampNumber(nextBody.intervalHours, databaseBackupSettings.intervalHours, 1, 720);
        const autoEnabled = nextBody.autoEnabled === true;
        databaseBackupSettings = Object.assign({}, databaseBackupSettings, {
          autoEnabled,
          intervalHours,
          retentionCount: clampNumber(nextBody.retentionCount, databaseBackupSettings.retentionCount, 1, 100),
          nextRunAt: autoEnabled ? new Date(Date.now() + intervalHours * 60 * 60 * 1000).toISOString() : null
        });
        writeJson(res, 200, {
          data: {
            settings: clone(databaseBackupSettings),
            active: false
          }
        });
      });
      return;
    }

    if (req.method === 'POST' && path === '/api/v1/setting/database-backup/run') {
      const startedAt = new Date();
      const completedAt = new Date(startedAt.getTime() + 900);
      const run = {
        _id: `backup-run-${Date.now()}`,
        mode: 'manual',
        status: 'completed',
        databaseName: 'newSystem-e2e',
        filename: `newSystem-newSystem-e2e-${Date.now()}.json.gz`,
        sizeBytes: 20480,
        checksum: 'manual-e2e-checksum',
        collectionCount: 4,
        documentCount: 55,
        collections: [
          { name: 'users', count: 12 },
          { name: 'payments', count: 24 },
          { name: 'settings', count: 10 },
          { name: 'logs', count: 9 }
        ],
        error: '',
        startedAt: startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        downloadable: true
      };
      databaseBackupRuns.unshift(run);
      databaseBackupSettings = Object.assign({}, databaseBackupSettings, {
        lastRunAt: completedAt.toISOString(),
        nextRunAt: databaseBackupSettings.autoEnabled
          ? new Date(completedAt.getTime() + databaseBackupSettings.intervalHours * 60 * 60 * 1000).toISOString()
          : null
      });
      writeJson(res, 200, { data: buildDatabaseBackupPayload(false) });
      return;
    }

    if (req.method === 'GET' && /^\/api\/v1\/setting\/database-backup\/[^/]+\/download$/.test(path)) {
      const id = decodeURIComponent(path.split('/')[5] || '');
      const run = databaseBackupRuns.find(item => item._id === id);
      if (!run) {
        writeJson(res, 404, { error: 'backup_not_found' });
        return;
      }
      const origin = String(req.headers.origin || '*');
      res.writeHead(200, {
        'Content-Type': 'application/gzip',
        'Content-Disposition': `attachment; filename="${run.filename}"`,
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Access-Token, x-access-token, lang',
        'Vary': 'Origin'
      });
      res.end(Buffer.from('mock-database-backup'));
      return;
    }

    if (req.method === 'GET' && /^\/api\/v1\/setting\/database-backup\/[^/]+\/preview$/.test(path)) {
      const id = decodeURIComponent(path.split('/')[5] || '');
      const run = databaseBackupRuns.find(item => item._id === id);
      if (!run) {
        writeJson(res, 404, { error: 'backup_not_found' });
        return;
      }
      writeJson(res, 200, { data: buildBackupFilePreview(run) });
      return;
    }

    if (req.method === 'POST' && /^\/api\/v1\/setting\/database-backup\/[^/]+\/restore$/.test(path)) {
      const id = decodeURIComponent(path.split('/')[5] || '');
      const run = databaseBackupRuns.find(item => item._id === id);
      if (!run) {
        writeJson(res, 404, { error: 'backup_not_found' });
        return;
      }
      const preview = buildBackupFilePreview(run);
      writeJson(res, 200, {
        data: Object.assign({}, preview, {
          restoredAt: new Date().toISOString(),
          restoredCollections: preview.collectionCount,
          restoredDocuments: preview.documentCount
        })
      });
      return;
    }

    if (req.method === 'DELETE' && /^\/api\/v1\/setting\/database-backup\/[^/]+$/.test(path)) {
      const id = decodeURIComponent(path.split('/')[5] || '');
      databaseBackupRuns = databaseBackupRuns.filter(item => item._id !== id);
      writeJson(res, 200, { data: buildDatabaseBackupPayload(false) });
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/setting/runtime-access') {
      refreshRuntimeAccessInsights();
      writeJson(res, 200, { data: runtimeAccessSettings });
      return;
    }

    if (req.method === 'PUT' && path === '/api/v1/setting/runtime-access') {
      readBody(req).then((body) => {
        const nextBody = body || {};
        runtimeAccessSettings = Object.assign({}, runtimeAccessSettings, {
          trustProxy: nextBody.trustProxy === true,
          rateLimitEnabled: nextBody.rateLimitEnabled !== false,
          corsAllowedOrigins: normalizeLines(nextBody.corsAllowedOrigins),
          socketCorsOrigins: normalizeLines(nextBody.socketCorsOrigins),
          allowedIPs: normalizeLines(nextBody.allowedIPs),
          source: 'database',
          persisted: true,
          update: {
            by: null,
            datetime: new Date().toISOString()
          }
        });
        runtimeAccessSettings.insights.recentEvents.unshift({
          occurredAt: new Date().toISOString(),
          source: 'runtime-access',
          type: 'settings-updated',
          decision: 'allowed',
          ip: '127.0.0.1',
          method: 'PUT',
          path: '/api/v1/setting/runtime-access',
          origin: req.headers.origin || 'http://localhost:8083',
          statusCode: 200,
          message: 'Runtime access settings updated.',
          detail: {
            trustProxy: runtimeAccessSettings.trustProxy,
            rateLimitEnabled: runtimeAccessSettings.rateLimitEnabled
          }
        });
        runtimeAccessSettings.insights.recentEvents = runtimeAccessSettings.insights.recentEvents.slice(0, 20);
        refreshRuntimeAccessInsights();
        writeJson(res, 200, { data: runtimeAccessSettings });
      });
      return;
    }

    if (req.method === 'DELETE' && path === '/api/v1/setting/runtime-access/blocked-ip') {
      readBody(req).then((body) => {
        const ip = String(body && body.ip || '').trim();
        runtimeAccessSettings.insights.activeBlockedIps = (runtimeAccessSettings.insights.activeBlockedIps || []).filter(item => item.ip !== ip);
        runtimeAccessSettings.insights.recentEvents.unshift({
          occurredAt: new Date().toISOString(),
          source: 'runtime-access',
          type: 'ip-unblocked',
          decision: 'allowed',
          ip,
          method: 'DELETE',
          path: '/api/v1/setting/runtime-access/blocked-ip',
          origin: req.headers.origin || 'http://localhost:8083',
          statusCode: 200,
          message: 'IP manually unblocked.',
          detail: { reason: 'manual-unblock' }
        });
        runtimeAccessSettings.insights.recentEvents = runtimeAccessSettings.insights.recentEvents.slice(0, 20);
        refreshRuntimeAccessInsights();
        writeJson(res, 200, { data: runtimeAccessSettings });
      });
      return;
    }
  }

  writeJson(res, 404, { error: `No mock route for ${req.method} ${path}` });
});

server.listen(port, () => {
  process.stdout.write(`NewSystem mock API listening on http://127.0.0.1:${port}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
