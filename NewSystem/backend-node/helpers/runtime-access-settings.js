'use strict';

const mongoose = require('mongoose');
const RuntimeAccess = require('../server/Project/settings/controller/runtime_access');
const runtimeAccessMonitor = require('./runtime-access-monitor');

const DEFAULT_DEV_ORIGINS = [
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://localhost:8083',
    'http://127.0.0.1:8083',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:18080',
    'http://127.0.0.1:18080'
];
const CACHE_TTL_MS = 30 * 1000;

let boundApp = null;
let cache = {
    loadedAt: 0,
    loading: null,
    persisted: false,
    source: 'environment',
    doc: null,
    config: null
};

function isProduction() {
    return process.env.NODE_ENV === 'production';
}

function parseList(value) {
    if (Array.isArray(value)) {
        return value
            .map(function (item) { return String(item == null ? '' : item).trim(); })
            .filter(Boolean);
    }
    return String(value || '')
        .split(/[\n,]/)
        .map(function (item) { return item.trim(); })
        .filter(Boolean);
}

function uniqueList(items) {
    return Array.from(new Set(parseList(items)));
}

function getBaseServerOrigin() {
    const value = String(process.env.BASE_SERVER_URL || '').trim();
    if (!value) {
        return '';
    }
    try {
        return new URL(value).origin;
    } catch (err) {
        return '';
    }
}

function isLoopbackOrigin(origin) {
    if (!origin) return false;
    try {
        const parsed = new URL(String(origin));
        const hostname = String(parsed.hostname || '').toLowerCase();
        return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    } catch (err) {
        return false;
    }
}

function buildDefaultCorsOrigins() {
    const baseOrigin = getBaseServerOrigin();
    if (isProduction()) {
        return baseOrigin ? [baseOrigin] : [];
    }
    return uniqueList(
        baseOrigin
            ? DEFAULT_DEV_ORIGINS.concat([baseOrigin])
            : DEFAULT_DEV_ORIGINS.slice()
    );
}

function envDefaults() {
    const baseCors = buildDefaultCorsOrigins();
    return {
        key: 'default',
        trustProxy: isProduction(),
        rateLimitEnabled: isProduction(),
        corsAllowedOrigins: baseCors,
        socketCorsOrigins: baseCors.slice(),
        allowedIPs: []
    };
}

function cloneConfig(config) {
    return {
        key: config && config.key ? String(config.key) : 'default',
        trustProxy: !!(config && config.trustProxy),
        rateLimitEnabled: !(config && config.rateLimitEnabled === false),
        corsAllowedOrigins: uniqueList(config && config.corsAllowedOrigins),
        socketCorsOrigins: uniqueList(config && config.socketCorsOrigins),
        allowedIPs: uniqueList(config && config.allowedIPs)
    };
}

function resolveConfig(doc) {
    const fallback = envDefaults();
    if (!doc) {
        return fallback;
    }

    const corsAllowedOrigins = Array.isArray(doc.corsAllowedOrigins)
        ? uniqueList(doc.corsAllowedOrigins)
        : fallback.corsAllowedOrigins.slice();
    const socketCorsOrigins = Array.isArray(doc.socketCorsOrigins) && doc.socketCorsOrigins.length > 0
        ? uniqueList(doc.socketCorsOrigins)
        : corsAllowedOrigins.slice();

    return {
        key: doc.key || 'default',
        trustProxy: typeof doc.trustProxy === 'boolean' ? doc.trustProxy : fallback.trustProxy,
        rateLimitEnabled: typeof doc.rateLimitEnabled === 'boolean' ? doc.rateLimitEnabled : fallback.rateLimitEnabled,
        corsAllowedOrigins: corsAllowedOrigins,
        socketCorsOrigins: socketCorsOrigins,
        allowedIPs: Array.isArray(doc.allowedIPs) ? uniqueList(doc.allowedIPs) : fallback.allowedIPs.slice()
    };
}

function updateCache(doc, source) {
    cache = {
        loadedAt: Date.now(),
        loading: null,
        persisted: !!doc,
        source: source,
        doc: doc || null,
        config: cloneConfig(resolveConfig(doc))
    };
    applyExpressRuntime();
    return cache.config;
}

function applyExpressRuntime(app) {
    const target = app || boundApp;
    if (!target || typeof target.set !== 'function') {
        return;
    }
    const config = getResolvedConfig();
    target.set('trust proxy', !!config.trustProxy);
}

async function loadFromDatabase(force) {
    if (!force && cache.config && (Date.now() - cache.loadedAt) < CACHE_TTL_MS) {
        return cache.config;
    }

    if (cache.loading) {
        return cache.loading;
    }

    if (!mongoose.connection || mongoose.connection.readyState !== 1) {
        if (!cache.config) {
            updateCache(null, 'environment');
        }
        return cache.config;
    }

    cache.loading = RuntimeAccess.ensureDefaultRecord()
        .then(function (result) {
            const doc = result && result.doc ? result.doc : null;
            return updateCache(doc || null, doc ? 'database' : 'environment');
        })
        .catch(function () {
            return updateCache(null, 'environment');
        });

    return cache.loading;
}

function ensureFreshInBackground() {
    if (!cache.config) {
        updateCache(null, 'environment');
        return;
    }
    if ((Date.now() - cache.loadedAt) >= CACHE_TTL_MS && !cache.loading) {
        loadFromDatabase(false).catch(function () {});
    }
}

function getResolvedConfig() {
    if (!cache.config) {
        updateCache(null, 'environment');
    } else {
        ensureFreshInBackground();
    }
    return cloneConfig(cache.config);
}

function normalizeIp(ip) {
    return String(ip || '').replace('::ffff:', '').trim();
}

function isOriginAllowed(origin) {
    const config = getResolvedConfig();
    if (!origin) return true;
    if (!isProduction() && isLoopbackOrigin(origin)) return true;
    return config.corsAllowedOrigins.indexOf(String(origin)) !== -1;
}

function isSocketOriginAllowed(origin) {
    const config = getResolvedConfig();
    if (!origin) return true;
    if (!isProduction() && isLoopbackOrigin(origin)) return true;
    return config.socketCorsOrigins.indexOf(String(origin)) !== -1;
}

function isIpAllowed(ip) {
    const config = getResolvedConfig();
    if (!isProduction() || config.allowedIPs.length === 0) {
        return true;
    }
    return config.allowedIPs.indexOf(normalizeIp(ip)) !== -1;
}

async function getAdminPayload() {
    const resolved = getResolvedConfig();
    const defaults = envDefaults();
    return {
        _id: cache.doc && cache.doc._id ? String(cache.doc._id) : null,
        key: resolved.key || 'default',
        source: cache.source || 'environment',
        persisted: !!cache.persisted,
        trustProxy: resolved.trustProxy,
        rateLimitEnabled: resolved.rateLimitEnabled,
        corsAllowedOrigins: resolved.corsAllowedOrigins.slice(),
        socketCorsOrigins: resolved.socketCorsOrigins.slice(),
        allowedIPs: resolved.allowedIPs.slice(),
        defaults: {
            trustProxy: defaults.trustProxy,
            rateLimitEnabled: defaults.rateLimitEnabled,
            corsAllowedOrigins: defaults.corsAllowedOrigins.slice(),
            socketCorsOrigins: defaults.socketCorsOrigins.slice(),
            allowedIPs: defaults.allowedIPs.slice()
        },
        insights: await runtimeAccessMonitor.getAdminInsights(),
        create: cache.doc && cache.doc.create ? cache.doc.create : undefined,
        update: cache.doc && cache.doc.update ? cache.doc.update : undefined
    };
}

function bindExpressApp(app) {
    boundApp = app;
    applyExpressRuntime(app);
}

async function prime() {
    await loadFromDatabase(true);
    applyExpressRuntime();
    return getResolvedConfig();
}

module.exports = {
    parseList,
    uniqueList,
    envDefaults,
    bindExpressApp,
    prime,
    refresh: function () {
        return loadFromDatabase(true);
    },
    updateCacheFromDocument: function (doc) {
        return updateCache(doc || null, doc ? 'database' : 'environment');
    },
    getResolvedConfig,
    getAdminPayload,
    isOriginAllowed,
    isSocketOriginAllowed,
    isIpAllowed,
    normalizeIp,
    isRateLimitEnabled: function () {
        return getResolvedConfig().rateLimitEnabled;
    }
};
