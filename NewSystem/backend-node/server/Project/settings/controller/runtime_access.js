'use strict';

const mongoose = require('mongoose');
var objSchema = require('../models/runtime_access.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'create.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' },
    { path: 'update.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' }
];

const baseService = createBaseService(objSchema, defaultPopulate);
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

function toAccountObjectId(accountId) {
    if (!accountId || !mongoose.Types.ObjectId.isValid(String(accountId))) {
        return null;
    }
    return new mongoose.Types.ObjectId(String(accountId));
}

function buildSeedPayload(accountId) {
    const defaults = envDefaults();
    return {
        key: 'default',
        trustProxy: defaults.trustProxy,
        rateLimitEnabled: defaults.rateLimitEnabled,
        corsAllowedOrigins: defaults.corsAllowedOrigins.slice(),
        socketCorsOrigins: defaults.socketCorsOrigins.slice(),
        allowedIPs: defaults.allowedIPs.slice(),
        create: {
            by: toAccountObjectId(accountId),
            datetime: new Date()
        }
    };
}

async function ensureDefaultRecord(accountId) {
    const existing = await baseService.onQuery({ key: 'default' });
    if (existing) {
        return { doc: existing, created: false };
    }

    try {
        const created = await baseService.onCreate(buildSeedPayload(accountId));
        return { doc: created, created: true };
    } catch (err) {
        if (err && err.code === 11000) {
            const doc = await baseService.onQuery({ key: 'default' });
            if (doc) {
                return { doc: doc, created: false };
            }
        }
        throw err;
    }
}

module.exports = Object.assign({}, baseService, {
    envDefaults,
    ensureDefaultRecord
});
