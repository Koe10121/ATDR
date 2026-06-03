'use strict';

const mongoose = require('mongoose');
const RuntimeAccessBlockedIp = require('../server/Project/settings/models/runtime_access_blocked_ip.model');
const RuntimeAccessEvent = require('../server/Project/settings/models/runtime_access_event.model');

const MAX_RECENT_EVENTS = 200;
const DEFAULT_EVENT_LIMIT = 100;

let sequence = 0;
const blockedIps = new Map();
const recentEvents = [];

function hasDatabase() {
    return !!(mongoose.connection && mongoose.connection.readyState === 1);
}

function normalizeIp(ip) {
    return String(ip || '').replace('::ffff:', '').trim();
}

function sanitizeText(value) {
    return String(value == null ? '' : value).trim();
}

function cloneDetail(detail) {
    if (!detail || typeof detail !== 'object') {
        return undefined;
    }
    try {
        return JSON.parse(JSON.stringify(detail));
    } catch (err) {
        return undefined;
    }
}

function pushEvent(event) {
    recentEvents.unshift(event);
    if (recentEvents.length > MAX_RECENT_EVENTS) {
        recentEvents.length = MAX_RECENT_EVENTS;
    }
    return event;
}

function cleanupBlockedIps() {
    const now = Date.now();
    blockedIps.forEach(function (record, ip) {
        if (!record || !record.expiresAt || record.expiresAt <= now || record.revokedAt) {
            blockedIps.delete(ip);
        }
    });
}

function toBlockedIpPayload(record) {
    if (!record) {
        return null;
    }
    return {
        ip: record.ip || '',
        reason: record.reason || 'rate-limit',
        source: record.source || 'runtime-access',
        blockedAt: new Date(record.blockedAt).toISOString(),
        expiresAt: new Date(record.expiresAt).toISOString(),
        remainingMs: Math.max(0, new Date(record.expiresAt).getTime() - Date.now()),
        method: record.method || '',
        path: record.path || '',
        origin: record.origin || '',
        message: record.message || '',
        revokedAt: record.revokedAt ? new Date(record.revokedAt).toISOString() : null
    };
}

function toEventPayload(event) {
    return {
        id: event.id || String(++sequence),
        occurredAt: event.occurredAt ? new Date(event.occurredAt).toISOString() : new Date().toISOString(),
        source: sanitizeText(event.source) || 'runtime-access',
        type: sanitizeText(event.type) || 'event',
        decision: sanitizeText(event.decision) || 'observe',
        ip: normalizeIp(event.ip),
        method: sanitizeText(event.method),
        path: sanitizeText(event.path),
        origin: sanitizeText(event.origin),
        statusCode: event.statusCode ? Number(event.statusCode) : null,
        message: sanitizeText(event.message),
        detail: cloneDetail(event.detail || event.details)
    };
}

function persistEventAsync(event) {
    if (!hasDatabase()) return;
    RuntimeAccessEvent.create({
        occurredAt: event.occurredAt,
        source: event.source,
        type: event.type,
        decision: event.decision,
        ip: event.ip,
        method: event.method,
        path: event.path,
        origin: event.origin,
        statusCode: event.statusCode,
        message: event.message,
        detail: event.detail || null
    }).catch(function () {});
}

function persistBlockedIpAsync(record) {
    if (!hasDatabase()) return;
    RuntimeAccessBlockedIp.findOneAndUpdate(
        { ip: record.ip },
        {
            $set: {
                source: record.source,
                reason: record.reason,
                method: record.method,
                path: record.path,
                origin: record.origin,
                message: record.message,
                blockedAt: record.blockedAt,
                expiresAt: record.expiresAt,
                revokedAt: null,
                revokedBy: null,
                revokeReason: ''
            }
        },
        { upsert: true, setDefaultsOnInsert: true, new: true }
    ).catch(function () {});
}

function recordEvent(payload) {
    const event = toEventPayload(Object.assign({}, payload || {}, {
        occurredAt: payload && payload.occurredAt ? payload.occurredAt : new Date().toISOString()
    }));
    pushEvent(event);
    persistEventAsync(event);
    return event;
}

function blockIp(ip, durationMs, meta) {
    const normalizedIp = normalizeIp(ip);
    const now = Date.now();
    const duration = Math.max(0, Number(durationMs) || 0);
    const expiresAt = now + duration;
    const record = {
        ip: normalizedIp,
        reason: sanitizeText(meta && meta.reason) || 'rate-limit',
        source: sanitizeText(meta && meta.source) || 'rate-limit',
        blockedAt: new Date(now),
        expiresAt: new Date(expiresAt),
        method: sanitizeText(meta && meta.method),
        path: sanitizeText(meta && meta.path),
        origin: sanitizeText(meta && meta.origin),
        message: sanitizeText(meta && meta.message),
        revokedAt: null
    };

    blockedIps.set(normalizedIp, record);
    persistBlockedIpAsync(record);

    recordEvent({
        source: record.source,
        type: 'ip-blocked',
        decision: 'blocked',
        ip: normalizedIp,
        method: record.method,
        path: record.path,
        origin: record.origin,
        statusCode: meta && meta.statusCode ? meta.statusCode : 429,
        message: record.message || 'IP temporarily blocked by rate limiting.',
        detail: {
            reason: record.reason,
            expiresAt: record.expiresAt.toISOString(),
            durationMs: duration
        }
    });

    return toBlockedIpPayload(record);
}

async function getBlockedIp(ip) {
    cleanupBlockedIps();
    const normalizedIp = normalizeIp(ip);
    const cached = blockedIps.get(normalizedIp);
    if (cached && cached.expiresAt && new Date(cached.expiresAt).getTime() > Date.now() && !cached.revokedAt) {
        return toBlockedIpPayload(cached);
    }

    if (!hasDatabase()) {
        return null;
    }

    const doc = await RuntimeAccessBlockedIp.findOne({
        ip: normalizedIp,
        revokedAt: null,
        expiresAt: { $gt: new Date() }
    }).lean();

    if (!doc) {
        blockedIps.delete(normalizedIp);
        return null;
    }

    blockedIps.set(normalizedIp, doc);
    return toBlockedIpPayload(doc);
}

async function unblockIp(ip, meta) {
    const normalizedIp = normalizeIp(ip);
    const now = new Date();
    blockedIps.delete(normalizedIp);

    if (!hasDatabase()) {
        recordEvent({
            source: 'runtime-access',
            type: 'ip-unblocked',
            decision: 'allowed',
            ip: normalizedIp,
            message: 'IP manually unblocked.'
        });
        return { ip: normalizedIp, unblocked: true };
    }

    const doc = await RuntimeAccessBlockedIp.findOneAndUpdate(
        { ip: normalizedIp },
        {
            $set: {
                revokedAt: now,
                revokedBy: meta && meta.actorId ? meta.actorId : null,
                revokeReason: sanitizeText(meta && meta.reason) || 'manual-unblock',
                expiresAt: now
            }
        },
        { new: true }
    ).lean();

    recordEvent({
        source: 'runtime-access',
        type: 'ip-unblocked',
        decision: 'allowed',
        ip: normalizedIp,
        method: meta && meta.method,
        path: meta && meta.path,
        origin: meta && meta.origin,
        statusCode: 200,
        message: 'IP manually unblocked.',
        detail: {
            reason: sanitizeText(meta && meta.reason) || 'manual-unblock'
        }
    });

    return {
        ip: normalizedIp,
        unblocked: true,
        blockedRecord: doc ? toBlockedIpPayload(doc) : null
    };
}

async function getActiveBlockedIps() {
    cleanupBlockedIps();
    if (!hasDatabase()) {
        return Array.from(blockedIps.values())
            .sort(function (a, b) { return new Date(b.blockedAt).getTime() - new Date(a.blockedAt).getTime(); })
            .map(toBlockedIpPayload);
    }

    const docs = await RuntimeAccessBlockedIp.find({
        revokedAt: null,
        expiresAt: { $gt: new Date() }
    }).sort({ blockedAt: -1 }).lean();

    docs.forEach(function (doc) {
        blockedIps.set(normalizeIp(doc.ip), doc);
    });

    return docs.map(toBlockedIpPayload);
}

async function getRecentEvents(limit) {
    const safeLimit = Math.min(MAX_RECENT_EVENTS, Math.max(1, Number(limit) || DEFAULT_EVENT_LIMIT));
    if (!hasDatabase()) {
        return recentEvents.slice(0, safeLimit).map(function (event) {
            return Object.assign({}, event, event.detail ? { detail: cloneDetail(event.detail) } : {});
        });
    }

    const docs = await RuntimeAccessEvent.find({})
        .sort({ occurredAt: -1, createdAt: -1 })
        .limit(safeLimit)
        .lean();

    return docs.map(toEventPayload);
}

async function getAdminInsights() {
    const activeBlockedIps = await getActiveBlockedIps();
    const recent = await getRecentEvents(DEFAULT_EVENT_LIMIT);
    return {
        generatedAt: new Date().toISOString(),
        activeBlockedIps: activeBlockedIps,
        recentEvents: recent,
        stats: {
            activeBlockedIpCount: activeBlockedIps.length,
            recentEventCount: recent.length
        }
    };
}

module.exports = {
    normalizeIp,
    recordEvent,
    blockIp,
    getBlockedIp,
    unblockIp,
    getActiveBlockedIps,
    getRecentEvents,
    getAdminInsights
};
