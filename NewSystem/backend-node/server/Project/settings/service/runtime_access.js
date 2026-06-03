'use strict';

const mongo = require('mongodb');
const RuntimeAccess = require('../controller/runtime_access');
const Account = require('../../accounts/controller/account');
const resMsg = require('./message');
const runtimeAccessSettings = require('../../../../helpers/runtime-access-settings');
const runtimeAccessMonitor = require('../../../../helpers/runtime-access-monitor');
const { writeAudit } = require('../../../../helpers/audit.logger');

function toBoolean(value, fallback) {
    if (value === undefined || value === null || String(value).trim() === '') {
        return fallback;
    }
    return String(value).toLowerCase() === 'true';
}

function toPayload(body, currentDoc) {
    return {
        key: 'default',
        trustProxy: toBoolean(body && body.trustProxy, currentDoc ? currentDoc.trustProxy : runtimeAccessSettings.envDefaults().trustProxy),
        rateLimitEnabled: toBoolean(body && body.rateLimitEnabled, currentDoc ? currentDoc.rateLimitEnabled : runtimeAccessSettings.envDefaults().rateLimitEnabled),
        corsAllowedOrigins: runtimeAccessSettings.uniqueList(body && body.corsAllowedOrigins),
        socketCorsOrigins: runtimeAccessSettings.uniqueList(body && body.socketCorsOrigins),
        allowedIPs: runtimeAccessSettings.uniqueList(body && body.allowedIPs)
    };
}

function toAuditState(doc) {
    if (!doc) return null;
    return {
        key: doc.key || 'default',
        trustProxy: !!doc.trustProxy,
        rateLimitEnabled: !(doc.rateLimitEnabled === false),
        corsAllowedOrigins: runtimeAccessSettings.uniqueList(doc.corsAllowedOrigins),
        socketCorsOrigins: runtimeAccessSettings.uniqueList(doc.socketCorsOrigins),
        allowedIPs: runtimeAccessSettings.uniqueList(doc.allowedIPs)
    };
}

function diffAuditState(beforeState, afterState) {
    const fields = ['trustProxy', 'rateLimitEnabled', 'corsAllowedOrigins', 'socketCorsOrigins', 'allowedIPs'];
    return fields.filter(function (field) {
        return JSON.stringify(beforeState ? beforeState[field] : null) !== JSON.stringify(afterState ? afterState[field] : null);
    });
}

async function writeRuntimeAccessAudit(request, accountId, action, beforeDoc, afterDoc, detailOverride) {
    const beforeState = toAuditState(beforeDoc);
    const afterState = toAuditState(afterDoc);
    const changedFields = detailOverride && Array.isArray(detailOverride.changedFields)
        ? detailOverride.changedFields
        : diffAuditState(beforeState, afterState);

    if (action === 'update' && changedFields.length === 0 && !detailOverride) {
        return null;
    }

    return writeAudit({
        module: 'runtime-access',
        action: action,
        actorType: accountId ? 'account' : 'system',
        actorId: accountId ? String(accountId) : null,
        targetId: afterDoc && afterDoc._id ? String(afterDoc._id) : (detailOverride && detailOverride.targetId ? detailOverride.targetId : 'default'),
        resourceType: 'Setting_RuntimeAccess',
        resourceId: afterDoc && afterDoc._id ? String(afterDoc._id) : null,
        detail: detailOverride || {
            key: 'default',
            changedFields: changedFields,
            before: beforeState,
            after: afterState
        }
    }, request);
}

async function resolveAccountId(request) {
    const token = request && request.headers && request.headers['x-access-token'] ? String(request.headers['x-access-token']) : '';
    if (!token) return null;
    const account = await Account.onQuery({ 'control.device.xAccessToken': token });
    return account && account._id && mongo.ObjectId.isValid(String(account._id)) ? new mongo.ObjectId(account._id) : null;
}

function resolveIpFromRequest(request) {
    return runtimeAccessMonitor.normalizeIp(
        (request && request.body && request.body.ip) ||
        (request && request.query && request.query.ip) ||
        ''
    );
}

exports.onGet = async function (request, response) {
    try {
        await runtimeAccessSettings.refresh();
        return resMsg.sendResponse(response, 0, 20000, await runtimeAccessSettings.getAdminPayload());
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onUpdate = async function (request, response) {
    try {
        const accountId = await resolveAccountId(request);
        const seeded = await RuntimeAccess.ensureDefaultRecord(accountId);
        const current = seeded && seeded.doc ? seeded.doc : null;
        const payload = toPayload(request.body || {}, current);
        let doc = null;

        if (current && current._id) {
            payload.update = { by: accountId, datetime: new Date() };
            doc = await RuntimeAccess.onUpdate({ key: 'default' }, payload);
        } else {
            payload.create = { by: accountId, datetime: new Date() };
            doc = await RuntimeAccess.onCreate(payload);
        }

        await writeRuntimeAccessAudit(request, accountId, current && current._id ? 'update' : 'create', current, doc);
        runtimeAccessSettings.updateCacheFromDocument(doc);
        return resMsg.sendResponse(response, 0, 20000, await runtimeAccessSettings.getAdminPayload());
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onUnblockIp = async function (request, response) {
    try {
        const ip = resolveIpFromRequest(request);
        if (!ip) {
            return response.status(400).json({ message: 'IP is required.' });
        }

        const accountId = await resolveAccountId(request);
        const result = await runtimeAccessMonitor.unblockIp(ip, {
            actorId: accountId,
            reason: (request && request.body && request.body.reason) || 'manual-unblock',
            method: request.method,
            path: request.originalUrl || request.url,
            origin: request.headers && request.headers.origin
        });

        await writeRuntimeAccessAudit(request, accountId, 'unblock-ip', null, null, {
            ip: ip,
            targetId: ip,
            changedFields: ['blocked-ip'],
            action: 'unblock-ip',
            result: result
        });

        return resMsg.sendResponse(response, 0, 20000, await runtimeAccessSettings.getAdminPayload());
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};
