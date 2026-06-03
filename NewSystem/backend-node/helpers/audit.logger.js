'use strict';

const AuditEvent = require('../server/Project/security/models/audit_event.model');

async function writeAudit(payload = {}, request = null) {
    try {
        if (!payload.module || !payload.action) return null;
        const body = Object.assign({}, payload);
        if (request) {
            if (!body.ip) body.ip = request.ip || null;
            if (!body.userAgent && typeof request.get === 'function') {
                body.userAgent = request.get('User-Agent') || null;
            }
        }
        const created = await AuditEvent.create(body);
        return created && typeof created.toObject === 'function'
            ? created.toObject()
            : body;
    } catch (err) {
        return null;
    }
}

module.exports = { writeAudit };
