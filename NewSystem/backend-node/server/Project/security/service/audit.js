'use strict';

const AuditEvent = require('../models/audit_event.model');
const resMsg = require('../../settings/service/message');

exports.onQuerys = async function (request, response) {
    try {
        var query = {};
        if (request.query.module) query.module = String(request.query.module).trim();
        if (request.query.action) query.action = String(request.query.action).trim();
        if (request.query.actorId) query.actorId = String(request.query.actorId).trim();
        if (request.query.resourceId) query.resourceId = String(request.query.resourceId).trim();
        if (request.query.targetId) query.targetId = String(request.query.targetId).trim();

        var limit = Number(request.query.limit || 50);
        if (!Number.isFinite(limit) || limit <= 0) limit = 50;
        if (limit > 200) limit = 200;

        var docs = await AuditEvent.find(query)
            .sort({ createdAt: -1 })
            .limit(limit)
            .lean();

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = docs;
        return response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};
