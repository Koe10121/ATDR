'use strict';

const mongo = require('mongodb');
const Permission = require('../controller/permission');
const AssignmentModel = require('../models/assignment.model');
const resMsg = require('../../settings/service/message');

function getBatchItems(body) {
    if (Array.isArray(body)) return body;
    if (body && Array.isArray(body.items)) return body.items;
    return [];
}

function normalizePermissionPath(path) {
    if (!path) return '';
    var normalized = String(path).trim();
    var queryIndex = normalized.indexOf('?');
    if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex);
    var hashIndex = normalized.indexOf('#');
    if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex);
    normalized = normalized.replace(/\/{2,}/g, '/');
    if (!normalized.startsWith('/')) normalized = '/' + normalized;
    if (normalized.length > 1 && normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}

function buildPermissionMatrix(permissions) {
    var map = {};
    for (var i = 0; i < permissions.length; i++) {
        var row = permissions[i] || {};
        var path = normalizePermissionPath(row.menu && row.menu.path ? row.menu.path : '');
        if (!path) continue;
        if (!map[path]) {
            map[path] = { all: false, view: false, edit: false, delete: false, action: false, logs: false };
        }
        map[path].all = map[path].all || !!row.all;
        map[path].view = map[path].view || !!row.view;
        map[path].edit = map[path].edit || !!row.edit;
        map[path].delete = map[path].delete || !!row.delete;
        map[path].action = map[path].action || !!row.action;
        map[path].logs = map[path].logs || !!row.logs;
    }
    return map;
}

function hasScopeAccess(assignments, accountId, targetAccountId, targetUnitId) {
    for (var i = 0; i < assignments.length; i++) {
        var assignment = assignments[i] || {};
        if (assignment.active === false) continue;
        var scope = assignment.dataScope || 'self';
        if (scope === 'org') return true;
        if (scope === 'self') {
            if (!targetAccountId || String(targetAccountId) === String(accountId)) return true;
        }
        if (scope === 'unit') {
            if (!targetUnitId) continue;
            var units = Array.isArray(assignment.scopeUnits) ? assignment.scopeUnits : [];
            for (var j = 0; j < units.length; j++) {
                var unit = units[j];
                var unitId = unit && unit._id ? unit._id : unit;
                if (String(unitId) === String(targetUnitId)) return true;
            }
        }
    }
    return false;
}

exports.onQuerys = async function (request, response, next) {
    try {
        var querys = {};
        const doc = await Permission.onQuerys(querys);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onCreate = async function (request, response, next) {
    try {
        const doc = await Permission.onCreate(request.body);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onUpdate = async function (request, response, next) {
    try {
        var query = {}
        query._id = new mongo.ObjectId(request.body._id);
        var payload = Object.assign({}, request.body);
        delete payload._id;

        const doc = await Permission.onUpdate(query, payload);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onDelete = async function (request, response, next) {
    try {
        var query = {};
        query._id = new mongo.ObjectId(request.body.id)
        const doc = await Permission.onDelete(query);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onCreateeBatch = async function (request, response, next) {
    try {
        var items = getBatchItems(request.body);
        var docs = [];

        for (var i = 0; i < items.length; i++) {
            docs.push(await Permission.onCreate(items[i]));
        }

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = docs
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onUpdateBatch = async function (request, response, next) {
    try {
        var items = getBatchItems(request.body);
        var docs = [];

        for (var i = 0; i < items.length; i++) {
            var query = {}
            query._id = new mongo.ObjectId(items[i]._id);
            var payload = Object.assign({}, items[i]);
            delete payload._id;
            docs.push(await Permission.onUpdate(query, payload));
        }

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = docs
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onMyPermissions = async function (request, response, next) {
    try {
        var body = request.body && typeof request.body === 'object' ? request.body : {};
        var rawAccountId = body.accounts || request.query.accountId || body.accountId;
        var accountId = rawAccountId && rawAccountId._id ? rawAccountId._id : rawAccountId;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var badRes = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(badRes);
        }

        var accountObjectId = new mongo.ObjectId(accountId);
        var assignments = await AssignmentModel.find({ account: accountObjectId, active: true })
            .populate({ path: 'group', select: 'title description visibleType' })
            .lean();

        var groupIds = assignments
            .map(function (item) { return item.group && item.group._id ? item.group._id : item.group; })
            .filter(Boolean);

        var permissionRows = [];
        if (groupIds.length > 0) {
            permissionRows = await Permission.onQuerys({ group: { $in: groupIds } });
        }

        var matrix = buildPermissionMatrix(permissionRows);

        var checkPath = request.query.path || body.path;
        var checkAction = request.query.action || body.action;
        var targetAccountId = request.query.targetAccountId || body.targetAccountId || null;
        var targetUnitId = request.query.targetUnitId || body.targetUnitId || null;

        var allowed = null;
        if (checkPath && checkAction) {
            var normalizedCheckPath = normalizePermissionPath(checkPath);
            var pathRule = matrix[normalizedCheckPath] || {};
            var hasMenuPermission = !!(pathRule.all || pathRule[checkAction]);
            var hasDataScope = hasScopeAccess(assignments, accountObjectId, targetAccountId, targetUnitId);
            allowed = hasMenuPermission && hasDataScope;
        }

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            accountId: accountObjectId,
            assignments: assignments,
            permissions: permissionRows,
            matrix: matrix,
            allowed: allowed
        };
        return response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400);
        return response.status(404).json(resData);
    }
};
