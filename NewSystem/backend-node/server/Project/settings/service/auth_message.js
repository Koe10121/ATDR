'use strict';

const mongo = require("mongodb");
var AuthMessage = require('../controller/auth_message');
var resMsg = require('./message');
const { resolveActorObjectId } = require('./request-actor');

exports.onQuerys = async function (request, response, next) {
    try {
        var querys = {};
        const doc = await AuthMessage.onQuerys(querys);
        return resMsg.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return resMsg.sendResponse(response, 0, 40400);
    }
};

exports.onCreate = async function (request, response, next) {
    try {
        const payload = Object.assign({}, request.body || {});
        const accountId = resolveActorObjectId(request, payload);
        if (accountId) {
            payload.create = Object.assign({}, payload.create || {}, {
                by: accountId
            });
        }
        const doc = await AuthMessage.onCreate(payload);
        return resMsg.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return resMsg.sendResponse(response, 0, 40400);
    }
};

exports.onUpdate = async function (request, response, next) {
    try {
        const id = request.body && request.body._id ? String(request.body._id) : null;
        if (!id || !mongo.ObjectId.isValid(id)) {
            return resMsg.sendResponse(response, 0, 40400);
        }
        var query = { _id: new mongo.ObjectId(id) };
        const payload = Object.assign({}, request.body || {});
        const accountId = resolveActorObjectId(request, payload);
        payload.update = Object.assign({}, payload.update || {}, {
            by: accountId,
            datetime: new Date()
        });
        const doc = await AuthMessage.onUpdate(query, payload);
        return resMsg.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return resMsg.sendResponse(response, 0, 40400);
    }
};

exports.onDelete = async function (request, response, next) {
    try {
        const rawId = (request.body && (request.body.id || request.body._id)) || (request.query && request.query.id) || null;
        const id = rawId ? String(rawId) : null;
        if (!id || !mongo.ObjectId.isValid(id)) {
            return resMsg.sendResponse(response, 0, 40400);
        }
        const doc = await AuthMessage.onDelete({ _id: new mongo.ObjectId(id) });
        return resMsg.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return resMsg.sendResponse(response, 0, 40400);
    }
};
