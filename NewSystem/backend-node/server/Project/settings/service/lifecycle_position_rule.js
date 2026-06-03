'use strict';

var mongo = require('mongodb');
const resMsg = require("../service/message");
const Controller = require('../controller/lifecycle_position_rule');
const { attachAudit, normalizeLangArray, normalizeStringArray } = require('./lifecycle_shared');
const { ensureLifecycleMasterData } = require('./lifecycle-master');

function toObjectIds(items) {
    return normalizeStringArray(items).filter(mongo.ObjectId.isValid).map(function (item) {
        return new mongo.ObjectId(item);
    });
}

exports.onQuerys = async function (request, response) {
    try {
        await ensureLifecycleMasterData();
        const docs = await Controller.onQuerys({});
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = docs;
        response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onCreate = async function (request, response) {
    try {
        const payload = await attachAudit(request, {
            key: String(request.body && request.body.key || '').trim().toUpperCase(),
            title: normalizeLangArray(request.body && request.body.title),
            description: normalizeLangArray(request.body && request.body.description),
            affiliationTypes: toObjectIds(request.body && request.body.affiliationTypes),
            matchType: String(request.body && request.body.matchType || 'CONTAINS').trim().toUpperCase(),
            matchValues: normalizeStringArray(request.body && request.body.matchValues),
            orgScope: String(request.body && request.body.orgScope || 'unit').trim().toLowerCase(),
            accessProfiles: toObjectIds(request.body && request.body.accessProfiles),
            priority: Number(request.body && request.body.priority || 100),
            source: request.body && request.body.source ? String(request.body.source) : 'MANUAL',
            version: Number(request.body && request.body.version || 1),
            isSystem: !!(request.body && request.body.isSystem),
            state: !(request.body && request.body.state === false)
        }, 'create');
        const doc = await Controller.onCreate(payload);
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onUpdate = async function (request, response) {
    try {
        const query = { _id: new mongo.ObjectId(request.body._id) };
        const payload = await attachAudit(request, {
            _id: request.body._id,
            key: String(request.body && request.body.key || '').trim().toUpperCase(),
            title: normalizeLangArray(request.body && request.body.title),
            description: normalizeLangArray(request.body && request.body.description),
            affiliationTypes: toObjectIds(request.body && request.body.affiliationTypes),
            matchType: String(request.body && request.body.matchType || 'CONTAINS').trim().toUpperCase(),
            matchValues: normalizeStringArray(request.body && request.body.matchValues),
            orgScope: String(request.body && request.body.orgScope || 'unit').trim().toLowerCase(),
            accessProfiles: toObjectIds(request.body && request.body.accessProfiles),
            priority: Number(request.body && request.body.priority || 100),
            source: request.body && request.body.source ? String(request.body.source) : 'MANUAL',
            version: Number(request.body && request.body.version || 1),
            isSystem: !!(request.body && request.body.isSystem),
            state: !(request.body && request.body.state === false)
        }, 'update');
        const doc = await Controller.onUpdate(query, payload);
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onDelete = async function (request, response) {
    try {
        const doc = await Controller.onDelete({ _id: new mongo.ObjectId(request.body.id) });
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};
