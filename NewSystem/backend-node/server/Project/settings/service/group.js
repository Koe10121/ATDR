'use strict';

var mongo = require('mongodb');
var Group = require('../controller/group');
const resMsg = require("../service/message");
const { attachAudit } = require('./request-actor');

exports.onQuery = async function (request, response, next) {
    try {
        var querys = {};
        const doc = await Group.onQuery(querys);
        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onQuerys = async function (request, response, next) {
    try {
        var querys = {};
        const doc = await Group.onQuerys(querys);
        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onCreate = async function (request, response, next) {
    try {
        const payload = await attachAudit(request, Object.assign({}, request.body || {}), 'create');
        const doc = await Group.onCreate(payload);
        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onUpdate = async function (request, response, next) {
    try {
        var query = {};
        query._id = new mongo.ObjectId(request.body._id);
        const payload = await attachAudit(request, Object.assign({}, request.body || {}), 'update');
        const doc = await Group.onUpdate(query, payload);
        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};

exports.onDelete = async function (request, response, next) {
    try {
        var query = {};
        query._id = new mongo.ObjectId(request.body.id);
        const doc = await Group.onDelete(query);
        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400);
        response.status(404).json(resData);
    }
};
