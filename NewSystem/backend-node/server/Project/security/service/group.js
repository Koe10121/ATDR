'use strict';

const mongo = require('mongodb');
const Group = require('../controller/group');
const resMsg = require('../../settings/service/message');

exports.onQuerys = async function (request, response, next) {
    try {
        var querys = {};
        const doc = await Group.onQuerys(querys);

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
        const doc = await Group.onCreate(request.body);

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

        const doc = await Group.onUpdate(query, payload);

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
        const doc = await Group.onDelete(query);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};
