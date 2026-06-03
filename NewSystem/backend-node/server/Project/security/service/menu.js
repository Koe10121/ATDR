'use strict';

const mongo = require('mongodb');
const Menu = require('../controller/menu');
const resMsg = require('../../settings/service/message');

exports.onQuerys = async function (request, response, next) {
    try {
        var querys = {};
        const doc = await Menu.onQuerys(querys);

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
        const doc = await Menu.onCreate(request.body);

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

        const doc = await Menu.onUpdate(query, payload);

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
        const doc = await Menu.onDelete(query);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};
