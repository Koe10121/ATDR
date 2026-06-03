'use strict';

const mongo = require('mongodb');
const Category = require('../controller/category');
const ResMessage = require('../../settings/service/message');

exports.onQuery = async function (request, response) {
    try {
        let query = {};

        const doc = await Category.onQuery(query);
        return ResMessage.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return ResMessage.sendResponse(response, 0, 40400);
    }
};

exports.onQuerys = async function (request, response) {
    try {
        let query = {};


        const doc = await Category.onQuerys(query);


        title.filter(function (item) { item.key === lang}).at(-1).value

        return ResMessage.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return ResMessage.sendResponse(response, 0, 40400);
    }
};

exports.onCreate = async function (request, response) {
    try {
        const doc = await Category.onCreate(request.body);
        return ResMessage.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return ResMessage.sendResponse(response, 0, 40400);
    }
};

exports.onUpdate = async function (request, response) {
    try {

        let query = {};
        query._id = new mongo.ObjectId(request.body._id);
        const payload = Object.assign({}, request.body);
        delete payload._id;

        const doc = await Category.onUpdate(query, payload);
        return ResMessage.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return ResMessage.sendResponse(response, 0, 40400);
    }
};

exports.onDelete = async function (request, response) {
    try {
        let query = {};
        query._id = new mongo.ObjectId(request.body._id);
        const doc = await Category.onDelete(query);
        return ResMessage.sendResponse(response, 0, 20000, doc);
    } catch (err) {
        return ResMessage.sendResponse(response, 0, 40400);
    }
};
