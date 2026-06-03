'use strict';

const mongo = require('mongodb');
const Assignment = require('../controller/assignment');
const resMsg = require('../../settings/service/message');

function toObjectId(id) {
  if (!id || !mongo.ObjectId.isValid(id)) return null;
  return new mongo.ObjectId(id);
}

exports.onQuerys = async function (request, response) {
  try {
    var query = {};
    if (request.query.accountId) {
      const accountId = toObjectId(request.query.accountId);
      if (accountId) query.account = accountId;
    }
    if (request.query.groupId) {
      const groupId = toObjectId(request.query.groupId);
      if (groupId) query.group = groupId;
    }
    if (request.query.active === 'true') query.active = true;
    if (request.query.active === 'false') query.active = false;

    const doc = await Assignment.onQuerys(query);
    var resData = await resMsg.onMessage_Response(0,20000);
    resData.data = doc;
    return response.status(200).json(resData);
  } catch (err) {
    var resData = await resMsg.onMessage_Response(0,40400);
    return response.status(404).json(resData);
  }
};

exports.onCreate = async function (request, response) {
  try {
    const payload = Object.assign({}, request.body);
    payload.account = toObjectId(payload.account);
    payload.group = toObjectId(payload.group);
    payload.scopeUnits = Array.isArray(payload.scopeUnits)
      ? payload.scopeUnits.map(function (item) { return String(item); }).filter(Boolean)
      : [];

    if (!payload.account || !payload.group) {
      var badRes = await resMsg.onMessage_Response(0,40400);
      return response.status(404).json(badRes);
    }

    const doc = await Assignment.onCreate(payload);
    var resData = await resMsg.onMessage_Response(0,20000);
    resData.data = doc;
    return response.status(200).json(resData);
  } catch (err) {
    var resData = await resMsg.onMessage_Response(0,40400);
    return response.status(404).json(resData);
  }
};

exports.onUpdate = async function (request, response) {
  try {
    var query = { _id: new mongo.ObjectId(request.body._id) };
    const payload = Object.assign({}, request.body);
    delete payload._id;

    if (payload.account) payload.account = toObjectId(payload.account);
    if (payload.group) payload.group = toObjectId(payload.group);
    if (Array.isArray(payload.scopeUnits)) {
      payload.scopeUnits = payload.scopeUnits.map(function (item) { return String(item); }).filter(Boolean);
    }

    const doc = await Assignment.onUpdate(query, payload);
    var resData = await resMsg.onMessage_Response(0,20000);
    resData.data = doc;
    return response.status(200).json(resData);
  } catch (err) {
    var resData = await resMsg.onMessage_Response(0,40400);
    return response.status(404).json(resData);
  }
};

exports.onDelete = async function (request, response) {
  try {
    var query = { _id: new mongo.ObjectId(request.body.id || request.body._id) };
    const doc = await Assignment.onDelete(query);

    var resData = await resMsg.onMessage_Response(0,20000);
    resData.data = doc;
    return response.status(200).json(resData);
  } catch (err) {
    var resData = await resMsg.onMessage_Response(0,40400);
    return response.status(404).json(resData);
  }
};
