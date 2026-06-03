
const mongo = require("mongodb");
var infomation_messages = require('../controller/message')
var resMsg = require('./message');
const { attachAudit } = require('./request-actor');


exports.onQuery = async function (request, response, next) {
    try {

        var querys = {};
        const doc = await infomation_messages.onQuery(querys);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onQuerys = async function (request, response, next) {
    try {

        var querys = {};

        const doc = await infomation_messages.onQuerys(querys);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        console.log(err)
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.onCreate = async function (request, response, next) {
    try {
        const payload = await attachAudit(request, Object.assign({}, request.body || {}), 'create');
        const doc = await infomation_messages.onCreate(payload);

        var resData = await resMsg.onMessage_Response(20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(40400)
        response.status(404).json(resData);
    }
};

exports.onUpdate = async function (request, response, next) {
    try {

        var query = {}
        query._id = new mongo.ObjectId(request.body._id);

        const payload = await attachAudit(request, Object.assign({}, request.body || {}), 'update');
        const doc = await infomation_messages.onUpdate(query,payload);


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
        query._id = new mongo.ObjectId((request.body && (request.body.id || request.body._id)) || (request.query && request.query.id))
        const doc = await infomation_messages.onDelete(query);

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = doc
        response.status(200).json(resData);

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }

};



exports.onMessage_Response = async function (number, code, res) {
    try {

        var query = {};
        (number != null)? query.number = number : query.number = 0;
        (code != null)? query.code = code : null;

        var doc =  await infomation_messages.onQuery(query);
        delete doc._id;
        delete doc.create;
        delete doc.update;
        delete doc.__v;
        delete doc.number;
        delete doc.enable;

        return doc

    } catch (err) {
        return err
    }
};


// ================================
// Helper for unified response
// ================================
exports.sendResponse =  async function (response, numbers, code, data = null) {
    const httpCode = Number(String(code).substring(0, 3)); // เอา 3 หลักแรก
    const resData = await resMsg.onMessage_Response(numbers, code);
    if (data !== null) resData.data = data;
    return response.status(httpCode).json(resData);
}
