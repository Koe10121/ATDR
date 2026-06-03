'use strict';

const mongo = require('mongodb');
const resMsg = require('./message');
const HrIdentityController = require('../controller/hr_identity_master');

exports.onUpdate = async function (request, response) {
    try {
        const identityId = request.body && request.body.identityId ? String(request.body.identityId) : '';
        const accountId = request.body && request.body.accountId ? String(request.body.accountId) : '';
        if (!identityId) {
            return response.status(422).json({
                status: 422,
                message: 'missing_identity_id'
            });
        }

        const query = { _id: new mongo.ObjectId(identityId) };
        const payload = {
            linkedAccount: accountId ? new mongo.ObjectId(accountId) : null
        };
        const doc = await HrIdentityController.onUpdate(query, payload);
        const resData = await resMsg.onMessage_Response(0, 20000);
        resData.data = doc;
        return response.status(200).json(resData);
    } catch (err) {
        return response.status(500).json({
            status: 500,
            message: err && err.message ? err.message : 'hr_identity_link_failed'
        });
    }
};
