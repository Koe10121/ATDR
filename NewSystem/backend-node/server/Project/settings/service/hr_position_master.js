'use strict';

const Controller = require('../controller/hr_position_master');
const resMsg = require('./message');

exports.onQuerys = async function (request, response) {
    try {
        const docs = await Controller.onQuerys({}, undefined, '');
        const resData = await resMsg.onMessage_Response(0, 20000);
        resData.data = docs;
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0, 50000);
        return response.status(500).json(resData);
    }
};
