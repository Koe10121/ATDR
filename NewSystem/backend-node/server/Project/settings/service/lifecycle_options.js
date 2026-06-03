'use strict';

const resMsg = require("../service/message");
const { buildLifecycleOptions, loadLifecycleCatalog } = require('./lifecycle-master');

exports.onOptions = async function (request, response) {
    try {
        const catalog = await loadLifecycleCatalog();
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = buildLifecycleOptions(catalog);
        response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        response.status(500).json(resData);
    }
};
