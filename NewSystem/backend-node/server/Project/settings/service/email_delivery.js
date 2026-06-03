'use strict';

const iamAdminClient = require('../../security/service/iam-admin-client');

const APP_ID = 'newSystem';

function resolveLang(request) {
    return request && request.headers && request.headers.lang ? String(request.headers.lang) : 'th';
}

function buildRequestOptions(request, method, path, payload, params) {
    return {
        method: method,
        path: path,
        headers: {
            lang: resolveLang(request)
        },
        params: params || undefined,
        data: payload || undefined
    };
}

function normalizeProxyError(error, fallback) {
    if (error && error.payload && error.statusCode) {
        return {
            statusCode: error.statusCode,
            payload: error.payload
        };
    }
    if (error && error.response) {
        return {
            statusCode: error.response.status || 502,
            payload: error.response.data || { status: false, error: fallback }
        };
    }
    return {
        statusCode: 502,
        payload: { status: false, error: fallback }
    };
}

async function proxy(response, options, fallback) {
    try {
        const result = await iamAdminClient.requestAdmin(options);
        return response.status(200).json(result);
    } catch (error) {
        const normalized = normalizeProxyError(error, fallback);
        return response.status(normalized.statusCode).json(normalized.payload);
    }
}

exports.onGet = async function (request, response, next) {
    return proxy(
        response,
        buildRequestOptions(request, 'get', '/setting/email-delivery', null, { appId: APP_ID }),
        'iam_email_delivery_failed'
    );
};

exports.onUpdate = async function (request, response, next) {
    const payload = Object.assign({}, request && request.body ? request.body : {}, {
        appId: APP_ID
    });
    return proxy(
        response,
        buildRequestOptions(request, 'put', '/setting/email-delivery', payload, null),
        'iam_update_email_delivery_failed'
    );
};
