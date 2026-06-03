'use strict';

const iamAdminClient = require('../../security/service/iam-admin-client');

const APP_ID = 'newSystem';

function resolveLang(request) {
    return request && request.headers && request.headers.lang ? String(request.headers.lang) : 'th';
}

function buildQuery(request) {
    return Object.assign(
        {},
        request && request.query ? request.query : {},
        request && request.body ? request.body : {}
    );
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

async function proxy(response, request, options, fallback) {
    try {
        const result = await iamAdminClient.requestAdmin(options);
        return response.status(200).json(result);
    } catch (error) {
        const normalized = normalizeProxyError(error, fallback);
        return response.status(normalized.statusCode).json(normalized.payload);
    }
}

exports.onDefinitions = async function (request, response, next) {
    return proxy(
        response,
        request,
        buildRequestOptions(request, 'get', '/setting/email-workflows/definitions', null, { appId: APP_ID }),
        'iam_email_workflow_definitions_failed'
    );
};

exports.onQuerys = async function (request, response, next) {
    const params = Object.assign({}, request && request.query ? request.query : {}, {
        appId: APP_ID
    });
    return proxy(
        response,
        request,
        buildRequestOptions(request, 'get', '/setting/email-workflows', null, params),
        'iam_email_workflows_failed'
    );
};

exports.onCreate = async function (request, response, next) {
    const payload = Object.assign({}, request && request.body ? request.body : {}, {
        appId: APP_ID
    });
    return proxy(
        response,
        request,
        buildRequestOptions(request, 'post', '/setting/email-workflows', payload, null),
        'iam_create_email_workflow_failed'
    );
};

exports.onUpdate = async function (request, response, next) {
    const payload = Object.assign({}, request && request.body ? request.body : {}, {
        appId: APP_ID
    });
    return proxy(
        response,
        request,
        buildRequestOptions(request, 'put', '/setting/email-workflows', payload, null),
        'iam_update_email_workflow_failed'
    );
};

exports.onDelete = async function (request, response, next) {
    const input = buildQuery(request);
    const payload = {
        appId: APP_ID
    };
    if (input.id) payload.id = input.id;
    if (input._id) payload._id = input._id;
    if (input.eventKey) payload.eventKey = input.eventKey;

    return proxy(
        response,
        request,
        buildRequestOptions(request, 'delete', '/setting/email-workflows', payload, null),
        'iam_delete_email_workflow_failed'
    );
};
