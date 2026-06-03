'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const iamAdminClient = require('../../security/service/iam-admin-client');
const emailDeliveryService = require('./email_delivery');

function createResponse() {
    return {
        statusCode: 200,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(payload) {
            this.body = payload;
            return this;
        }
    };
}

const clientSnapshot = {
    requestAdmin: iamAdminClient.requestAdmin
};

test.afterEach(function () {
    iamAdminClient.requestAdmin = clientSnapshot.requestAdmin;
});

test('pay hub email delivery service scopes get requests to newSystem', async function () {
    let requestOptions = null;
    iamAdminClient.requestAdmin = async function (options) {
        requestOptions = options;
        return { number: 0, code: 20000, data: { appId: 'newSystem' } };
    };

    const response = createResponse();
    await emailDeliveryService.onGet({
        headers: {
            lang: 'en'
        }
    }, response);

    assert.equal(response.statusCode, 200);
    assert.deepEqual(requestOptions, {
        method: 'get',
        path: '/setting/email-delivery',
        headers: {
            lang: 'en'
        },
        params: {
            appId: 'newSystem'
        },
        data: undefined
    });
});

test('pay hub email delivery service scopes update payloads to newSystem', async function () {
    let requestOptions = null;
    iamAdminClient.requestAdmin = async function (options) {
        requestOptions = options;
        return { number: 0, code: 20000, data: options.data };
    };

    const response = createResponse();
    await emailDeliveryService.onUpdate({
        body: {
            appId: 'other-app',
            appName: 'NewSystem',
            smtp: {
                host: 'smtp.newSystem.example.test'
            }
        },
        headers: {
            lang: 'th'
        }
    }, response);

    assert.equal(response.statusCode, 200);
    assert.equal(requestOptions.method, 'put');
    assert.equal(requestOptions.path, '/setting/email-delivery');
    assert.equal(requestOptions.data.appId, 'newSystem');
    assert.equal(requestOptions.data.appName, 'NewSystem');
});

test('pay hub email delivery service propagates upstream error payloads', async function () {
    iamAdminClient.requestAdmin = async function () {
        const error = new Error('upstream_failed');
        error.response = {
            status: 403,
            data: { status: false, error: 'forbidden' }
        };
        throw error;
    };

    const response = createResponse();
    await emailDeliveryService.onUpdate({
        body: {
            appName: 'NewSystem'
        },
        headers: {}
    }, response);

    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.body, { status: false, error: 'forbidden' });
});
