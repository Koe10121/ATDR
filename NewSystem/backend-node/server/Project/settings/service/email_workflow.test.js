'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const iamAdminClient = require('../../security/service/iam-admin-client');
const emailWorkflowService = require('./email_workflow');

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

test('pay hub email workflow service scopes definition requests to newSystem', async function () {
    let requestOptions = null;
    iamAdminClient.requestAdmin = async function (options) {
        requestOptions = options;
        return { number: 0, code: 20000, data: [] };
    };

    const response = createResponse();
    await emailWorkflowService.onDefinitions({
        headers: {
            lang: 'en'
        }
    }, response);

    assert.equal(response.statusCode, 200);
    assert.deepEqual(requestOptions, {
        method: 'get',
        path: '/setting/email-workflows/definitions',
        headers: {
            lang: 'en'
        },
        params: {
            appId: 'newSystem'
        },
        data: undefined
    });
});

test('pay hub email workflow service scopes list requests to newSystem', async function () {
    let requestOptions = null;
    iamAdminClient.requestAdmin = async function (options) {
        requestOptions = options;
        return { number: 0, code: 20000, data: [] };
    };

    const response = createResponse();
    await emailWorkflowService.onQuerys({
        query: {
            eventKey: 'account.invite'
        },
        headers: {
            lang: 'en'
        }
    }, response);

    assert.equal(response.statusCode, 200);
    assert.deepEqual(requestOptions, {
        method: 'get',
        path: '/setting/email-workflows',
        headers: {
            lang: 'en'
        },
        params: {
            eventKey: 'account.invite',
            appId: 'newSystem'
        },
        data: undefined
    });
});

test('pay hub email workflow service scopes create payloads to newSystem', async function () {
    let requestOptions = null;
    iamAdminClient.requestAdmin = async function (options) {
        requestOptions = options;
        return { number: 0, code: 20000, data: options.data };
    };

    const response = createResponse();
    await emailWorkflowService.onCreate({
        body: {
            eventKey: 'account.invite',
            steps: [
                {
                    recipient: { mode: 'request', value: '' },
                    template: { subject: 'Invite {email}', text: 'Hello {fullName}', html: '<p>{fullName}</p>' }
                }
            ]
        },
        headers: {
            lang: 'th'
        }
    }, response);

    assert.equal(response.statusCode, 200);
    assert.equal(requestOptions.data.appId, 'newSystem');
    assert.equal(requestOptions.data.eventKey, 'account.invite');
});

test('pay hub email workflow service propagates upstream error payloads', async function () {
    iamAdminClient.requestAdmin = async function () {
        const error = new Error('upstream_failed');
        error.response = {
            status: 403,
            data: { status: false, error: 'unknown_placeholders' }
        };
        throw error;
    };

    const response = createResponse();
    await emailWorkflowService.onUpdate({
        body: {
            eventKey: 'account.invite'
        },
        headers: {}
    }, response);

    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.body, { status: false, error: 'unknown_placeholders' });
});
