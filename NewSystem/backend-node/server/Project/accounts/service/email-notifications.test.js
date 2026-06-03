'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const EmailNotifications = require('../../../../helpers/email-notifications');
const iamAdminClient = require('../../security/service/iam-admin-client');

const clientSnapshot = {
    requestAdmin: iamAdminClient.requestAdmin
};

test.afterEach(function () {
    iamAdminClient.requestAdmin = clientSnapshot.requestAdmin;
});

function withEnv(values, fn) {
    const previous = {};
    Object.keys(values).forEach(function (key) {
        previous[key] = process.env[key];
        if (values[key] === undefined) {
            delete process.env[key];
        } else {
            process.env[key] = values[key];
        }
    });
    try {
        fn();
    } finally {
        Object.keys(values).forEach(function (key) {
            if (previous[key] === undefined) {
                delete process.env[key];
            } else {
                process.env[key] = previous[key];
            }
        });
    }
}

test('email notification templates support env overrides and placeholders', function () {
    withEnv({
        PROJECT_MAIL_APP_NAME: 'NewSystem Test',
        PROJECT_APP_URL: 'https://newSystem.example.test',
        PROJECT_INVITE_EMAIL_SUBJECT: 'Invite {email} to {appName}',
        PROJECT_INVITE_EMAIL_TEXT: 'Hello {fullName} {appUrl}',
        PROJECT_INVITE_EMAIL_HTML: '<p>{fullName}</p><a href="{appUrl}">{email}</a>'
    }, function () {
        const template = EmailNotifications.buildTemplate('invite', {
            email: 'user@example.test',
            firstName: 'Jane',
            lastName: 'Doe'
        });

        assert.equal(template.subject, 'Invite user@example.test to NewSystem Test');
        assert.equal(template.text, 'Hello Jane Doe https://newSystem.example.test');
        assert.equal(template.html, '<p>Jane Doe</p><a href="https://newSystem.example.test">user@example.test</a>');
    });
});

test('email notification html rendering escapes placeholder values', function () {
    withEnv({
        PROJECT_2FA_EMAIL_HTML: '<p>{code}</p>'
    }, function () {
        const template = EmailNotifications.buildTemplate('twoFa', {
            code: '<123456>'
        });

        assert.equal(template.html, '<p>&lt;123456&gt;</p>');
    });
});

test('NewSystem email workflow dispatch calls IAM with newSystem app scope', async function () {
    let requestOptions = null;
    iamAdminClient.requestAdmin = async function (options) {
        requestOptions = options;
        return { status: true, data: { success: true } };
    };

    const result = await EmailNotifications.dispatchEmailWorkflow({
        eventKey: 'newSystem.expiring',
        to: 'customer@example.test',
        context: {
            newSystemNo: 'NewSystem-1'
        },
        request: {
            headers: {
                lang: 'en'
            }
        }
    });

    assert.deepEqual(result, { status: true, data: { success: true } });
    assert.deepEqual(requestOptions, {
        method: 'post',
        path: '/setting/email-workflows/dispatch',
        headers: {
            lang: 'en'
        },
        data: {
            appId: 'newSystem',
            eventKey: 'newSystem.expiring',
            legacyType: '',
            to: 'customer@example.test',
            context: {
                newSystemNo: 'NewSystem-1',
                appId: 'newSystem'
            }
        }
    });
});
