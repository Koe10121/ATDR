'use strict';

const Mailer = require('./google/Mail');
const EmailNotificationSettings = require('../server/Project/settings/service/email_notification');
const iamAdminClient = require('../server/Project/security/service/iam-admin-client');

const APP_ID = 'newSystem';

const DEFAULTS = {
    invite: {
        subject: 'You have been invited to {appName}',
        text: [
            'Hello {fullName},',
            '',
            'You have been invited to use {appName}.',
            'Sign in with this email: {email}',
            '{appUrl}',
            '',
            'If you did not expect this invitation, you can ignore this email.'
        ].join('\n'),
        html: [
            '<p>Hello {fullName},</p>',
            '<p>You have been invited to use <b>{appName}</b>.</p>',
            '<p>Sign in with this email: <b>{email}</b></p>',
            '<p><a href="{appUrl}">{appUrl}</a></p>',
            '<p>If you did not expect this invitation, you can ignore this email.</p>'
        ].join('')
    },
    twoFa: {
        subject: 'Your {appName} verification code',
        text: 'Your verification code is {code}. This code expires in {expiresMinutes} minutes.',
        html: '<p>Your verification code is <b>{code}</b>.</p><p>This code expires in {expiresMinutes} minutes.</p>'
    }
};

function getEnv(name, fallback) {
    const value = process.env[name];
    return value && String(value).trim() ? String(value) : fallback;
}

function cleanString(value) {
    return value == null ? '' : String(value).trim();
}

function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function render(template, context, html) {
    const data = Object.assign({}, context || {});
    return String(template || '').replace(/\{([a-zA-Z0-9_]+)\}/g, function (_, key) {
        const value = Object.prototype.hasOwnProperty.call(data, key) ? data[key] : '';
        return html ? escapeHtml(value) : String(value == null ? '' : value);
    });
}

function baseContext(context) {
    const firstName = context && context.firstName ? String(context.firstName).trim() : '';
    const lastName = context && context.lastName ? String(context.lastName).trim() : '';
    const fullName = context && context.fullName ? String(context.fullName).trim() : [firstName, lastName].filter(Boolean).join(' ');
    return Object.assign({
        appName: getEnv('PROJECT_MAIL_APP_NAME', getEnv('APP_NAME', 'NewSystem')),
        appUrl: getEnv('PROJECT_APP_URL', getEnv('BASE_SERVER_URL', '')),
        email: '',
        firstName: firstName,
        lastName: lastName,
        fullName: fullName || 'there',
        expiresMinutes: '5'
    }, context || {}, {
        firstName: firstName,
        lastName: lastName,
        fullName: fullName || 'there'
    });
}

function buildTemplate(type, context) {
    const defaults = DEFAULTS[type];
    const prefix = type === 'invite' ? 'PROJECT_INVITE_EMAIL' : 'PROJECT_2FA_EMAIL';
    const data = baseContext(context);
    return {
        subject: render(getEnv(prefix + '_SUBJECT', defaults.subject), data, false),
        text: render(getEnv(prefix + '_TEXT', defaults.text), data, false),
        html: render(getEnv(prefix + '_HTML', defaults.html), data, true)
    };
}

function resolveLang(options) {
    const request = options && options.request ? options.request : null;
    return request && request.headers && request.headers.lang ? String(request.headers.lang) : 'th';
}

async function dispatchEmailWorkflow(options) {
    const input = options || {};
    const eventKey = cleanString(input.eventKey);
    if (!eventKey) {
        const error = new Error('event_key_required');
        error.statusCode = 400;
        throw error;
    }

    return iamAdminClient.requestAdmin({
        method: 'post',
        path: '/setting/email-workflows/dispatch',
        headers: {
            lang: resolveLang(input)
        },
        data: {
            appId: APP_ID,
            eventKey: eventKey,
            legacyType: cleanString(input.legacyType),
            to: input.to || input.email || '',
            context: Object.assign({}, input.context || {}, {
                appId: APP_ID
            })
        }
    });
}

async function getConfig() {
    try {
        return await EmailNotificationSettings.getConfig();
    } catch (err) {
        return {};
    }
}

function smtpFromConfig(config) {
    const smtp = config && config.smtp ? config.smtp : {};
    return {
        host: cleanString(smtp.host),
        port: Number(smtp.port) || 587,
        secure: typeof smtp.secure === 'boolean' ? smtp.secure : Number(smtp.port || 587) === 465,
        user: cleanString(smtp.user),
        pass: cleanString(smtp.pass)
    };
}

function senderFromConfig(config) {
    const smtp = smtpFromConfig(config);
    return {
        from: cleanString(config && config.from) || smtp.user,
        fromName: cleanString(config && config.fromName) || cleanString(config && config.appName) || 'NewSystem',
        appName: cleanString(config && config.appName) || 'NewSystem'
    };
}

function buildTemplateFromConfig(type, context, config) {
    const defaults = DEFAULTS[type];
    const configContext = {};
    if (config && config.appName) configContext.appName = config.appName;
    if (config && config.appUrl) configContext.appUrl = config.appUrl;
    const data = baseContext(Object.assign(configContext, context || {}));
    const configTemplate = type === 'invite' ? (config && config.invite) : (config && config.twoFa);
    return {
        subject: render((configTemplate && configTemplate.subject) || defaults.subject, data, false),
        text: render((configTemplate && configTemplate.text) || defaults.text, data, false),
        html: render((configTemplate && configTemplate.html) || defaults.html, data, true)
    };
}

function isTemplateActive(config, type) {
    if (config && config.enabled === false) return false;
    if (!Array.isArray(config && config.activeTemplates)) return true;
    return config.activeTemplates.indexOf(type) !== -1;
}

exports.isMailConfigured = async function () {
    const config = await getConfig();
    if (config && config.enabled === false) return false;
    return Mailer.hasUsableCredentials(smtpFromConfig(config));
};

exports.sendInvite = async function (to, context) {
    const config = await getConfig();
    if (!isTemplateActive(config, 'invite')) return { success: true, skipped: true, reason: 'template_inactive' };
    const template = buildTemplateFromConfig('invite', Object.assign({}, context || {}, { email: to }), config);
    return Mailer.sendMail(to, template.subject, template.text, template.html, Object.assign(senderFromConfig(config), { smtp: smtpFromConfig(config) }));
};

exports.sendTwoFa = async function (to, context) {
    const config = await getConfig();
    if (!isTemplateActive(config, 'twoFa')) return { success: true, skipped: true, reason: 'template_inactive' };
    const template = buildTemplateFromConfig('twoFa', Object.assign({}, context || {}, { email: to }), config);
    return Mailer.sendMail(to, template.subject, template.text, template.html, Object.assign(senderFromConfig(config), { smtp: smtpFromConfig(config) }));
};

exports.buildTemplate = buildTemplate;
exports.dispatchEmailWorkflow = dispatchEmailWorkflow;
