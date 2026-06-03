'use strict';

const mongo = require('mongodb');
const EmailNotification = require('../controller/email_notification');
const resMsg = require('./message');

const DEFAULT_CONFIG = {
    key: 'default',
    enabled: true,
    activeTemplates: ['invite', 'twoFa'],
    appName: 'NewSystem',
    appUrl: '',
    from: '',
    fromName: 'NewSystem',
    smtp: {
        host: '',
        port: 587,
        secure: false,
        user: '',
        pass: ''
    },
    invite: {
        subject: 'You have been invited to {appName}',
        text: 'Hello {fullName},\n\nYou have been invited to use {appName}.\nSign in with this email: {email}\n{appUrl}',
        html: '<p>Hello {fullName},</p><p>You have been invited to use <b>{appName}</b>.</p><p>Sign in with this email: <b>{email}</b></p><p><a href="{appUrl}">{appUrl}</a></p>'
    },
    twoFa: {
        subject: 'Your {appName} verification code',
        text: 'Your verification code is {code}. This code expires in {expiresMinutes} minutes.',
        html: '<p>Your verification code is <b>{code}</b>.</p><p>This code expires in {expiresMinutes} minutes.</p>'
    }
};

function cleanString(value) {
    return value == null ? '' : String(value);
}

function normalizeActiveTemplates(doc) {
    const allowed = ['invite', 'twoFa'];
    if (Array.isArray(doc && doc.activeTemplates)) {
        return doc.activeTemplates.map(cleanString).filter(function (item) {
            return allowed.indexOf(item) !== -1;
        });
    }
    return doc && doc.enabled === false ? [] : allowed.slice();
}

function mergeConfig(doc) {
    return {
        key: cleanString(doc && doc.key) || DEFAULT_CONFIG.key,
        enabled: !(doc && doc.enabled === false),
        activeTemplates: normalizeActiveTemplates(doc || DEFAULT_CONFIG),
        appName: cleanString(doc && doc.appName) || DEFAULT_CONFIG.appName,
        appUrl: cleanString(doc && doc.appUrl),
        from: cleanString(doc && doc.from),
        fromName: cleanString(doc && doc.fromName) || DEFAULT_CONFIG.fromName,
        smtp: {
            host: cleanString(doc && doc.smtp && doc.smtp.host),
            port: Number(doc && doc.smtp && doc.smtp.port) || DEFAULT_CONFIG.smtp.port,
            secure: !!(doc && doc.smtp && doc.smtp.secure),
            user: cleanString(doc && doc.smtp && doc.smtp.user),
            pass: cleanString(doc && doc.smtp && doc.smtp.pass)
        },
        invite: {
            subject: cleanString(doc && doc.invite && doc.invite.subject) || DEFAULT_CONFIG.invite.subject,
            text: cleanString(doc && doc.invite && doc.invite.text) || DEFAULT_CONFIG.invite.text,
            html: cleanString(doc && doc.invite && doc.invite.html) || DEFAULT_CONFIG.invite.html
        },
        twoFa: {
            subject: cleanString(doc && doc.twoFa && doc.twoFa.subject) || DEFAULT_CONFIG.twoFa.subject,
            text: cleanString(doc && doc.twoFa && doc.twoFa.text) || DEFAULT_CONFIG.twoFa.text,
            html: cleanString(doc && doc.twoFa && doc.twoFa.html) || DEFAULT_CONFIG.twoFa.html
        },
        create: doc && doc.create ? doc.create : undefined,
        update: doc && doc.update ? doc.update : undefined,
        _id: doc && doc._id ? String(doc._id) : null
    };
}

function sanitizeConfig(doc) {
    const config = mergeConfig(doc);
    config.smtp.hasPass = !!config.smtp.pass;
    config.smtp.pass = '';
    return config;
}

function toPayload(body, current) {
    const smtp = body && body.smtp ? body.smtp : {};
    const currentPass = current && current.smtp && current.smtp.pass ? current.smtp.pass : '';
    const nextPass = cleanString(smtp.pass);
    const activeTemplates = normalizeActiveTemplates(body);
    return {
        key: 'default',
        enabled: activeTemplates.length > 0 && !(body && body.enabled === false),
        activeTemplates: activeTemplates,
        appName: cleanString(body && body.appName) || DEFAULT_CONFIG.appName,
        appUrl: cleanString(body && body.appUrl),
        from: cleanString(body && body.from),
        fromName: cleanString(body && body.fromName) || DEFAULT_CONFIG.fromName,
        smtp: {
            host: cleanString(smtp.host),
            port: Number(smtp.port) || DEFAULT_CONFIG.smtp.port,
            secure: !!smtp.secure,
            user: cleanString(smtp.user),
            pass: nextPass && nextPass !== '********' ? nextPass : currentPass
        },
        invite: {
            subject: cleanString(body && body.invite && body.invite.subject) || DEFAULT_CONFIG.invite.subject,
            text: cleanString(body && body.invite && body.invite.text) || DEFAULT_CONFIG.invite.text,
            html: cleanString(body && body.invite && body.invite.html) || DEFAULT_CONFIG.invite.html
        },
        twoFa: {
            subject: cleanString(body && body.twoFa && body.twoFa.subject) || DEFAULT_CONFIG.twoFa.subject,
            text: cleanString(body && body.twoFa && body.twoFa.text) || DEFAULT_CONFIG.twoFa.text,
            html: cleanString(body && body.twoFa && body.twoFa.html) || DEFAULT_CONFIG.twoFa.html
        }
    };
}

async function resolveAccountId(request) {
    const authAccountId = request && request.authAccount && request.authAccount._id
        ? String(request.authAccount._id)
        : '';
    if (authAccountId && mongo.ObjectId.isValid(authAccountId)) {
        return new mongo.ObjectId(authAccountId);
    }
    return null;
}

exports.getConfig = async function () {
    const doc = await EmailNotification.onQuery({ key: 'default' });
    return mergeConfig(doc || DEFAULT_CONFIG);
};

exports.onGet = async function (request, response, next) {
    try {
        const doc = await EmailNotification.onQuery({ key: 'default' });
        return resMsg.sendResponse(response, 0, 20000, sanitizeConfig(doc || DEFAULT_CONFIG));
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onUpdate = async function (request, response, next) {
    try {
        const current = await EmailNotification.onQuery({ key: 'default' });
        const payload = toPayload(request.body || {}, current);
        const accountId = await resolveAccountId(request);
        if (current && current._id) {
            payload.update = { by: accountId, datetime: new Date() };
            const doc = await EmailNotification.onUpdate({ key: 'default' }, payload);
            return resMsg.sendResponse(response, 0, 20000, sanitizeConfig(doc));
        }
        payload.create = { by: accountId, datetime: new Date() };
        const doc = await EmailNotification.onCreate(payload);
        return resMsg.sendResponse(response, 0, 20000, sanitizeConfig(doc));
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};
