'use strict';

const mongo = require('mongodb');
const moment = require('moment');
const crypto = require('crypto');
const Utils = require("../../../../helpers/utils");
const Config = require("../../../../config/config");
const resMsg = require("../../settings/service/message");
const Account = require('../controller/account');
require('../../settings/models/lifecycle_affiliation_type.model');
require('../../settings/models/lifecycle_access_profile.model');
const accountAccess = require('../../security/service/account-access');
const iamAdminClient = require('../../security/service/iam-admin-client');
const EmailNotifications = require('../../../../helpers/email-notifications');
const { writeAudit } = require('../../../../helpers/audit.logger');
const { ensureBootstrapAccessForAccount } = require('../../security/service/bootstrap-access');
const {
    buildDeprovisionPlan,
    buildLifecycleContext,
    buildLifecycleTimeline,
    buildLifecycleSummary,
    buildProvisioningPlan,
    summarizeSignals
} = require('./identity-lifecycle');
const { splitLifecycleStorage } = require('./lifecycle-boundary');
const {
    canTransition,
    ensureAccountStatusMasterData,
    isSigninAllowed,
    resolveAccountStatus,
    resolveTargetStatusKey,
    toObjectId
} = require('./account-status');

const TRUST_DEVICE_DAYS = Number(process.env.TRUST_DEVICE_DAYS || 30);
const FORCE_2FA = typeof (Config.security && Config.security.authRequire2FA) === 'boolean'
    ? Config.security.authRequire2FA
    : true;

function normalizeIp(request) {
    var raw = request && request.headers ? request.headers['x-forwarded-for'] : null;
    if (Array.isArray(raw)) {
        raw = raw.length > 0 ? raw[0] : null;
    }
    if (raw && typeof raw === 'string') {
        raw = raw.split(',')[0].trim();
    }
    var ip = raw || request.ip || '';
    if (String(ip).startsWith('::ffff:')) {
        ip = String(ip).replace('::ffff:', '');
    }
    return String(ip || '');
}

function normalizeNetworkKey(ip) {
    var cleanIp = String(ip || '').trim();
    var ipv4 = cleanIp.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
    if (ipv4) {
        return ipv4[1] + '.' + ipv4[2] + '.' + ipv4[3];
    }
    return cleanIp;
}

function normalizeDeviceId(deviceId) {
    if (!deviceId) return null;
    var value = String(deviceId).trim();
    if (!value) return null;
    if (value.length < 8 || value.length > 200) return null;
    if (!/^[a-zA-Z0-9._:-]+$/.test(value)) return null;
    return value;
}

function createFingerprint(deviceId, userAgent) {
    if (!deviceId) return null;
    var src = String(deviceId) + '|' + String(userAgent || '');
    return crypto.createHash('sha256').update(src).digest('hex');
}

function getTrustedExpiresAt() {
    return new Date(Date.now() + (TRUST_DEVICE_DAYS * 24 * 60 * 60 * 1000));
}

function findTrustedDevice(control, fingerprint, networkKey) {
    if (!control || !Array.isArray(control.trustedDevices) || !fingerprint || !networkKey) {
        return null;
    }
    var now = Date.now();
    return control.trustedDevices.find(function (item) {
        if (!item) return false;
        if (String(item.fingerprint || '') !== String(fingerprint)) return false;
        if (String(item.networkKey || '') !== String(networkKey)) return false;
        if (!item.expiresAt) return false;
        return new Date(item.expiresAt).getTime() >= now;
    }) || null;
}

async function upsertTrustedDevice(accountId, trustedDevice) {
    if (!accountId || !trustedDevice || !trustedDevice.fingerprint || !trustedDevice.networkKey) {
        return;
    }
    var query = { _id: new mongo.ObjectId(accountId) };
    await Account.onUpdate(query, {
        $pull: {
            'control.trustedDevices': {
                fingerprint: trustedDevice.fingerprint,
                networkKey: trustedDevice.networkKey
            }
        }
    });
    await Account.onUpdate(query, {
        $push: {
            'control.trustedDevices': trustedDevice
        }
    });
}

function pickLangValue(items) {
    if (!Array.isArray(items)) return '';
    var found = items.find(function (item) {
        return item && item.value;
    });
    return found ? String(found.value) : '';
}


exports.onCheckAuthorization = async function (request, response, next) {
    try {
        var headers = request && request.headers ? request.headers : {};
        var accessToken = headers['x-access-token'] ? String(headers['x-access-token']).trim() : '';
        var cookieHeader = headers.cookie ? String(headers.cookie).trim() : '';
        if (!accessToken && !cookieHeader) {
            var missingTokenRes = await resMsg.onMessage_Response(0,40100);
            return response.status(401).json(missingTokenRes);
        }

        const current = await iamAdminClient.resolveCurrentAccount(request);
        const account = current && current.account ? current.account : null;
        if (!account || !account._id) {
            var unauthorizedRes = await resMsg.onMessage_Response(0,40100);
            return response.status(401).json(unauthorizedRes);
        }

        if (!request.body || typeof request.body !== 'object') {
            request.body = {};
        }
        request.body.accounts = String(account._id);
        request.authAccount = account;
        request.authSession = current && current.payload && current.payload.data && current.payload.data.authSession
            ? current.payload.data.authSession
            : null;
        return next();

    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

exports.verifyIdTokenGoogle = async function (request, response, next) {
    try {
        if (request.body && request.body.token) {
            const token = String(request.body.token).trim();
            if (!token) {
                var badToken = await resMsg.onMessage_Response(0,40100);
                return response.status(401).json(badToken);
            }

            const { OAuth2Client } = require('google-auth-library');
            const audience =
                process.env.GOOGLE_CLIENT_ID ||
                process.env.VUE_APP_CLIENTID ||
                '225788483142-8pkg8on8nh60ao83ve33ff3lflv2ccvo.apps.googleusercontent.com';
            const client = new OAuth2Client(audience || undefined);

            try {
                const ticket = await client.verifyIdToken({
                    idToken: token,
                    audience: audience
                });
                const payload = ticket.getPayload() || {};
                request.body.email = payload.email || null;
                request.body.googleSub = payload.sub || null;
                request.body.googleGivenName = payload.given_name || null;
                request.body.googleFamilyName = payload.family_name || null;
                request.body.googlePicture = payload.picture || null;
                return next();
            } catch (error) {
                console.error('Google token verification failed:', {
                    message: error && error.message ? error.message : 'unknown_error',
                    audience: audience
                });
                var invalidToken = await resMsg.onMessage_Response(0,40100);
                return response.status(401).json(invalidToken);
            }
        } else {
            return next();
        }
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,50000)
        return response.status(500).json(resData);
    }
};
exports.SingIn = async function (request, response, next) {
    try {
        let query = {};
        let loginEmail = null;
        const masterStatus = await ensureAccountStatusMasterData();
        const activeStatus = masterStatus.statuses.ACTIVE;
        const userAgent = String(request.get('User-Agent') || '');
        const deviceId = normalizeDeviceId(request.body && request.body.deviceId);
        const clientIp = normalizeIp(request);
        const networkKey = normalizeNetworkKey(clientIp);
        const fingerprint = createFingerprint(deviceId, userAgent);

        if (request.body.email) {
            loginEmail = String(request.body.email).trim().toLowerCase();
            query.$or = [
                { email: loginEmail },
                { 'authen.email': loginEmail }
            ];
        } else if (request.body.username && request.body.password === "********") {
            var elemMatch = {};
            elemMatch.type = (request.body.type == null)? new mongo.ObjectId("66a06852660ccb1debade7c5"):new mongo.ObjectId(request.body.username)
            elemMatch.username = request.body.username;
            query.authen = { $elemMatch : elemMatch }
        } else {
            const resData = await resMsg.onMessage_Response(0, 40400);
            return response.status(404).json(resData);
        }

        // console.log(query)
        let isDoc = await Account.onQuery(query);

        if (!isDoc && loginEmail && request.body.googleSub) {
            const createPayload = {
                dateTime: new Date(),
                code: 'GOOG-' + Utils.randomString(10).toUpperCase(),
                email: loginEmail,
                authen: [
                    {
                        username: loginEmail,
                        password: null,
                        email: loginEmail,
                        oAtuhToken: request.body.googleSub
                    }
                ],
                userinfo: {
                    firstName: toLangArray(request.body.googleGivenName, 'en'),
                    lastName: toLangArray(request.body.googleFamilyName, 'en'),
                    image: request.body.googlePicture || null
                },
                control: {
                    sso: true,
                    limit: 4,
                    trustedDevices: [],
                    device: []
                },
                verification: [],
                status: activeStatus ? toObjectId(activeStatus._id) : null
            };
            isDoc = await Account.onCreate(createPayload);
        }

        if (!isDoc) {
            const resData = await resMsg.onMessage_Response(0, 40400);
            return response.status(404).json(resData);
        }
        const resolvedAccount = await resolveAccountStatus(Account, isDoc);
        isDoc = resolvedAccount.account || isDoc;
        if (!isSigninAllowed(resolvedAccount.status)) {
            console.error('NewSystem sign-in denied by account status:', {
                accountId: String(isDoc._id),
                email: loginEmail,
                status: resolvedAccount.status && resolvedAccount.status.key ? resolvedAccount.status.key : null
            });
            const denied = await resMsg.onMessage_Response(0, 40100);
            denied.data = {
                status: resolvedAccount.status
            };
            return response.status(401).json(denied);
        }

        await ensureBootstrapAccessForAccount(isDoc._id);
        const trustedDevice = findTrustedDevice(isDoc.control, fingerprint, networkKey);
        const require2FA = FORCE_2FA ? !trustedDevice : false;

        const sessionQuery = { _id: new mongo.ObjectId(isDoc._id) };

        // Check verification
        // const isVerification = isDoc.verification.filter(
        //     item => item.status !== "6548516f7ab25be71bbeeed1"
        // );

        // Limit device
        if (isDoc.control && isDoc.control.limit <= isDoc.control.device.length) {
            await Account.onUpdate(sessionQuery, {
                $pull: { "control.device": isDoc.control.device[0] }
            });
        }

        // Create new device session
        const token = await Utils.createTokens();
        const devices = {
            version: "1",
            ip: clientIp,
            device: userAgent,
            xAccessToken: token,
            expired_key: new moment().unix() + Config.tokenExpired,
            accounts: isDoc._id,
            deviceId: deviceId,
            fingerprint: fingerprint,
            networkKey: networkKey,
            rememberDeviceRequested: false
        };

        await Account.onUpdate(sessionQuery, {
            $push: { "control.device": devices }
        });

        if (!require2FA && trustedDevice) {
            await upsertTrustedDevice(isDoc._id, {
                deviceId: deviceId || trustedDevice.deviceId || null,
                fingerprint: trustedDevice.fingerprint,
                networkKey: trustedDevice.networkKey,
                userAgent: userAgent,
                lastIp: clientIp,
                trustedAt: new Date(),
                expiresAt: getTrustedExpiresAt()
            });
        }

        // Clean sensitive data before response
        delete devices.ip;
        delete devices.device;

        const resData = await resMsg.onMessage_Response(0, 20000);
        devices.require2FA = require2FA;
        devices.trustedDeviceMatched = !require2FA;
        resData.data = devices;
        await writeAudit({
            module: 'auth',
            action: 'signin',
            actorType: 'user',
            actorId: String(isDoc._id),
            resourceType: 'Information_Accounts',
            resourceId: String(isDoc._id),
            meta: {
                require2FA: require2FA,
                trustedDeviceMatched: !require2FA,
                deviceId: deviceId,
                networkKey: networkKey
            }
        }, request);
        return response.status(200).json(resData);
    } catch (err) {
        console.error('SingIn error:', err);
        const resData = await resMsg.onMessage_Response(0, 50000);
        return response.status(500).json(resData);
    }
};

exports.onMe = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var notFound = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(notFound);
        }

        var query = { _id: new mongo.ObjectId(accountId) };
        var doc = await Account.onQuery(query, [{ path: 'status', select: 'key title description group state' }]);
        if (!doc) {
            var emptyRes = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(emptyRes);
        }
        var resolved = await resolveAccountStatus(Account, doc);
        doc = resolved.account || doc;

        if (doc.control && Array.isArray(doc.control.device)) {
            doc.control.device = doc.control.device.map(function (item) {
                var cloned = Object.assign({}, item);
                delete cloned.ip;
                delete cloned.device;
                return cloned;
            });
        }

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = doc;
        return response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onSessions = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!account) {
            var missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        var currentToken = request.headers && request.headers['x-access-token']
            ? String(request.headers['x-access-token'])
            : '';
        var sessions = Array.isArray(account.control && account.control.device)
            ? account.control.device.map(function (item) {
                return sanitizeSession(item, currentToken);
            }).filter(Boolean)
            : [];

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { sessions: sessions };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onRevokeSession = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        var sessionId = request.params && request.params.id ? String(request.params.id) : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId) || !sessionId || !mongo.ObjectId.isValid(sessionId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { $pull: { 'control.device': { _id: new mongo.ObjectId(sessionId) } } }
        );

        await writeAudit({
            module: 'auth',
            action: 'revoke-session',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            targetId: sessionId
        }, request);

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        var currentToken = request.headers && request.headers['x-access-token']
            ? String(request.headers['x-access-token'])
            : '';
        var sessions = Array.isArray(account && account.control && account.control.device)
            ? account.control.device.map(function (item) {
                return sanitizeSession(item, currentToken);
            }).filter(Boolean)
            : [];

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { revoked: true, sessions: sessions };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onAccountSessions = async function (request, response, next) {
    try {
        var accountId = request.params && request.params.id ? String(request.params.id) : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }
        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!account) {
            var missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }
        var currentToken = request.headers && request.headers['x-access-token']
            ? String(request.headers['x-access-token'])
            : '';
        var sessions = Array.isArray(account.control && account.control.device)
            ? account.control.device.map(function (item) {
                return sanitizeSession(item, currentToken);
            }).filter(Boolean)
            : [];
        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { sessions: sessions };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onAccountRevokeSession = async function (request, response, next) {
    try {
        var accountId = request.params && request.params.id ? String(request.params.id) : null;
        var sessionId = request.params && request.params.sessionId ? String(request.params.sessionId) : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId) || !sessionId || !mongo.ObjectId.isValid(sessionId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { $pull: { 'control.device': { _id: new mongo.ObjectId(sessionId) } } }
        );

        await writeAudit({
            module: 'accounts',
            action: 'admin-revoke-session',
            actorType: 'user',
            actorId: request.body && request.body.accounts ? String(request.body.accounts) : null,
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            targetId: sessionId
        }, request);

        return exports.onAccountSessions(request, response, next);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onLogout = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        var accessToken = request.headers && request.headers['x-access-token']
            ? String(request.headers['x-access-token'])
            : '';
        if (!accountId || !mongo.ObjectId.isValid(accountId) || !accessToken) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { $pull: { 'control.device': { xAccessToken: accessToken } } }
        );

        await writeAudit({
            module: 'auth',
            action: 'logout',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId)
        }, request);

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { loggedOut: true };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onLogoutAll = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { 'control.device': [] }
        );

        await writeAudit({
            module: 'auth',
            action: 'logout-all',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId)
        }, request);

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { loggedOutAll: true };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onStatusOptions = async function (request, response, next) {
    try {
        const master = await ensureAccountStatusMasterData();
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            group: master.group,
            statuses: Object.values(master.statuses)
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onGroupOptions = async function (request, response, next) {
    try {
        const docs = await accountAccess.getGroupOptions();
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            groups: docs || []
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onEffectivePermissions = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            const bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        const data = await accountAccess.getEffectivePermissions(accountId);
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = data;
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onChangeStatus = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            const bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        const account = await Account.onQuery(
            { _id: new mongo.ObjectId(accountId) },
            [{ path: 'status', select: 'key title description group state' }]
        );
        if (!account) {
            const missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        const resolved = await resolveAccountStatus(Account, account);
        const currentStatus = resolved.status;
        const targetKey = resolveTargetStatusKey(
            request.body && request.body.action,
            request.body && request.body.toStatusKey
        );

        if (!targetKey) {
            const invalid = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(invalid);
        }

        const master = resolved.master || await ensureAccountStatusMasterData();
        const targetStatus = master.statuses[targetKey];
        if (!targetStatus) {
            const invalid = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(invalid);
        }

        if (!canTransition(currentStatus && currentStatus.key, targetKey)) {
            const denied = await resMsg.onMessage_Response(0,40100);
            denied.data = {
                currentStatus: currentStatus || null,
                targetStatus: targetStatus
            };
            return response.status(401).json(denied);
        }

        const updated = await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { status: toObjectId(targetStatus._id) },
            [{ path: 'status', select: 'key title description group state' }]
        );

        await writeAudit({
            module: 'accounts',
            action: 'change-status',
            actorType: 'user',
            actorId: request.body && request.body.accounts ? String(request.body.accounts) : null,
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            detail: {
                fromStatus: currentStatus && currentStatus.key ? currentStatus.key : null,
                toStatus: targetKey
            }
        }, request);

        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = updated;
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onList = async function (request, response, next) {
    try {
        const docs = await Account.onQuerys(
            {},
            lifecyclePopulate()
        );
        const assignmentsByAccountId = await accountAccess.loadAssignmentsByAccountIds((docs || []).map(function (item) {
            return item && item._id ? item._id : null;
        }));

        const normalized = [];
        for (const item of docs || []) {
            const resolved = await resolveAccountStatus(Account, item);
            const account = resolved.account || item;
            if (account.control && Array.isArray(account.control.device)) {
                account.control.device = account.control.device.map(function (device) {
                    var cloned = Object.assign({}, device);
                    delete cloned.ip;
                    delete cloned.device;
                    return cloned;
                });
            }
            const assignmentRows = assignmentsByAccountId[String(account._id)] || [];
            account.securityAssignments = assignmentRows;
            account.securityGroups = assignmentRows.map(function (row) {
                return row && row.group ? row.group : null;
            }).filter(Boolean);
            normalized.push(account);
        }

        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = normalized;
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onLifecycleSummary = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        const account = await loadAccountForLifecycle(accountId);
        if (!account) {
            const missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        const context = await buildLifecycleContext(account.lifecycle || {}, account.lifecycle || {}, account);
        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            accountId: String(account._id),
            lifecycle: context.evaluation.lifecycle,
            summary: context.summary,
            timeline: buildLifecycleTimeline(context.evaluation, context.lifecycle, account),
            signals: summarizeSignals(context.evaluation.lifecycle, context.lifecycle, context.evaluation, account),
            plan: {
                targetStatusKey: context.evaluation.targetStatusKey,
                matchedRules: context.evaluation.matchedRules,
                recommendedProfiles: context.evaluation.recommendedProfiles,
                configurationErrors: context.evaluation.configurationErrors,
                warnings: context.evaluation.warnings
            }
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onUpdateLifecycle = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        const account = await loadAccountForLifecycle(accountId);
        if (!account) {
            const missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        const context = await buildLifecycleContext(request.body || {}, account.lifecycle || {}, account);
        const lifecycle = context.lifecycle;
        lifecycle.provisioning.lastEvaluatedAt = new Date();
        lifecycle.provisioning.lastSyncSource = 'MANUAL';

        const persisted = splitLifecycleStorage(lifecycle, account.hrContext || {});
        const updated = await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { lifecycle: persisted.lifecycle, hrContext: persisted.hrContext },
            lifecyclePopulate()
        );
        const audit = await writeAudit({
            module: 'identity-lifecycle',
            action: 'update',
            targetId: accountId,
            detail: {
                primaryAffiliation: lifecycle.primaryAffiliation,
                affiliationCount: lifecycle.affiliations.length,
                positionCount: lifecycle.positions.length
            }
        }, request);

        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            account: updated,
            lifecycle: context.evaluation.lifecycle,
            summary: context.summary,
            timeline: buildLifecycleTimeline(context.evaluation, context.lifecycle, updated),
            signals: summarizeSignals(context.evaluation.lifecycle, context.lifecycle, context.evaluation, updated),
            evaluation: {
                targetStatusKey: context.evaluation.targetStatusKey,
                matchedRules: context.evaluation.matchedRules,
                recommendedProfiles: context.evaluation.recommendedProfiles,
                configurationErrors: context.evaluation.configurationErrors,
                warnings: context.evaluation.warnings
            },
            audit: audit
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onProvisionAccount = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        const account = await loadAccountForLifecycle(accountId);
        if (!account) {
            const missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        const resolved = await resolveAccountStatus(Account, account);
        const context = await buildLifecycleContext(account.lifecycle || {}, account.lifecycle || {}, account);
        const plan = await buildProvisioningPlan(account, request.body || {});
        const lifecycle = context.lifecycle;
        if (plan.configurationErrors && plan.configurationErrors.length) {
            return configurationErrorResponse(response, plan.configurationErrors, plan.warnings);
        }
        lifecycle.provisioning.state = 'PROVISIONED';
        lifecycle.provisioning.strategy = plan.strategy;
        lifecycle.provisioning.joinerDate = lifecycle.provisioning.joinerDate || new Date();
        lifecycle.provisioning.lastProvisionedAt = new Date();
        lifecycle.provisioning.lastEvaluatedAt = new Date();
        lifecycle.provisioning.deprovisionDate = null;
        lifecycle.provisioning.deprovisionReason = null;

        const persisted = splitLifecycleStorage(lifecycle, account.hrContext || {});
        const updatePayload = { lifecycle: persisted.lifecycle, hrContext: persisted.hrContext };
        if (canApplyStatusTransition(resolved.status, plan.targetStatusKey)) {
            const master = resolved.master || await ensureAccountStatusMasterData();
            const targetStatus = master.statuses[plan.targetStatusKey];
            if (targetStatus && targetStatus._id) {
                updatePayload.status = toObjectId(targetStatus._id);
            }
        }

        const updated = await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            updatePayload,
            lifecyclePopulate()
        );
        const audit = await writeAudit({
            module: 'identity-lifecycle',
            action: 'provision',
            targetId: accountId,
            detail: plan
        }, request);

        const resData = await resMsg.onMessage_Response(0,20000);
        const updatedContext = await buildLifecycleContext(updated.lifecycle || {}, updated.lifecycle || {}, updated);
        resData.data = {
            account: updated,
            lifecycle: updatedContext.evaluation.lifecycle,
            summary: await buildLifecycleSummary(updated),
            timeline: buildLifecycleTimeline(updatedContext.evaluation, updatedContext.lifecycle, updated),
            signals: summarizeSignals(updatedContext.evaluation.lifecycle, updatedContext.lifecycle, updatedContext.evaluation, updated),
            plan: plan,
            audit: audit
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onDeprovisionAccount = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        const account = await loadAccountForLifecycle(accountId);
        if (!account) {
            const missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        const resolved = await resolveAccountStatus(Account, account);
        const plan = await buildDeprovisionPlan(account, request.body || {});
        if (plan.configurationErrors && plan.configurationErrors.length) {
            return configurationErrorResponse(response, plan.configurationErrors, plan.warnings);
        }
        const context = await buildLifecycleContext(account.lifecycle || {}, account.lifecycle || {}, account);
        const lifecycle = context.lifecycle;
        lifecycle.provisioning.state = 'DEPROVISIONED';
        lifecycle.provisioning.deprovisionDate = new Date();
        lifecycle.provisioning.deprovisionReason = plan.reason;
        lifecycle.provisioning.lastDeprovisionedAt = new Date();
        lifecycle.provisioning.lastEvaluatedAt = new Date();

        const persisted = splitLifecycleStorage(lifecycle, account.hrContext || {});
        const updatePayload = {
            lifecycle: persisted.lifecycle,
            hrContext: persisted.hrContext,
            'control.device': [],
            'control.trustedDevices': []
        };
        if (canApplyStatusTransition(resolved.status, plan.targetStatusKey)) {
            const master = resolved.master || await ensureAccountStatusMasterData();
            const targetStatus = master.statuses[plan.targetStatusKey];
            if (targetStatus && targetStatus._id) {
                updatePayload.status = toObjectId(targetStatus._id);
            }
        }

        const updated = await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            updatePayload,
            lifecyclePopulate()
        );
        const audit = await writeAudit({
            module: 'identity-lifecycle',
            action: 'deprovision',
            targetId: accountId,
            detail: plan
        }, request);

        const resData = await resMsg.onMessage_Response(0,20000);
        const updatedContext = await buildLifecycleContext(updated.lifecycle || {}, updated.lifecycle || {}, updated);
        resData.data = {
            account: updated,
            lifecycle: updatedContext.evaluation.lifecycle,
            summary: await buildLifecycleSummary(updated),
            timeline: buildLifecycleTimeline(updatedContext.evaluation, updatedContext.lifecycle, updated),
            signals: summarizeSignals(updatedContext.evaluation.lifecycle, updatedContext.lifecycle, updatedContext.evaluation, updated),
            plan: plan,
            audit: audit
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

function createOtpCode(length = 6) {
    var min = Math.pow(10, length - 1);
    var max = Math.pow(10, length) - 1;
    return String(Math.floor(min + (Math.random() * (max - min + 1))));
}

async function isMailConfigured() {
    return EmailNotifications.isMailConfigured();
}

function canExposeDevCode() {
    return process.env.NODE_ENV !== 'production' && process.env.EXPOSE_DEV_OTP === 'true';
}

function toLangArray(value, defaultKey) {
    var text = value ? String(value).trim() : '';
    if (!text) return [];
    return [{ key: defaultKey || 'en', value: text }];
}

function normalizeDateInput(value) {
    if (!value) return null;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date;
}

function sanitizeSession(item, currentToken) {
    if (!item) return null;
    return {
        _id: item._id ? String(item._id) : null,
        version: item.version || null,
        dateTime: item.dateTime || null,
        expired_key: item.expired_key || null,
        deviceId: item.deviceId || null,
        fingerprint: item.fingerprint || null,
        networkKey: item.networkKey || null,
        rememberDeviceRequested: !!item.rememberDeviceRequested,
        current: !!(currentToken && String(item.xAccessToken || '') === String(currentToken))
    };
}

function sanitizeTrustedDevice(item) {
    if (!item) return null;
    return {
        _id: item._id ? String(item._id) : null,
        deviceId: item.deviceId || null,
        fingerprint: item.fingerprint || null,
        networkKey: item.networkKey || null,
        trustedAt: item.trustedAt || null,
        expiresAt: item.expiresAt || null
    };
}

function canApplyStatusTransition(currentStatus, targetStatusKey) {
    return !!(targetStatusKey && currentStatus && canTransition(currentStatus.key, targetStatusKey));
}

function lifecyclePopulate() {
    return [
        { path: 'status', select: 'key title description group state' },
        { path: 'lifecycle.primaryAffiliation', select: 'key title description state source isSystem version' },
        { path: 'lifecycle.affiliations.type', select: 'key title description state source isSystem version' },
        { path: 'lifecycle.accessProfiles.profile', select: 'key title description defaultScope state source isSystem version' }
    ];
}

async function loadAccountForLifecycle(accountId) {
    if (!accountId || !mongo.ObjectId.isValid(accountId)) return null;
    return Account.onQuery(
        { _id: new mongo.ObjectId(accountId) },
        lifecyclePopulate()
    );
}

function configurationErrorResponse(response, errors, warnings) {
    return response.status(422).json({
        status: false,
        code: 42200,
        message: 'Lifecycle configuration error',
        data: {
            errors: Array.isArray(errors) ? errors : [],
            warnings: Array.isArray(warnings) ? warnings : []
        }
    });
}

exports.onUpdateAccount = async function (request, response, next) {
    try {
        const accountId = request.params && request.params.id ? request.params.id : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            const bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        const current = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!current) {
            const missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        const payload = request.body || {};
        const firstName = payload.firstName ? String(payload.firstName).trim() : '';
        const lastName = payload.lastName ? String(payload.lastName).trim() : '';
        const prefix = payload.prefix ? String(payload.prefix).trim() : '';
        const email = payload.email ? String(payload.email).trim().toLowerCase() : '';
        const code = payload.code ? String(payload.code).trim() : '';
        const cardId = payload.cardId ? String(payload.cardId).trim() : '';
        const msisdn = payload.msisdn ? String(payload.msisdn).trim() : '';
        const lineId = payload.lineId ? String(payload.lineId).trim() : '';
        const religion = payload.religion ? String(payload.religion).trim() : '';
        const image = payload.image ? String(payload.image).trim() : '';
        const birthday = normalizeDateInput(payload.birthday);
        const groupIds = Array.isArray(payload.groupIds)
            ? payload.groupIds
            : Array.isArray(payload.securityGroupIds)
                ? payload.securityGroupIds
                : [];

        const updatePayload = {
            code: code || null,
            email: email || null,
            userinfo: Object.assign({}, current.userinfo || {}, {
                prefix: prefix ? toLangArray(prefix, 'en') : [],
                firstName: firstName ? toLangArray(firstName, 'en') : [],
                lastName: lastName ? toLangArray(lastName, 'en') : []
                ,
                image: image || null,
                cardId: cardId || null,
                birthday: birthday,
                msisdn: msisdn || null,
                lineId: lineId || null,
                religion: religion || null
            })
        };

        if (Array.isArray(current.authen) && current.authen.length) {
            updatePayload.authen = current.authen.map(function (item, index) {
                const cloned = Object.assign({}, item);
                if (index === 0) {
                    cloned.username = email || cloned.username || null;
                    cloned.email = email || cloned.email || null;
                }
                return cloned;
            });
        }

        const updated = await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            updatePayload,
            [{ path: 'status', select: 'key title description group state' }]
        );
        let assignmentSnapshot = {
            assignments: [],
            groups: []
        };
        if (Array.isArray(groupIds)) {
            assignmentSnapshot = await iamAdminClient.syncAccountAssignments(accountId, groupIds);
        }

        const resolved = await resolveAccountStatus(Account, updated);
        const accountDoc = resolved.account || updated;
        accountDoc.securityAssignments = Array.isArray(assignmentSnapshot.assignments) ? assignmentSnapshot.assignments : [];
        accountDoc.securityGroups = Array.isArray(assignmentSnapshot.groups) ? assignmentSnapshot.groups : [];

        await writeAudit({
            module: 'accounts',
            action: 'update-account',
            actorType: 'user',
            actorId: request.body && request.body.accounts ? String(request.body.accounts) : null,
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            detail: {
                email: accountDoc.email || null,
                groupCount: accountDoc.securityGroups.length
            }
        }, request);

        const resData = await resMsg.onMessage_Response(0,20000);
        resData.data = accountDoc;
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(resData);
    }
};

exports.onTwoFaRequest = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        var query = { _id: new mongo.ObjectId(accountId) };
        var account = await Account.onQuery(query);
        if (!account) {
            var missingAccount = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missingAccount);
        }

        var targetEmail = account.email || null;
        if (!targetEmail && Array.isArray(account.authen)) {
            var authenEmail = account.authen.find(function (item) {
                return item && item.email;
            });
            targetEmail = authenEmail ? authenEmail.email : null;
        }
        if (!targetEmail) {
            var noEmail = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(noEmail);
        }

        var now = new Date();
        var cooldownMs = 30 * 1000;
        var existed = Array.isArray(account.verification)
            ? account.verification.find(function (item) {
                if (!item) return false;
                if (String(item.src || '') !== 'signin-2fa') return false;
                if (!item.expired) return false;
                return new Date(item.expired) >= now;
            })
            : null;
        if (existed && existed.dateTime && ((new Date(existed.dateTime).getTime() + cooldownMs) > now.getTime())) {
            var cooldownRes = await resMsg.onMessage_Response(0,20000);
            cooldownRes.data = {
                channel: 'email',
                expiresAt: existed.expired,
                resent: false,
                cooldownSeconds: Math.ceil(((new Date(existed.dateTime).getTime() + cooldownMs) - now.getTime()) / 1000)
            };
            if (!(await isMailConfigured()) && canExposeDevCode()) {
                cooldownRes.data.devCode = existed.code || null;
            }
            return response.status(200).json(cooldownRes);
        }

        var code = createOtpCode(6);
        var expiresAt = new Date(Date.now() + (5 * 60 * 1000));

        var mailSent = false;
        if (await isMailConfigured()) {
            var mailResult = await EmailNotifications.sendTwoFa(targetEmail, {
                code: code,
                expiresMinutes: 5
            });
            if (!mailResult || !mailResult.success) {
                var mailErr = await resMsg.onMessage_Response(0,50000);
                return response.status(500).json(mailErr);
            }
            mailSent = true;
        }

        var updatePayload = {
            $pull: {
                verification: { src: 'signin-2fa' }
            }
        };
        await Account.onUpdate(query, updatePayload);
        await Account.onUpdate(query, {
            $push: {
                verification: {
                    src: 'signin-2fa',
                    code: code,
                    dateTime: new Date(),
                    expired: expiresAt,
                    status: null
                }
            }
        });

        await writeAudit({
            module: 'auth',
            action: '2fa-request',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            meta: {
                channel: 'email',
                email: targetEmail,
                expiresAt: expiresAt,
                mailSent: mailSent
            }
        }, request);

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            channel: 'email',
            expiresAt: expiresAt,
            resent: true
        };
        if (!mailSent && canExposeDevCode()) {
            resData.data.devCode = code;
        }
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onTwoFaVerify = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        var code = request.body && request.body.code ? String(request.body.code).trim() : '';
        if (!accountId || !mongo.ObjectId.isValid(accountId) || !code) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!account || !Array.isArray(account.verification)) {
            var notFound = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(notFound);
        }

        var now = new Date();
        var matched = account.verification.find(function (item) {
            if (!item) return false;
            if (String(item.src || '') !== 'signin-2fa') return false;
            if (String(item.code || '') !== code) return false;
            if (!item.expired) return false;
            return new Date(item.expired) >= now;
        });
        if (!matched) {
            var denied = await resMsg.onMessage_Response(0,40100);
            return response.status(401).json(denied);
        }

        const accountQuery = { _id: new mongo.ObjectId(accountId) };
        await Account.onUpdate(accountQuery, { $pull: { verification: { src: 'signin-2fa' } } });

        await writeAudit({
            module: 'auth',
            action: '2fa-verify',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            meta: {
                verified: true
            }
        }, request);

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { verified: true };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onTrustDevice = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        var accessToken = request.headers && request.headers['x-access-token']
            ? String(request.headers['x-access-token'])
            : '';
        if (!accessToken) {
            var denied = await resMsg.onMessage_Response(0,40100);
            return response.status(401).json(denied);
        }

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!account || !account.control || !Array.isArray(account.control.device)) {
            var missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        var activeSession = account.control.device.find(function (item) {
            return item && String(item.xAccessToken || '') === accessToken;
        });
        if (!activeSession || !activeSession.fingerprint || !activeSession.networkKey) {
            var invalid = await resMsg.onMessage_Response(0,40100);
            return response.status(401).json(invalid);
        }

        var trustedPayload = {
            deviceId: activeSession.deviceId || null,
            fingerprint: activeSession.fingerprint,
            networkKey: activeSession.networkKey,
            userAgent: activeSession.device || null,
            lastIp: activeSession.ip || null,
            trustedAt: new Date(),
            expiresAt: getTrustedExpiresAt()
        };
        await upsertTrustedDevice(accountId, trustedPayload);

        await writeAudit({
            module: 'auth',
            action: 'trust-device',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            meta: {
                trusted: true,
                expiresAt: trustedPayload.expiresAt
            }
        }, request);

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = {
            trusted: true,
            expiresAt: trustedPayload.expiresAt
        };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onTrustedDevices = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!account) {
            var missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        var devices = Array.isArray(account.control && account.control.trustedDevices)
            ? account.control.trustedDevices.map(sanitizeTrustedDevice).filter(Boolean)
            : [];

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { trustedDevices: devices };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onRevokeTrustedDevice = async function (request, response, next) {
    try {
        var accountId = request.body && request.body.accounts ? request.body.accounts : null;
        var trustedDeviceId = request.params && request.params.id ? String(request.params.id) : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId) || !trustedDeviceId || !mongo.ObjectId.isValid(trustedDeviceId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { $pull: { 'control.trustedDevices': { _id: new mongo.ObjectId(trustedDeviceId) } } }
        );

        await writeAudit({
            module: 'auth',
            action: 'revoke-trusted-device',
            actorType: 'user',
            actorId: String(accountId),
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            targetId: trustedDeviceId
        }, request);

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        var devices = Array.isArray(account && account.control && account.control.trustedDevices)
            ? account.control.trustedDevices.map(sanitizeTrustedDevice).filter(Boolean)
            : [];

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { revoked: true, trustedDevices: devices };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onAccountTrustedDevices = async function (request, response, next) {
    try {
        var accountId = request.params && request.params.id ? String(request.params.id) : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        var account = await Account.onQuery({ _id: new mongo.ObjectId(accountId) });
        if (!account) {
            var missing = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(missing);
        }

        var devices = Array.isArray(account.control && account.control.trustedDevices)
            ? account.control.trustedDevices.map(sanitizeTrustedDevice).filter(Boolean)
            : [];

        var resData = await resMsg.onMessage_Response(0,20000);
        resData.data = { trustedDevices: devices };
        return response.status(200).json(resData);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};

exports.onAccountRevokeTrustedDevice = async function (request, response, next) {
    try {
        var accountId = request.params && request.params.id ? String(request.params.id) : null;
        var trustedDeviceId = request.params && request.params.trustedDeviceId ? String(request.params.trustedDeviceId) : null;
        if (!accountId || !mongo.ObjectId.isValid(accountId) || !trustedDeviceId || !mongo.ObjectId.isValid(trustedDeviceId)) {
            var bad = await resMsg.onMessage_Response(0,40400);
            return response.status(404).json(bad);
        }

        await Account.onUpdate(
            { _id: new mongo.ObjectId(accountId) },
            { $pull: { 'control.trustedDevices': { _id: new mongo.ObjectId(trustedDeviceId) } } }
        );

        await writeAudit({
            module: 'accounts',
            action: 'admin-revoke-trusted-device',
            actorType: 'user',
            actorId: request.body && request.body.accounts ? String(request.body.accounts) : null,
            resourceType: 'Information_Accounts',
            resourceId: String(accountId),
            targetId: trustedDeviceId
        }, request);

        return exports.onAccountTrustedDevices(request, response, next);
    } catch (err) {
        var fail = await resMsg.onMessage_Response(0,50000);
        return response.status(500).json(fail);
    }
};
