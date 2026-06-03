'use strict';

const mongo = require('mongodb');
const Group = require('../../settings/controller/group');
const Status = require('../../settings/controller/status');

const ACCOUNT_STATUS_GROUP_KEY = 'ACCOUNT_STATUS';
const STATUS_DEFINITIONS = [
    { key: 'PENDING', title: 'Pending', description: 'Account is pending activation.', signinAllowed: false },
    { key: 'ACTIVE', title: 'Active', description: 'Account is active and can sign in.', signinAllowed: true },
    { key: 'INACTIVE', title: 'Inactive', description: 'Account is inactive by administrator action.', signinAllowed: false },
    { key: 'LOCKED', title: 'Locked', description: 'Account is locked by security policy.', signinAllowed: false },
    { key: 'SUSPENDED', title: 'Suspended', description: 'Account is suspended pending review.', signinAllowed: false },
    { key: 'ARCHIVED', title: 'Archived', description: 'Account is archived and no longer usable.', signinAllowed: false }
];

const TRANSITIONS = {
    PENDING: ['ACTIVE', 'INACTIVE', 'ARCHIVED'],
    ACTIVE: ['INACTIVE', 'LOCKED', 'SUSPENDED', 'ARCHIVED'],
    INACTIVE: ['ACTIVE', 'ARCHIVED'],
    LOCKED: ['ACTIVE', 'SUSPENDED', 'ARCHIVED'],
    SUSPENDED: ['ACTIVE', 'INACTIVE', 'ARCHIVED'],
    ARCHIVED: []
};

const ACTION_TO_STATUS = {
    activate: 'ACTIVE',
    archive: 'ARCHIVED',
    deactivate: 'INACTIVE',
    inactivate: 'INACTIVE',
    lock: 'LOCKED',
    suspend: 'SUSPENDED',
    unlock: 'ACTIVE'
};

function normalizeKey(value) {
    return String(value || '').trim().toUpperCase();
}

function toObjectId(value) {
    if (!value || !mongo.ObjectId.isValid(value)) return null;
    return new mongo.ObjectId(value);
}

function toLangArray(value, key) {
    return [{ key: key || 'en', value: String(value || '').trim() }];
}

function sanitizeStatus(doc) {
    if (!doc) return null;
    return {
        _id: doc._id,
        key: doc.key || null,
        title: Array.isArray(doc.title) ? doc.title : [],
        description: Array.isArray(doc.description) ? doc.description : [],
        group: doc.group || null,
        state: typeof doc.state === 'boolean' ? doc.state : true
    };
}

function getLegacyStatusKey(value) {
    if (value === 0 || value === '0') return 'ACTIVE';
    if (value === 1 || value === '1') return 'INACTIVE';
    if (value === 2 || value === '2') return 'SUSPENDED';
    return 'PENDING';
}

async function ensureGroup() {
    let group = await Group.onQuery({ key: ACCOUNT_STATUS_GROUP_KEY });
    if (group) return group;

    group = await Group.onCreate({
        key: ACCOUNT_STATUS_GROUP_KEY,
        title: toLangArray('Account Status', 'en'),
        description: toLangArray('Master data for account lifecycle status.', 'en'),
        status: null,
        state: true
    });

    return group;
}

async function ensureStatuses(groupId) {
    const statusMap = {};
    for (const item of STATUS_DEFINITIONS) {
        let doc = await Status.onQuery({
            group: toObjectId(groupId),
            key: item.key
        });

        if (!doc) {
            doc = await Status.onCreate({
                key: item.key,
                title: toLangArray(item.title, 'en'),
                description: toLangArray(item.description, 'en'),
                group: toObjectId(groupId),
                status: null,
                state: true
            });
        }

        statusMap[item.key] = sanitizeStatus(doc);
    }

    return statusMap;
}

async function ensureAccountStatusMasterData() {
    const group = await ensureGroup();
    const statuses = await ensureStatuses(group._id);
    return {
        group,
        statuses
    };
}

async function findStatusById(statusId) {
    const objectId = toObjectId(statusId);
    if (!objectId) return null;
    const doc = await Status.onQuery({ _id: objectId });
    return sanitizeStatus(doc);
}

async function resolveAccountStatus(accountController, account) {
    const master = await ensureAccountStatusMasterData();
    if (!account) {
        return { account: null, status: master.statuses.PENDING, master };
    }

    const rawStatus = account.status;
    if (rawStatus && typeof rawStatus === 'object' && rawStatus.key) {
        return { account, status: sanitizeStatus(rawStatus), master };
    }

    const current = await findStatusById(rawStatus);
    if (current) {
        return { account, status: current, master };
    }

    const fallbackKey = getLegacyStatusKey(rawStatus);
    const fallbackStatus = master.statuses[fallbackKey] || master.statuses.PENDING;
    if (fallbackStatus && account._id) {
        await accountController.onUpdate(
            { _id: toObjectId(account._id) },
            { status: toObjectId(fallbackStatus._id) }
        );
        const updated = await accountController.onQuery(
            { _id: toObjectId(account._id) },
            [{ path: 'status', select: 'key title description group state' }]
        );
        return {
            account: updated || account,
            status: fallbackStatus,
            master
        };
    }

    return { account, status: fallbackStatus, master };
}

function resolveTargetStatusKey(action, toStatusKey) {
    const normalizedAction = String(action || '').trim().toLowerCase();
    return ACTION_TO_STATUS[normalizedAction] || normalizeKey(toStatusKey);
}

function canTransition(fromKey, toKey) {
    const current = normalizeKey(fromKey);
    const target = normalizeKey(toKey);
    if (!current || !target) return false;
    if (current === target) return true;
    return (TRANSITIONS[current] || []).includes(target);
}

function isSigninAllowed(status) {
    const key = normalizeKey(status && status.key ? status.key : status);
    const found = STATUS_DEFINITIONS.find(item => item.key === key);
    return !!(found && found.signinAllowed);
}

module.exports = {
    ACCOUNT_STATUS_GROUP_KEY,
    STATUS_DEFINITIONS,
    TRANSITIONS,
    canTransition,
    ensureAccountStatusMasterData,
    isSigninAllowed,
    resolveAccountStatus,
    resolveTargetStatusKey,
    sanitizeStatus,
    toObjectId
};
