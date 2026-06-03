'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { promisify } = require('util');
const mongo = require('mongodb');
const mongoose = require('mongoose');
const DatabaseBackup = require('../models/database_backup.model');
const DatabaseBackupRun = require('../models/database_backup_run.model');
const Account = require('../../accounts/controller/account');
const resMsg = require('./message');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
const DEFAULT_KEY = 'default';
const DEFAULT_INTERVAL_HOURS = 24;
const DEFAULT_RETENTION_COUNT = 10;
const MIN_INTERVAL_HOURS = 1;
const MAX_INTERVAL_HOURS = 720;
const MIN_RETENTION_COUNT = 1;
const MAX_RETENTION_COUNT = 100;

let activeBackup = null;
let autoTimer = null;

function toBoolean(value, fallback) {
    if (value === undefined || value === null || String(value).trim() === '') return fallback;
    if (typeof value === 'boolean') return value;
    const normalized = String(value).trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
    return fallback;
}

function clampNumber(value, fallback, min, max) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function defaultBackupDir() {
    return process.env.DATABASE_BACKUP_DIR || path.join(process.cwd(), 'backups', 'database');
}

function resolveBackupDir(value) {
    const source = String(value || defaultBackupDir()).trim() || defaultBackupDir();
    return path.isAbsolute(source) ? source : path.resolve(process.cwd(), source);
}

function sanitizeName(value) {
    return String(value || 'database').replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'database';
}

function timestampName(date) {
    return date.toISOString().replace(/[:.]/g, '-');
}

function defaultSettingsPayload(accountId) {
    return {
        key: DEFAULT_KEY,
        autoEnabled: false,
        intervalHours: DEFAULT_INTERVAL_HOURS,
        retentionCount: DEFAULT_RETENTION_COUNT,
        backupDir: resolveBackupDir(),
        lastRunAt: null,
        nextRunAt: null,
        create: {
            by: accountId,
            datetime: new Date()
        }
    };
}

function nextRunDate(settings, fromDate) {
    if (!(settings && settings.autoEnabled)) return null;
    const intervalHours = clampNumber(settings.intervalHours, DEFAULT_INTERVAL_HOURS, MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS);
    return new Date((fromDate ? fromDate.getTime() : Date.now()) + intervalHours * 60 * 60 * 1000);
}

async function resolveAccountId(request) {
    const token = request && request.headers && request.headers['x-access-token'] ? String(request.headers['x-access-token']) : '';
    if (!token) return null;
    const account = await Account.onQuery({ 'control.device.xAccessToken': token });
    return account && account._id && mongo.ObjectId.isValid(String(account._id)) ? new mongo.ObjectId(account._id) : null;
}

async function ensureSettings(accountId) {
    const existing = await DatabaseBackup.findOne({ key: DEFAULT_KEY }).lean();
    if (existing) return existing;
    try {
        const created = await DatabaseBackup.create(defaultSettingsPayload(accountId || null));
        return created.toObject();
    } catch (err) {
        if (err && err.code === 11000) {
            const doc = await DatabaseBackup.findOne({ key: DEFAULT_KEY }).lean();
            if (doc) return doc;
        }
        throw err;
    }
}

function settingsPayload(body, current, accountId) {
    const now = new Date();
    const payload = {
        key: DEFAULT_KEY,
        autoEnabled: toBoolean(body && body.autoEnabled, current ? current.autoEnabled : false),
        intervalHours: clampNumber(body && body.intervalHours, current ? current.intervalHours : DEFAULT_INTERVAL_HOURS, MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS),
        retentionCount: clampNumber(body && body.retentionCount, current ? current.retentionCount : DEFAULT_RETENTION_COUNT, MIN_RETENTION_COUNT, MAX_RETENTION_COUNT),
        backupDir: resolveBackupDir(current && current.backupDir ? current.backupDir : defaultBackupDir()),
        lastRunAt: current && current.lastRunAt ? current.lastRunAt : null,
        update: {
            by: accountId || null,
            datetime: now
        }
    };
    payload.nextRunAt = nextRunDate(payload, now);
    return payload;
}

function sanitizeSettings(settings) {
    const source = settings || {};
    return {
        key: DEFAULT_KEY,
        autoEnabled: !!source.autoEnabled,
        intervalHours: clampNumber(source.intervalHours, DEFAULT_INTERVAL_HOURS, MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS),
        retentionCount: clampNumber(source.retentionCount, DEFAULT_RETENTION_COUNT, MIN_RETENTION_COUNT, MAX_RETENTION_COUNT),
        backupDir: resolveBackupDir(source.backupDir),
        lastRunAt: source.lastRunAt || null,
        nextRunAt: source.nextRunAt || null
    };
}

function sanitizeRun(run) {
    const source = run && typeof run.toObject === 'function' ? run.toObject() : (run || {});
    return {
        _id: source._id ? String(source._id) : '',
        mode: source.mode || 'manual',
        status: source.status || 'running',
        databaseName: source.databaseName || '',
        filename: source.filename || '',
        sizeBytes: Number(source.sizeBytes) || 0,
        checksum: source.checksum || '',
        collectionCount: Number(source.collectionCount) || 0,
        documentCount: Number(source.documentCount) || 0,
        collections: Array.isArray(source.collections) ? source.collections : [],
        error: source.error || '',
        startedAt: source.startedAt || null,
        completedAt: source.completedAt || null,
        downloadable: !!(source.status === 'completed' && source.filePath && fs.existsSync(source.filePath))
    };
}

function sanitizeCollectionPreview(item) {
    const source = item || {};
    return {
        name: source.name || '',
        type: source.type || 'collection',
        documentCount: Number(source.documentCount) || 0
    };
}

function sanitizeArchiveCollection(item) {
    const source = item || {};
    return {
        name: source.name || '',
        documentCount: Number(source.documentCount || source.count) || 0
    };
}

function isRestorableCollectionName(name) {
    const value = String(name || '').trim();
    return !!(value && value.indexOf('system.') !== 0 && value.indexOf('\0') === -1 && value.indexOf('$') === -1);
}

async function listRuns() {
    const runs = await DatabaseBackupRun.find({}).sort({ startedAt: -1 }).limit(50).lean();
    return runs.map(sanitizeRun);
}

function buildArchivePreview(run, archive) {
    const metadata = archive && archive.metadata ? archive.metadata : {};
    const collectionPayload = archive && archive.collections && typeof archive.collections === 'object'
        ? archive.collections
        : {};
    const metadataCollections = Array.isArray(metadata.collections) ? metadata.collections : null;
    const collections = metadataCollections
        ? metadataCollections.map(sanitizeArchiveCollection)
        : Object.keys(collectionPayload).map(function (name) {
            const docs = Array.isArray(collectionPayload[name]) ? collectionPayload[name] : [];
            return sanitizeArchiveCollection({ name: name, documentCount: docs.length });
        });

    return {
        run: sanitizeRun(run),
        metadata: {
            app: metadata.app || '',
            databaseName: metadata.databaseName || (run && run.databaseName) || '',
            mode: metadata.mode || (run && run.mode) || '',
            createdAt: metadata.createdAt || (run && run.completedAt) || null
        },
        collectionCount: collections.length,
        documentCount: collections.reduce(function (total, item) {
            return total + (Number(item.documentCount) || 0);
        }, 0),
        collections: collections
    };
}

async function findCompletedRun(id) {
    if (!id || !mongo.ObjectId.isValid(String(id))) {
        const err = new Error('backup_run_id_required');
        err.statusCode = 400;
        throw err;
    }
    const run = await DatabaseBackupRun.findOne({ _id: new mongo.ObjectId(String(id)) }).lean();
    if (!run) {
        const err = new Error('backup_not_found');
        err.statusCode = 404;
        throw err;
    }
    if (!(run.status === 'completed' && run.filePath && fs.existsSync(run.filePath))) {
        const err = new Error('backup_file_not_found');
        err.statusCode = 404;
        throw err;
    }
    return run;
}

async function readBackupArchive(run) {
    const buffer = await fs.promises.readFile(run.filePath);
    const raw = await gunzip(buffer);
    const archive = JSON.parse(raw.toString('utf8'));
    if (!(archive && archive.collections && typeof archive.collections === 'object')) {
        const err = new Error('backup_archive_invalid');
        err.statusCode = 422;
        throw err;
    }
    return archive;
}

async function listCollectionsPreview() {
    const db = mongoose.connection && mongoose.connection.db ? mongoose.connection.db : null;
    if (!db) {
        throw new Error('database_not_connected');
    }

    const collections = await db.listCollections().toArray();
    const previews = [];
    for (const item of collections) {
        const name = item && item.name ? String(item.name) : '';
        if (!name || name.indexOf('system.') === 0) continue;
        const collection = db.collection(name);
        const documentCount = await collection.estimatedDocumentCount().catch(function () {
            return 0;
        });
        previews.push(sanitizeCollectionPreview({
            name: name,
            type: item.type || 'collection',
            documentCount: documentCount
        }));
    }

    previews.sort(function (left, right) {
        return left.name.localeCompare(right.name);
    });

    return {
        generatedAt: new Date(),
        collectionCount: previews.length,
        documentCount: previews.reduce(function (total, item) {
            return total + (Number(item.documentCount) || 0);
        }, 0),
        collections: previews
    };
}

async function restoreBackupRun(run, accountId) {
    const db = mongoose.connection && mongoose.connection.db ? mongoose.connection.db : null;
    if (!db) {
        throw new Error('database_not_connected');
    }

    const archive = await readBackupArchive(run);
    const preview = buildArchivePreview(run, archive);
    let restoredCollections = 0;
    let restoredDocuments = 0;

    for (const name of Object.keys(archive.collections || {})) {
        if (!isRestorableCollectionName(name)) continue;
        const docs = Array.isArray(archive.collections[name]) ? archive.collections[name] : [];
        const collection = db.collection(name);
        await collection.deleteMany({});
        if (docs.length) {
            await collection.insertMany(docs, { ordered: false });
        }
        restoredCollections += 1;
        restoredDocuments += docs.length;
    }

    await DatabaseBackupRun.findOneAndUpdate({ _id: run._id }, {
        restore: {
            by: accountId || null,
            datetime: new Date(),
            collectionCount: restoredCollections,
            documentCount: restoredDocuments
        }
    }).catch(function () {});

    return Object.assign({}, preview, {
        restoredAt: new Date(),
        restoredCollections: restoredCollections,
        restoredDocuments: restoredDocuments
    });
}

async function adminPayload(settings) {
    return {
        settings: sanitizeSettings(settings || await ensureSettings(null)),
        runs: await listRuns(),
        active: !!activeBackup
    };
}

function settingsOnlyPayload(settings) {
    return {
        settings: sanitizeSettings(settings),
        active: !!activeBackup
    };
}

async function updateSchedule(settings) {
    if (autoTimer) {
        clearInterval(autoTimer);
        autoTimer = null;
    }
    const current = sanitizeSettings(settings);
    if (!current.autoEnabled) return;

    const intervalMs = current.intervalHours * 60 * 60 * 1000;
    autoTimer = setInterval(function () {
        createBackup('auto', null).catch(function (err) {
            console.error('Auto database backup failed:', err && err.message ? err.message : err);
        });
    }, intervalMs);
    if (autoTimer.unref) autoTimer.unref();
}

async function cleanupRetention(retentionCount, mode) {
    if (mode !== 'auto') return;
    const keep = clampNumber(retentionCount, DEFAULT_RETENTION_COUNT, MIN_RETENTION_COUNT, MAX_RETENTION_COUNT);
    const completed = await DatabaseBackupRun.find({ status: 'completed', mode: 'auto' }).sort({ completedAt: -1 }).skip(keep).lean();
    for (const run of completed) {
        if (run.filePath) {
            await fs.promises.unlink(run.filePath).catch(function () {});
        }
        await DatabaseBackupRun.deleteOne({ _id: run._id });
    }
}

async function readCollections(db) {
    const collections = await db.listCollections().toArray();
    const payload = {};
    const summaries = [];
    let documentCount = 0;

    for (const item of collections) {
        const name = item && item.name ? String(item.name) : '';
        if (!name || name.indexOf('system.') === 0) continue;
        const docs = await db.collection(name).find({}).toArray();
        payload[name] = docs;
        summaries.push({ name: name, count: docs.length });
        documentCount += docs.length;
    }

    return {
        collections: payload,
        summaries: summaries,
        documentCount: documentCount
    };
}

async function createBackup(mode, accountId) {
    if (activeBackup) {
        const err = new Error('backup_already_running');
        err.statusCode = 409;
        throw err;
    }

    const settings = sanitizeSettings(await ensureSettings(accountId));
    const backupDir = resolveBackupDir(settings.backupDir);
    const startedAt = new Date();
    const db = mongoose.connection && mongoose.connection.db ? mongoose.connection.db : null;
    if (!db) {
        throw new Error('database_not_connected');
    }

    await fs.promises.mkdir(backupDir, { recursive: true });
    const run = await DatabaseBackupRun.create({
        mode: mode || 'manual',
        status: 'running',
        databaseName: db.databaseName || '',
        backupDir: backupDir,
        startedAt: startedAt,
        create: {
            by: accountId || null,
            datetime: startedAt
        }
    });

    activeBackup = String(run._id);
    try {
        const snapshot = await readCollections(db);
        const filename = [
            'newSystem',
            sanitizeName(db.databaseName),
            timestampName(startedAt),
            String(run._id)
        ].join('-') + '.json.gz';
        const filePath = path.join(backupDir, filename);
        const archive = {
            metadata: {
                app: 'newSystem',
                databaseName: db.databaseName || '',
                mode: mode || 'manual',
                createdAt: startedAt.toISOString(),
                collections: snapshot.summaries
            },
            collections: snapshot.collections
        };
        const buffer = await gzip(Buffer.from(JSON.stringify(archive)));
        await fs.promises.writeFile(filePath, buffer);
        const checksum = crypto.createHash('sha256').update(buffer).digest('hex');
        const stat = await fs.promises.stat(filePath);
        const completedAt = new Date();

        const updatedRun = await DatabaseBackupRun.findOneAndUpdate({ _id: run._id }, {
            status: 'completed',
            filename: filename,
            filePath: filePath,
            sizeBytes: stat.size,
            checksum: checksum,
            collectionCount: snapshot.summaries.length,
            documentCount: snapshot.documentCount,
            collections: snapshot.summaries,
            completedAt: completedAt
        }, { new: true }).lean();

        await DatabaseBackup.findOneAndUpdate({ key: DEFAULT_KEY }, {
            lastRunAt: completedAt,
            nextRunAt: nextRunDate(settings, completedAt)
        });
        await cleanupRetention(settings.retentionCount, mode || 'manual');
        return sanitizeRun(updatedRun);
    } catch (err) {
        await DatabaseBackupRun.findOneAndUpdate({ _id: run._id }, {
            status: 'failed',
            error: err && err.message ? err.message : String(err),
            completedAt: new Date()
        });
        throw err;
    } finally {
        activeBackup = null;
    }
}

exports.primeAutoBackup = async function () {
    const settings = await ensureSettings(null);
    await updateSchedule(settings);
};

exports.onGet = async function (request, response) {
    try {
        const settings = await ensureSettings(null);
        return resMsg.sendResponse(response, 0, 20000, await adminPayload(settings));
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onCollections = async function (request, response) {
    try {
        return resMsg.sendResponse(response, 0, 20000, await listCollectionsPreview());
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onPreview = async function (request, response) {
    try {
        const id = request && request.params ? request.params.id : '';
        const run = await findCompletedRun(id);
        const archive = await readBackupArchive(run);
        return resMsg.sendResponse(response, 0, 20000, buildArchivePreview(run, archive));
    } catch (err) {
        return response.status(err.statusCode || 500).json({ status: false, error: err.message || 'backup_preview_failed' });
    }
};

exports.onRestore = async function (request, response) {
    try {
        const id = request && request.params ? request.params.id : '';
        const accountId = await resolveAccountId(request);
        const run = await findCompletedRun(id);
        return resMsg.sendResponse(response, 0, 20000, await restoreBackupRun(run, accountId));
    } catch (err) {
        return response.status(err.statusCode || 500).json({ status: false, error: err.message || 'backup_restore_failed' });
    }
};

exports.onUpdate = async function (request, response) {
    try {
        const accountId = await resolveAccountId(request);
        const current = await ensureSettings(accountId);
        const payload = settingsPayload(request.body || {}, current, accountId);
        const settings = await DatabaseBackup.findOneAndUpdate({ key: DEFAULT_KEY }, payload, { new: true, upsert: true }).lean();
        await updateSchedule(settings);
        return resMsg.sendResponse(response, 0, 20000, settingsOnlyPayload(settings));
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onRun = async function (request, response) {
    try {
        const accountId = await resolveAccountId(request);
        await createBackup('manual', accountId);
        return resMsg.sendResponse(response, 0, 20000, await adminPayload(await ensureSettings(accountId)));
    } catch (err) {
        if (err && err.statusCode === 409) {
            return response.status(409).json({ status: false, error: err.message });
        }
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onDelete = async function (request, response) {
    try {
        const id = request && request.params ? request.params.id : '';
        if (!id || !mongo.ObjectId.isValid(String(id))) {
            return response.status(400).json({ status: false, error: 'backup_run_id_required' });
        }
        const run = await DatabaseBackupRun.findOne({ _id: new mongo.ObjectId(String(id)) }).lean();
        if (!run) {
            return response.status(404).json({ status: false, error: 'backup_not_found' });
        }
        if (run.filePath) {
            await fs.promises.unlink(run.filePath).catch(function () {});
        }
        await DatabaseBackupRun.deleteOne({ _id: run._id });
        return resMsg.sendResponse(response, 0, 20000, await adminPayload(await ensureSettings(null)));
    } catch (err) {
        return resMsg.sendResponse(response, 0, 50000);
    }
};

exports.onDownload = async function (request, response) {
    try {
        const id = request && request.params ? request.params.id : '';
        if (!id || !mongo.ObjectId.isValid(String(id))) {
            return response.status(400).json({ status: false, error: 'backup_run_id_required' });
        }
        const run = await DatabaseBackupRun.findOne({ _id: new mongo.ObjectId(String(id)) }).lean();
        if (!(run && run.status === 'completed' && run.filePath && fs.existsSync(run.filePath))) {
            return response.status(404).json({ status: false, error: 'backup_file_not_found' });
        }
        return response.download(run.filePath, run.filename || path.basename(run.filePath));
    } catch (err) {
        return response.status(500).json({ status: false, error: 'backup_download_failed' });
    }
};

exports._private = {
    sanitizeSettings: sanitizeSettings,
    sanitizeRun: sanitizeRun,
    settingsPayload: settingsPayload,
    sanitizeCollectionPreview: sanitizeCollectionPreview,
    sanitizeArchiveCollection: sanitizeArchiveCollection,
    buildArchivePreview: buildArchivePreview,
    resolveBackupDir: resolveBackupDir,
    defaultBackupDir: defaultBackupDir
};
