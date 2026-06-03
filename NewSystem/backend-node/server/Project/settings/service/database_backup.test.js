'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const databaseBackupService = require('./database_backup');

test('database backup settings payload clamps scheduler values and keeps storage server-owned', function () {
    const current = {
        autoEnabled: false,
        intervalHours: 24,
        retentionCount: 10,
        backupDir: '/srv/newSystem/backups',
        lastRunAt: '2026-05-10T12:00:00.000Z'
    };

    const payload = databaseBackupService._private.settingsPayload({
        autoEnabled: true,
        intervalHours: 9999,
        retentionCount: 0,
        backupDir: '/tmp/user-controlled'
    }, current, null);

    assert.equal(payload.autoEnabled, true);
    assert.equal(payload.intervalHours, 720);
    assert.equal(payload.retentionCount, 1);
    assert.equal(payload.backupDir, '/srv/newSystem/backups');
    assert.equal(payload.lastRunAt, current.lastRunAt);
    assert.ok(payload.nextRunAt instanceof Date);
});

test('database backup run sanitizer hides file path and marks downloadable files', function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'newSystem-backup-test-'));
    const filePath = path.join(tempDir, 'backup.json.gz');
    fs.writeFileSync(filePath, 'backup');

    try {
        const payload = databaseBackupService._private.sanitizeRun({
            _id: 'backup-run-1',
            status: 'completed',
            filePath,
            filename: 'backup.json.gz',
            sizeBytes: 6,
            collectionCount: 2,
            documentCount: 4
        });

        assert.equal(payload.downloadable, true);
        assert.equal(payload.filePath, undefined);
        assert.equal(payload.filename, 'backup.json.gz');
        assert.equal(payload.sizeBytes, 6);
        assert.equal(payload.collectionCount, 2);
        assert.equal(payload.documentCount, 4);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test('database backup collection preview sanitizer exposes names and counts only', function () {
    const payload = databaseBackupService._private.sanitizeCollectionPreview({
        name: 'NewSystem_Documents',
        type: 'collection',
        documentCount: '42',
        sampleDocument: { cardNumber: 'hidden' }
    });

    assert.deepEqual(payload, {
        name: 'NewSystem_Documents',
        type: 'collection',
        documentCount: 42
    });
});

test('database backup archive preview summarizes backup file metadata', function () {
    const payload = databaseBackupService._private.buildArchivePreview({
        _id: 'backup-run-1',
        mode: 'manual',
        status: 'completed',
        databaseName: 'newSystem-test'
    }, {
        metadata: {
            app: 'newSystem',
            databaseName: 'newSystem-test',
            mode: 'manual',
            createdAt: '2026-05-11T00:00:00.000Z',
            collections: [
                { name: 'users', count: 3 },
                { name: 'newSystem_documents', count: 4 }
            ]
        },
        collections: {
            users: [{}, {}, {}],
            newSystem_documents: [{}, {}, {}, {}]
        }
    });

    assert.equal(payload.metadata.app, 'newSystem');
    assert.equal(payload.collectionCount, 2);
    assert.equal(payload.documentCount, 7);
    assert.deepEqual(payload.collections, [
        { name: 'users', documentCount: 3 },
        { name: 'newSystem_documents', documentCount: 4 }
    ]);
});
