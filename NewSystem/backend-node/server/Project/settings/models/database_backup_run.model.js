'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    mode: { type: String, default: 'manual', index: true },
    status: { type: String, default: 'running', index: true },
    databaseName: { type: String, default: '' },
    filename: { type: String, default: '' },
    filePath: { type: String, default: '' },
    backupDir: { type: String, default: '' },
    sizeBytes: { type: Number, default: 0 },
    checksum: { type: String, default: '' },
    collectionCount: { type: Number, default: 0 },
    documentCount: { type: Number, default: 0 },
    collections: [{
        name: { type: String, default: '' },
        count: { type: Number, default: 0 }
    }],
    error: { type: String, default: '' },
    startedAt: { type: Date, default: Date.now, index: true },
    completedAt: { type: Date, default: null },
    create: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: Date.now }
    }
});

module.exports = mongoose.model('Setting_DatabaseBackupRun', objsSchema, 'Setting_DatabaseBackupRun');
