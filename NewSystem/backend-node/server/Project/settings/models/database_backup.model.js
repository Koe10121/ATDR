'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    key: { type: String, default: 'default', unique: true },
    autoEnabled: { type: Boolean, default: false },
    intervalHours: { type: Number, default: 24 },
    retentionCount: { type: Number, default: 10 },
    backupDir: { type: String, default: '' },
    lastRunAt: { type: Date, default: null },
    nextRunAt: { type: Date, default: null },
    create: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: Date.now }
    },
    update: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: null }
    }
});

module.exports = mongoose.model('Setting_DatabaseBackup', objsSchema, 'Setting_DatabaseBackup');
