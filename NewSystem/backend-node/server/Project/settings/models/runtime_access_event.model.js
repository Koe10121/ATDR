'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var RETENTION_DAYS = Number(process.env.RUNTIME_ACCESS_EVENT_RETENTION_DAYS || 30);
if (!Number.isFinite(RETENTION_DAYS) || RETENTION_DAYS <= 0) {
    RETENTION_DAYS = 30;
}

var objsSchema = new Schema({
    occurredAt: { type: Date, default: Date.now, index: true },
    source: { type: String, default: 'runtime-access' },
    type: { type: String, default: 'event' },
    decision: { type: String, default: 'observe' },
    ip: { type: String, default: '', index: true },
    method: { type: String, default: '' },
    path: { type: String, default: '' },
    origin: { type: String, default: '' },
    statusCode: { type: Number, default: null },
    message: { type: String, default: '' },
    detail: { type: Schema.Types.Mixed, default: null }
}, {
    timestamps: true
});

objsSchema.index({ occurredAt: 1 }, { expireAfterSeconds: RETENTION_DAYS * 24 * 60 * 60 });

module.exports = mongoose.model('Setting_RuntimeAccessEvent', objsSchema, 'Setting_RuntimeAccessEvent');
