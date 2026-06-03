'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    ip: { type: String, required: true, unique: true, index: true },
    source: { type: String, default: 'rate-limit' },
    reason: { type: String, default: 'rate-limit' },
    method: { type: String, default: '' },
    path: { type: String, default: '' },
    origin: { type: String, default: '' },
    message: { type: String, default: '' },
    blockedAt: { type: Date, default: Date.now, index: true },
    expiresAt: { type: Date, required: true, index: true },
    revokedAt: { type: Date, default: null, index: true },
    revokedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts', default: null },
    revokeReason: { type: String, default: '' }
}, {
    timestamps: true
});

module.exports = mongoose.model('Setting_RuntimeAccessBlockedIp', objsSchema, 'Setting_RuntimeAccessBlockedIp');
