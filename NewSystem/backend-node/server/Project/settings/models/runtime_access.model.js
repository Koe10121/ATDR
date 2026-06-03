'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    key: { type: String, default: 'default', unique: true },
    trustProxy: { type: Boolean, default: false },
    rateLimitEnabled: { type: Boolean, default: true },
    corsAllowedOrigins: [{ type: String }],
    socketCorsOrigins: [{ type: String }],
    allowedIPs: [{ type: String }],
    create: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: Date.now }
    },
    update: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: null }
    }
});

module.exports = mongoose.model('Setting_RuntimeAccess', objsSchema, 'Setting_RuntimeAccess');
