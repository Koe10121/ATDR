'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    key: { type: String, default: 'default', unique: true },
    enabled: { type: Boolean, default: true },
    activeTemplates: [{ type: String }],
    appName: { type: String, default: 'NewSystem' },
    appUrl: { type: String, default: '' },
    from: { type: String, default: '' },
    fromName: { type: String, default: 'NewSystem' },
    smtp: {
        host: { type: String, default: '' },
        port: { type: Number, default: 587 },
        secure: { type: Boolean, default: false },
        user: { type: String, default: '' },
        pass: { type: String, default: '' }
    },
    invite: {
        subject: { type: String, default: '' },
        text: { type: String, default: '' },
        html: { type: String, default: '' }
    },
    twoFa: {
        subject: { type: String, default: '' },
        text: { type: String, default: '' },
        html: { type: String, default: '' }
    },
    create: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: Date.now }
    },
    update: {
        by: { type: mongoose.Schema.Types.ObjectId, ref: 'Information_Accounts' },
        datetime: { type: Date, default: null }
    }
});

module.exports = mongoose.model('Setting_EmailNotification', objsSchema, 'Setting_EmailNotification');
