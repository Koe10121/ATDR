'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

var auditEventSchema = new Schema({
    module: { type: String, required: true, trim: true },
    action: { type: String, required: true, trim: true },
    actorType: { type: String, default: null },
    actorId: { type: String, default: null },
    targetId: { type: String, default: null },
    resourceType: { type: String, default: null },
    resourceId: { type: String, default: null },
    detail: { type: Schema.Types.Mixed, default: null },
    meta: { type: Schema.Types.Mixed, default: null },
    ip: { type: String, default: null },
    userAgent: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
}, {
    versionKey: false
});

auditEventSchema.index({ module: 1, action: 1, createdAt: -1 });
auditEventSchema.index({ actorId: 1, createdAt: -1 });
auditEventSchema.index({ resourceId: 1, createdAt: -1 });

module.exports = mongoose.model('Security_AuditEvent', auditEventSchema, 'Security_AuditEvent');
