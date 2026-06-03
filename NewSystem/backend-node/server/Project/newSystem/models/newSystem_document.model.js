'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const auditSchema = new Schema({
  by: { type: Schema.ObjectId, default: null },
  name: { type: String, default: null },
  email: { type: String, default: null },
  datetime: { type: Date, default: Date.now }
}, { _id: false });

const newSystemDocumentSchema = new Schema({
  newSystemNo: { type: String, trim: true, required: true, index: true },
  title: { type: String, trim: true, required: true },
  partnerName: { type: String, trim: true, required: true, index: true },
  partnerType: { type: String, trim: true, default: 'University' },
  country: { type: String, trim: true, default: 'Thailand' },
  ownerUnit: { type: String, trim: true, default: null },
  coordinatorName: { type: String, trim: true, default: null },
  coordinatorEmail: { type: String, trim: true, lowercase: true, default: null },
  status: {
    type: String,
    enum: ['draft', 'review', 'active', 'expiring', 'expired', 'archived'],
    default: 'draft',
    index: true
  },
  effectiveDate: { type: Date, default: null },
  expiryDate: { type: Date, default: null, index: true },
  renewalNoticeDate: { type: Date, default: null },
  documentUrl: { type: String, trim: true, default: null },
  tags: [{ type: String, trim: true }],
  notes: { type: String, trim: true, default: null },
  create: { type: auditSchema, default: () => ({}) },
  update: { type: auditSchema, default: null }
}, {
  timestamps: true
});

newSystemDocumentSchema.index({ newSystemNo: 1 }, { unique: true });
newSystemDocumentSchema.index({ title: 'text', partnerName: 'text', ownerUnit: 'text', tags: 'text' });

module.exports = mongoose.model('NewSystem_Document', newSystemDocumentSchema, 'NewSystem_Document');
