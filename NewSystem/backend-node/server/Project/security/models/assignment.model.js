'use strict';

const mongoose = require('mongoose');
var Schema = mongoose.Schema;
const commonInterface = require('./common.interface');

var auditSchema = new Schema(commonInterface.getAuditInterface(Schema), { _id: false });

var securityAssignmentSchema = new Schema({
  account: { type: Schema.ObjectId, required: true },
  group: { type: Schema.ObjectId, ref: 'Security_Group', required: true },

  dataScope: {
    type: String,
    enum: ['self', 'unit', 'org'],
    default: 'self'
  },
  scopeUnits: [{ type: String }],

  active: { type: Boolean, default: true },

  created: {
    type: auditSchema,
    default: commonInterface.getCreatedDefault
  },
  updated: {
    type: auditSchema,
    default: commonInterface.getUpdatedDefault
  }
});

securityAssignmentSchema.index({ account: 1, group: 1 }, { unique: true });

var securityAssignmentModel = mongoose.model('Security_Assignment', securityAssignmentSchema, 'Security_Assignment');
module.exports = securityAssignmentModel;
