'use strict';

const mongoose = require('mongoose');
var Schema = mongoose.Schema;
const commonInterface = require('./common.interface');

var multiLanguageSchema = new Schema(commonInterface.multiLanguageInterface, { _id: false });
var auditSchema = new Schema(commonInterface.getAuditInterface(Schema), { _id: false });

var securityMenuSchema = new Schema({
  title: [multiLanguageSchema],
  description: [multiLanguageSchema],
  state: { type: Boolean, default: true },
  path: { type: String, required: true, trim: true, unique: true },
  type: { type: Schema.ObjectId, ref: 'Security_Type', required: true },

  created: {
    type: auditSchema,
    default: commonInterface.getCreatedDefault
  },
  updated: {
    type: auditSchema,
    default: commonInterface.getUpdatedDefault
  }
});

var securityMenuModel = mongoose.model('Security_Menu', securityMenuSchema, 'Security_Menu');
module.exports = securityMenuModel;
