'use strict';

const mongoose = require('mongoose');
var Schema = mongoose.Schema;
const commonInterface = require('./common.interface');

var multiLanguageSchema = new Schema(commonInterface.multiLanguageInterface, { _id: false });
var auditSchema = new Schema(commonInterface.getAuditInterface(Schema), { _id: false });

var securityTypeSchema = new Schema({
  title: [multiLanguageSchema],
  description: [multiLanguageSchema],
  state: { type: Boolean, default: true },

  created: {
    type: auditSchema,
    default: commonInterface.getCreatedDefault
  },
  updated: {
    type: auditSchema,
    default: commonInterface.getUpdatedDefault
  }
});

var securityTypeModel = mongoose.model('Security_Type', securityTypeSchema, 'Security_Type');
module.exports = securityTypeModel;
