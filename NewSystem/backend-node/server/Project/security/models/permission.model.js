'use strict';

const mongoose = require('mongoose');
var Schema = mongoose.Schema;
const commonInterface = require('./common.interface');

var auditSchema = new Schema(commonInterface.getAuditInterface(Schema), { _id: false });

var securityPermissionSchema = new Schema({
  group: { type: Schema.ObjectId, ref: 'Security_Group', required: true },
  menu: { type: Schema.ObjectId, ref: 'Security_Menu', required: true },

  all: { type: Boolean, default: false },
  view: { type: Boolean, default: false },
  edit: { type: Boolean, default: false },
  delete: { type: Boolean, default: false },
  action: { type: Boolean, default: false },
  logs: { type: Boolean, default: false },

  created: {
    type: auditSchema,
    default: commonInterface.getCreatedDefault
  },
  updated: {
    type: auditSchema,
    default: commonInterface.getUpdatedDefault
  }
});

securityPermissionSchema.index({ group: 1, menu: 1 }, { unique: true });

var securityPermissionModel = mongoose.model('Security_Permission', securityPermissionSchema, 'Security_Permission');
module.exports = securityPermissionModel;
