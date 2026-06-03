'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { LocalizedValueSchema, attachLocalizedVirtuals } = require('./hr_master_shared.model');

const HrOrgUnitMasterSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    code: { type: String, default: null, index: true },
    title: [LocalizedValueSchema],
    description: [LocalizedValueSchema],
    orgGroup: { type: Schema.ObjectId, ref: 'Setting_HR_OrgGroupMaster', default: null },
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

attachLocalizedVirtuals(HrOrgUnitMasterSchema);
module.exports = mongoose.model('Setting_HR_OrgUnitMaster', HrOrgUnitMasterSchema, 'Setting_HR_OrgUnitMaster');
