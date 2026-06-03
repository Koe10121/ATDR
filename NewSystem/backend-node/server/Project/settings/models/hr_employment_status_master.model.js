'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { LocalizedValueSchema, attachLocalizedVirtuals } = require('./hr_master_shared.model');

const HrEmploymentStatusMasterSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    code: { type: String, default: null, index: true },
    title: [LocalizedValueSchema],
    description: [LocalizedValueSchema],
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

attachLocalizedVirtuals(HrEmploymentStatusMasterSchema);
module.exports = mongoose.model('Setting_HR_EmploymentStatusMaster', HrEmploymentStatusMasterSchema, 'Setting_HR_EmploymentStatusMaster');
