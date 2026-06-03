'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { LocalizedValueSchema, attachLocalizedVirtuals } = require('./hr_master_shared.model');

const HrAcademicRankMasterSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    title: [LocalizedValueSchema],
    description: [LocalizedValueSchema],
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

attachLocalizedVirtuals(HrAcademicRankMasterSchema);
module.exports = mongoose.model('Setting_HR_AcademicRankMaster', HrAcademicRankMasterSchema, 'Setting_HR_AcademicRankMaster');
