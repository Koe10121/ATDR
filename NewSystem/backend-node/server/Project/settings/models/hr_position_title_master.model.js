'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { LocalizedValueSchema, attachLocalizedVirtuals } = require('./hr_master_shared.model');

const HrPositionTitleMasterSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    title: [LocalizedValueSchema],
    description: [LocalizedValueSchema],
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

attachLocalizedVirtuals(HrPositionTitleMasterSchema);
module.exports = mongoose.model('Setting_HR_PositionTitleMaster', HrPositionTitleMasterSchema, 'Setting_HR_PositionTitleMaster');
