'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { LocalizedValueSchema, attachLocalizedVirtuals } = require('./hr_master_shared.model');

const HrDegreeLevelMasterSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    code: { type: String, default: null, index: true },
    title: [LocalizedValueSchema],
    description: [LocalizedValueSchema],
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

attachLocalizedVirtuals(HrDegreeLevelMasterSchema);
module.exports = mongoose.model('Setting_HR_DegreeLevelMaster', HrDegreeLevelMasterSchema, 'Setting_HR_DegreeLevelMaster');
