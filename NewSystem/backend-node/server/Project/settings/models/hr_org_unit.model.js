'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const LocalizedValueSchema = new Schema({
    key: { type: String, default: null },
    value: { type: String, default: null }
}, { _id: false });

const HrOrgUnitSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    code: { type: String, default: null },
    title: [LocalizedValueSchema],
    type: { type: String, default: 'unit' },
    level: { type: Number, default: 0 },
    parent: { type: Schema.ObjectId, ref: 'Setting_HR_OrgUnit', default: null },
    pathKeys: [{ type: String, default: null }],
    pathTitles: [{ type: String, default: null }],
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

module.exports = mongoose.model('Setting_HR_OrgUnit', HrOrgUnitSchema, 'Setting_HR_OrgUnit');
