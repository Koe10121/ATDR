'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const HrSyncRunSchema = new Schema({
    sourceFile: { type: String, default: null },
    sourceSheet: { type: String, default: null },
    sourceTimestamp: { type: Date, default: null },
    status: { type: String, default: 'COMPLETED' },
    rowCount: { type: Number, default: 0 },
    orgUnitCount: { type: Number, default: 0 },
    positionCount: { type: Number, default: 0 },
    workforceCount: { type: Number, default: 0 },
    identityCount: { type: Number, default: 0 },
    orgGroupCount: { type: Number, default: 0 },
    orgUnitMasterCount: { type: Number, default: 0 },
    subUnitCount: { type: Number, default: 0 },
    degreeLevelCount: { type: Number, default: 0 },
    employmentStatusCount: { type: Number, default: 0 },
    workLineCount: { type: Number, default: 0 },
    personnelTypeCount: { type: Number, default: 0 },
    academicRankCount: { type: Number, default: 0 },
    positionTitleCount: { type: Number, default: 0 },
    matchedAccountCount: { type: Number, default: 0 },
    unmatchedAccountCount: { type: Number, default: 0 },
    warnings: [{ type: String, default: null }],
    summary: { type: Schema.Types.Mixed, default: {} }
}, { timestamps: true });

module.exports = mongoose.model('Setting_HR_SyncRun', HrSyncRunSchema, 'Setting_HR_SyncRun');
