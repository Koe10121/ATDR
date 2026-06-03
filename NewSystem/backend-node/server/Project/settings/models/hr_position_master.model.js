'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const HrPositionMasterSchema = new Schema({
    positionCode: { type: String, default: null, index: true, unique: true },
    positionStatus: { type: String, default: null },
    positionTitle: { type: String, default: null },
    academicTitle: { type: String, default: null },
    workLineCode: { type: String, default: null },
    workLineName: { type: String, default: null },
    workLine: { type: Schema.ObjectId, ref: 'Setting_HR_WorkLineMaster', default: null },
    personnelTypeCode: { type: String, default: null },
    personnelTypeName: { type: String, default: null },
    personnelType: { type: Schema.ObjectId, ref: 'Setting_HR_PersonnelTypeMaster', default: null },
    orgGroupName: { type: String, default: null },
    orgGroup: { type: Schema.ObjectId, ref: 'Setting_HR_OrgGroupMaster', default: null },
    orgUnitCode: { type: String, default: null },
    orgUnitName: { type: String, default: null },
    orgUnitMaster: { type: Schema.ObjectId, ref: 'Setting_HR_OrgUnitMaster', default: null },
    orgSubUnitName: { type: String, default: null },
    subUnitMaster: { type: Schema.ObjectId, ref: 'Setting_HR_SubUnitMaster', default: null },
    orgPath: [{ type: String, default: null }],
    degreeLevelName: { type: String, default: null },
    degreeLevelMaster: { type: Schema.ObjectId, ref: 'Setting_HR_DegreeLevelMaster', default: null },
    employmentStatusName: { type: String, default: null },
    employmentStatusMaster: { type: Schema.ObjectId, ref: 'Setting_HR_EmploymentStatusMaster', default: null },
    academicRank: { type: Schema.ObjectId, ref: 'Setting_HR_AcademicRankMaster', default: null },
    positionTitleMaster: { type: Schema.ObjectId, ref: 'Setting_HR_PositionTitleMaster', default: null },
    workforceProfile: { type: Schema.ObjectId, ref: 'Setting_HR_WorkforceMaster', default: null },
    orgUnit: { type: Schema.ObjectId, ref: 'Setting_HR_OrgUnit', default: null },
    suggestedAffiliation: { type: Schema.ObjectId, ref: 'Setting_Lifecycle_AffiliationType', default: null },
    isOpen: { type: Boolean, default: true },
    source: { type: String, default: 'HR_IMPORT' }
}, { timestamps: true });

module.exports = mongoose.model('Setting_HR_PositionMaster', HrPositionMasterSchema, 'Setting_HR_PositionMaster');
