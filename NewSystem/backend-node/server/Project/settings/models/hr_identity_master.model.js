'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const HrIdentityMasterSchema = new Schema({
    identityKey: { type: String, default: null, index: true, unique: true },
    personnelCode: { type: String, default: null, index: true },
    positionCode: { type: String, default: null },
    prefix: { type: String, default: null },
    firstName: { type: String, default: null },
    lastName: { type: String, default: null },
    fullName: { type: String, default: null },
    gender: { type: String, default: null },
    age: { type: String, default: null },
    degreeLevelName: { type: String, default: null },
    degreeLevelMaster: { type: Schema.ObjectId, ref: 'Setting_HR_DegreeLevelMaster', default: null },
    province: { type: String, default: null },
    generation: { type: String, default: null },
    tenureGroup: { type: String, default: null },
    tenureYears: { type: String, default: null },
    employmentStatusName: { type: String, default: null },
    employmentStatusMaster: { type: Schema.ObjectId, ref: 'Setting_HR_EmploymentStatusMaster', default: null },
    workLineName: { type: String, default: null },
    workLine: { type: Schema.ObjectId, ref: 'Setting_HR_WorkLineMaster', default: null },
    personnelTypeName: { type: String, default: null },
    personnelType: { type: Schema.ObjectId, ref: 'Setting_HR_PersonnelTypeMaster', default: null },
    positionTitle: { type: String, default: null },
    positionTitleMaster: { type: Schema.ObjectId, ref: 'Setting_HR_PositionTitleMaster', default: null },
    academicTitle: { type: String, default: null },
    academicRank: { type: Schema.ObjectId, ref: 'Setting_HR_AcademicRankMaster', default: null },
    orgGroupName: { type: String, default: null },
    orgGroup: { type: Schema.ObjectId, ref: 'Setting_HR_OrgGroupMaster', default: null },
    orgUnitName: { type: String, default: null },
    orgUnitMaster: { type: Schema.ObjectId, ref: 'Setting_HR_OrgUnitMaster', default: null },
    subUnitName: { type: String, default: null },
    subUnitMaster: { type: Schema.ObjectId, ref: 'Setting_HR_SubUnitMaster', default: null },
    orgPath: [{ type: String, default: null }],
    workforceProfile: { type: Schema.ObjectId, ref: 'Setting_HR_WorkforceMaster', default: null },
    positionMaster: { type: Schema.ObjectId, ref: 'Setting_HR_PositionMaster', default: null },
    suggestedAffiliation: { type: Schema.ObjectId, ref: 'Setting_Lifecycle_AffiliationType', default: null },
    linkedAccount: { type: Schema.ObjectId, default: null },
    vacancy: { type: Boolean, default: false },
    source: { type: String, default: 'HR_IMPORT' }
}, { timestamps: true });

module.exports = mongoose.model('Setting_HR_IdentityMaster', HrIdentityMasterSchema, 'Setting_HR_IdentityMaster');
