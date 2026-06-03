'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const HrWorkforceMasterSchema = new Schema({
    key: { type: String, default: null, index: true, unique: true },
    workLineCode: { type: String, default: null },
    workLineName: { type: String, default: null },
    workLine: { type: Schema.ObjectId, ref: 'Setting_HR_WorkLineMaster', default: null },
    personnelTypeCode: { type: String, default: null },
    personnelTypeName: { type: String, default: null },
    personnelType: { type: Schema.ObjectId, ref: 'Setting_HR_PersonnelTypeMaster', default: null },
    orgGroupName: { type: String, default: null },
    orgGroup: { type: Schema.ObjectId, ref: 'Setting_HR_OrgGroupMaster', default: null },
    employmentStatus: { type: String, default: null },
    employmentStatusMaster: { type: Schema.ObjectId, ref: 'Setting_HR_EmploymentStatusMaster', default: null },
    suggestedAffiliation: { type: Schema.ObjectId, ref: 'Setting_Lifecycle_AffiliationType', default: null },
    source: { type: String, default: 'HR_IMPORT' },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

module.exports = mongoose.model('Setting_HR_WorkforceMaster', HrWorkforceMasterSchema, 'Setting_HR_WorkforceMaster');
