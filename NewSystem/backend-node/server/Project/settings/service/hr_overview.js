'use strict';

const HrOrgUnit = require('../models/hr_org_unit.model');
const HrOrgGroupMaster = require('../models/hr_org_group_master.model');
const HrOrgUnitMaster = require('../models/hr_org_unit_master.model');
const HrSubUnitMaster = require('../models/hr_sub_unit_master.model');
const HrDegreeLevelMaster = require('../models/hr_degree_level_master.model');
const HrEmploymentStatusMaster = require('../models/hr_employment_status_master.model');
const HrWorkLineMaster = require('../models/hr_work_line_master.model');
const HrPersonnelTypeMaster = require('../models/hr_personnel_type_master.model');
const HrAcademicRankMaster = require('../models/hr_academic_rank_master.model');
const HrPositionTitleMaster = require('../models/hr_position_title_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrWorkforceMaster = require('../models/hr_workforce_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const HrSyncRun = require('../models/hr_sync_run.model');
const resMsg = require('./message');

exports.onOverview = async function (request, response) {
    try {
        const [orgUnitCount, orgGroupCount, orgUnitMasterCount, subUnitCount, degreeLevelCount, employmentStatusCount, workLineCount, personnelTypeCount, academicRankCount, positionTitleCount, positionCount, workforceCount, identityCount, lastRun] = await Promise.all([
            HrOrgUnit.countDocuments({}),
            HrOrgGroupMaster.countDocuments({}),
            HrOrgUnitMaster.countDocuments({}),
            HrSubUnitMaster.countDocuments({}),
            HrDegreeLevelMaster.countDocuments({}),
            HrEmploymentStatusMaster.countDocuments({}),
            HrWorkLineMaster.countDocuments({}),
            HrPersonnelTypeMaster.countDocuments({}),
            HrAcademicRankMaster.countDocuments({}),
            HrPositionTitleMaster.countDocuments({}),
            HrPositionMaster.countDocuments({}),
            HrWorkforceMaster.countDocuments({}),
            HrIdentityMaster.countDocuments({}),
            HrSyncRun.findOne({}).sort({ createdAt: -1 }).lean()
        ]);
        const resData = await resMsg.onMessage_Response(0, 20000);
        resData.data = {
            orgUnitCount: orgUnitCount,
            orgGroupCount: orgGroupCount,
            orgUnitMasterCount: orgUnitMasterCount,
            subUnitCount: subUnitCount,
            degreeLevelCount: degreeLevelCount,
            employmentStatusCount: employmentStatusCount,
            workLineCount: workLineCount,
            personnelTypeCount: personnelTypeCount,
            academicRankCount: academicRankCount,
            positionTitleCount: positionTitleCount,
            positionCount: positionCount,
            workforceCount: workforceCount,
            identityCount: identityCount,
            lastRun: lastRun || null
        };
        return response.status(200).json(resData);
    } catch (err) {
        const resData = await resMsg.onMessage_Response(0, 50000);
        return response.status(500).json(resData);
    }
};
