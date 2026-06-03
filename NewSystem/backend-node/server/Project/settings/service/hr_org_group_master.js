'use strict';
const Controller = require('../controller/hr_org_group_master');
const HrOrgUnitMaster = require('../models/hr_org_unit_master.model');
const HrSubUnitMaster = require('../models/hr_sub_unit_master.model');
const HrWorkforceMaster = require('../models/hr_workforce_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { createHrMasterCrudService } = require('./hr_master_service');

module.exports = createHrMasterCrudService(Controller, {
    populate: [],
    dependencies: [
        { Model: HrOrgUnitMaster, field: 'orgGroup', label: 'HR Org Unit Master' },
        { Model: HrSubUnitMaster, field: 'orgGroup', label: 'HR Sub Unit Master' },
        { Model: HrWorkforceMaster, field: 'orgGroup', label: 'HR Workforce Master' },
        { Model: HrPositionMaster, field: 'orgGroup', label: 'HR Position Master' },
        { Model: HrIdentityMaster, field: 'orgGroup', label: 'HR Identity Master' }
    ]
});
