'use strict';
const Controller = require('../controller/hr_personnel_type_master');
const HrWorkforceMaster = require('../models/hr_workforce_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { createHrMasterCrudService } = require('./hr_master_service');

module.exports = createHrMasterCrudService(Controller, {
    populate: [],
    dependencies: [
        { Model: HrWorkforceMaster, field: 'personnelType', label: 'HR Workforce Master' },
        { Model: HrPositionMaster, field: 'personnelType', label: 'HR Position Master' },
        { Model: HrIdentityMaster, field: 'personnelType', label: 'HR Identity Master' }
    ]
});
