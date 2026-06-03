'use strict';
const Controller = require('../controller/hr_academic_rank_master');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { createHrMasterCrudService } = require('./hr_master_service');

module.exports = createHrMasterCrudService(Controller, {
    populate: [],
    dependencies: [
        { Model: HrPositionMaster, field: 'academicRank', label: 'HR Position Master' },
        { Model: HrIdentityMaster, field: 'academicRank', label: 'HR Identity Master' }
    ]
});
