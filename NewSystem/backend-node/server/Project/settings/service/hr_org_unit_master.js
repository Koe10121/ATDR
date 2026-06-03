'use strict';
const Controller = require('../controller/hr_org_unit_master');
const HrSubUnitMaster = require('../models/hr_sub_unit_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { createHrMasterCrudService, buildBasePayload } = require('./hr_master_service');
const { normalizeString, pickLangValue } = require('./hr_shared');

module.exports = createHrMasterCrudService(Controller, {
    populate: [{ path: 'orgGroup', select: 'key title description' }],
    buildPayload: function (body) {
        const payload = buildBasePayload(body);
        const titleText = pickLangValue(payload.title);
        payload.orgGroup = normalizeString(body && (body.orgGroup || body.orgGroupId)) || null;
        payload.key = normalizeString(body && body.key) || [normalizeString(body && body.orgGroupKey), titleText]
            .filter(Boolean)
            .join(':')
            .toLowerCase()
            .replace(/[^a-z0-9\u0E00-\u0E7F:]+/g, '-');
        return payload;
    },
    dependencies: [
        { Model: HrSubUnitMaster, field: 'orgUnit', label: 'HR Sub Unit Master' },
        { Model: HrPositionMaster, field: 'orgUnitMaster', label: 'HR Position Master' },
        { Model: HrIdentityMaster, field: 'orgUnitMaster', label: 'HR Identity Master' }
    ]
});
