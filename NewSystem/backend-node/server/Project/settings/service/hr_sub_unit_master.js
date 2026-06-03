'use strict';
const Controller = require('../controller/hr_sub_unit_master');
const HrPositionMaster = require('../models/hr_position_master.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const { createHrMasterCrudService, buildBasePayload } = require('./hr_master_service');
const { normalizeString, pickLangValue } = require('./hr_shared');

module.exports = createHrMasterCrudService(Controller, {
    populate: [
        { path: 'orgGroup', select: 'key title description' },
        { path: 'orgUnit', select: 'key code title description orgGroup' }
    ],
    buildPayload: function (body) {
        const payload = buildBasePayload(body);
        const titleText = pickLangValue(payload.title);
        payload.orgGroup = normalizeString(body && (body.orgGroup || body.orgGroupId)) || null;
        payload.orgUnit = normalizeString(body && (body.orgUnit || body.orgUnitId)) || null;
        payload.key = normalizeString(body && body.key) || [normalizeString(body && body.orgGroupKey), normalizeString(body && body.orgUnitKey), titleText]
            .filter(Boolean)
            .join(':')
            .toLowerCase()
            .replace(/[^a-z0-9\u0E00-\u0E7F:]+/g, '-');
        return payload;
    },
    dependencies: [
        { Model: HrPositionMaster, field: 'subUnitMaster', label: 'HR Position Master' },
        { Model: HrIdentityMaster, field: 'subUnitMaster', label: 'HR Identity Master' }
    ]
});
