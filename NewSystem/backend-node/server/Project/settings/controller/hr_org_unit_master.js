const objSchema = require('../models/hr_org_unit_master.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, [
    { path: 'orgGroup', select: 'key title' }
]);
