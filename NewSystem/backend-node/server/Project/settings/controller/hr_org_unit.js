const objSchema = require('../models/hr_org_unit.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, []);
