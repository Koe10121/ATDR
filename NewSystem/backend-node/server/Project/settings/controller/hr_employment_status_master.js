const objSchema = require('../models/hr_employment_status_master.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, []);
