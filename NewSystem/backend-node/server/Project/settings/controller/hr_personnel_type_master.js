const objSchema = require('../models/hr_personnel_type_master.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, []);
