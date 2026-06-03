const objSchema = require('../models/hr_work_line_master.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, []);
