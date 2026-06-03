const objSchema = require('../models/hr_position_title_master.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, []);
