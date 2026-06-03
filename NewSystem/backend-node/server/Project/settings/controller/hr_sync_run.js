const objSchema = require('../models/hr_sync_run.model');
const createBaseService = require('../../../../helpers/base.service');

module.exports = createBaseService(objSchema, []);
