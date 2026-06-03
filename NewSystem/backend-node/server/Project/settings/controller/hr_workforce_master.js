const objSchema = require('../models/hr_workforce_master.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'workLine', select: 'key code title' },
    { path: 'personnelType', select: 'key code title' },
    { path: 'orgGroup', select: 'key title' },
    { path: 'employmentStatusMaster', select: 'key code title' },
    { path: 'suggestedAffiliation', select: 'key title' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
