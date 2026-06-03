const objSchema = require('../models/hr_position_master.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'workLine', select: 'key code title' },
    { path: 'personnelType', select: 'key code title' },
    { path: 'orgGroup', select: 'key title' },
    { path: 'orgUnitMaster', select: 'key code title' },
    { path: 'subUnitMaster', select: 'key title' },
    { path: 'degreeLevelMaster', select: 'key code title' },
    { path: 'employmentStatusMaster', select: 'key code title' },
    { path: 'academicRank', select: 'key title' },
    { path: 'positionTitleMaster', select: 'key title' },
    { path: 'workforceProfile', select: 'key workLineName personnelTypeName orgGroupName' },
    { path: 'orgUnit', select: 'key code title type level pathTitles' },
    { path: 'suggestedAffiliation', select: 'key title' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
