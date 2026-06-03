const objSchema = require('../models/hr_identity_master.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'degreeLevelMaster', select: 'key code title' },
    { path: 'employmentStatusMaster', select: 'key code title' },
    { path: 'workLine', select: 'key code title' },
    { path: 'personnelType', select: 'key code title' },
    { path: 'academicRank', select: 'key title' },
    { path: 'positionTitleMaster', select: 'key title' },
    { path: 'orgGroup', select: 'key title' },
    { path: 'orgUnitMaster', select: 'key code title' },
    { path: 'subUnitMaster', select: 'key title' },
    { path: 'workforceProfile', select: 'key workLineName personnelTypeName orgGroupName' },
    { path: 'positionMaster', select: 'positionCode positionTitle orgPath' },
    { path: 'suggestedAffiliation', select: 'key title' },
    { path: 'linkedAccount', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
