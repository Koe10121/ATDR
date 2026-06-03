var objSchema = require('../models/lifecycle_position_rule.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'affiliationTypes', select: 'key title description state source isSystem version' },
    { path: 'accessProfiles', select: 'key title description defaultScope state source isSystem version' },
    { path: 'create.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' },
    { path: 'update.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
