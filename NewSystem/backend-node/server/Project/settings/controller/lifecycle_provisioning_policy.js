var objSchema = require('../models/lifecycle_provisioning_policy.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'affiliationType', select: 'key title description state source isSystem version' },
    { path: 'defaultAccessProfiles', select: 'key title description defaultScope state source isSystem version' },
    { path: 'defaultTargetStatus', select: 'key title description state' },
    { path: 'create.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' },
    { path: 'update.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
