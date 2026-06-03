var objSchema = require('../models/auth_message.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'status', select: 'key title state' },
    { path: 'create.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' },
    { path: 'update.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
