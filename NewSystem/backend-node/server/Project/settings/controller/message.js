var mongo = require('mongodb');
var objSchema = require('../models/message.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'create.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' },
    { path: 'update.by', select: 'code email userinfo.prefix userinfo.firstName userinfo.lastName' }
];
module.exports = createBaseService(objSchema, defaultPopulate);
