'use strict';

const mongo = require('mongodb');
const objSchema = require('../models/sub-districts.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'province', select: 'title description code' },
    { path: 'district', select: 'title description code' },
    { path: 'status', select: 'title description state' },
    { path: 'create.by', select: 'firstname lastname email' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
