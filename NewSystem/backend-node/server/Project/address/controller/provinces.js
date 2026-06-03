'use strict';

const mongo = require('mongodb');
const objSchema = require('../models/provinces.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'status', select: 'title description state' },
    { path: 'create.by', select: 'firstname lastname email' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
