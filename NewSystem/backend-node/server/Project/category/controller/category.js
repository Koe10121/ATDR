'use strict';

const mongo = require('mongodb');
const objSchema = require('../models/category.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
    { path: 'status', select: 'title description' },
    { path: 'create.by', select: 'firstname lastname email' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
