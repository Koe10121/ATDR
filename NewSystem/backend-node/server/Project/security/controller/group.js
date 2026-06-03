'use strict';

const objSchema = require('../models/group.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
  { path: 'visibleType', select: 'title description' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
