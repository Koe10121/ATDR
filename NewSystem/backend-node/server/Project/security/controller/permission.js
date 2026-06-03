'use strict';

const objSchema = require('../models/permission.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
  { path: 'group', select: 'title description visibleType' },
  { path: 'menu', select: 'title description path type' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
