'use strict';

const objSchema = require('../models/menu.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
  { path: 'type', select: 'title description' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
