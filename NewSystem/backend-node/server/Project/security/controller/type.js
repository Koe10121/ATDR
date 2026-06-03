'use strict';

const objSchema = require('../models/type.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [];

module.exports = createBaseService(objSchema, defaultPopulate);
