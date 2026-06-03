'use strict';

const objSchema = require('../models/assignment.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [
  { path: 'account', select: 'email code userinfo.firstName userinfo.lastName' },
  { path: 'group', select: 'title description visibleType' }
];

module.exports = createBaseService(objSchema, defaultPopulate);
