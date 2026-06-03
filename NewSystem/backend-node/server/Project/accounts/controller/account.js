'use strict';

const mongo = require('mongodb');
const objSchema = require('../models/account.model');
const createBaseService = require('../../../../helpers/base.service');

const defaultPopulate = [];

module.exports = createBaseService(objSchema, defaultPopulate);
