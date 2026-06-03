'use strict';

const events = require('events');
const mongoose = require('mongoose');
const configureMongoose = require('../helpers/configure-mongoose');

events.setMaxListeners(25);
configureMongoose(mongoose);
