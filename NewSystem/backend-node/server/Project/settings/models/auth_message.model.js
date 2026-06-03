'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    title: [{
        key: { type: String, default: null },
        value: { type: String, default: null },
    }],
    description: [{
        key: { type: String, default: null },
        value: { type: String, default: null },
    }],
    startDate: { type: Date, default: null },
    endDate: { type: Date, default: null },
    status: { type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Status', default: null },
    create: {
        by: { type: mongoose.Schema.Types.ObjectId },
        datetime: { type: Date, default: Date.now }
    },
    update: {
        by: { type: mongoose.Schema.Types.ObjectId },
        datetime: { type: Date, default: null }
    },
});

module.exports = mongoose.model('Setting_AuthMessage', objsSchema, 'Setting_AuthMessage');
