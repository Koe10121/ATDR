'use strict';

const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var categorySchema = new Schema({
    title           : [{
        key            : {type: String, default: null},
        value          : {type: String, default: null},
    }],
    description     : [{
        key            : {type: String, default: null},
        value          : {type: String, default: null},
    }],

    password        : {type: String, default: null},
    status          : {type: Schema.ObjectId, ref: 'Setting_Status', default: '689c04cb255db4e56aea88ef' },
    create          : {
        by              : {type: Schema.ObjectId},
        datetime        : {type: Date, default: Date.now}
    },
});

var categoryModel = mongoose.model('Application_Category', categorySchema, 'Application_Category');
module.exports = categoryModel;
