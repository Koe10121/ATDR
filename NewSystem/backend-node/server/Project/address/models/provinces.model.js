'use strict';

const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({

    code            : {type: Number, default: null},
    title           : [{
        key            : {type: String, default: null},
        value          : {type: String, default: null},
    }],
    description     : [{
        key            : {type: String, default: null},
        value          : {type: String, default: null},
    }],
    status                  : {type: Schema.ObjectId, ref: 'Setting_Status', default: new Object("63fb5ffb9c438d82661190bc")},
    create          : {
        by              : {type: Schema.ObjectId, ref: 'Infomation_Admins'},
        datetime        : {type: Date, default: Date.now}
    },

});

var objsSchema = mongoose.model('Province', objsSchema, 'Province');
module.exports = objsSchema;
