'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    key             : {type: String, default: null},
    title           : [{
        key            : {type: String, default: null},
        value          : {type: String, default: null},
    }],
    description     : [{
        key            : {type: String, default: null},
        value          : {type: String, default: null},
    }],
    status          : {type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Status', default: "689c04cb255db4e56aea88ef" },
    group           : {type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Group', default: "689c04cb255db4e56aea88ef" },
    state           : {type: Boolean, default: true},
    create          : {
        by              : {type: mongoose.Schema.Types.ObjectId},
        datetime        : {type: Date, default: Date.now}
    },
    update          : {
        by              : {type: mongoose.Schema.Types.ObjectId},
        datetime        : {type: Date, default: null}
    },
});

module.exports = mongoose.model('Setting_Status', objsSchema, 'Setting_Status');
