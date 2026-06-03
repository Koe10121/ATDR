'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    key                     : {type: String, default: null},
    title                   : [{
        key                    : {type: String, default: null},
        value                  : {type: String, default: null}
    }],
    description             : [{
        key                    : {type: String, default: null},
        value                  : {type: String, default: null}
    }],
    affiliationTypes        : [{type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Lifecycle_AffiliationType'}],
    matchType               : {type: String, default: 'CONTAINS'},
    matchValues             : [{type: String, default: null}],
    orgScope                : {type: String, default: 'unit'},
    accessProfiles          : [{type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Lifecycle_AccessProfile'}],
    priority                : {type: Number, default: 100},
    source                  : {type: String, default: 'SYSTEM'},
    version                 : {type: Number, default: 1},
    isSystem                : {type: Boolean, default: false},
    state                   : {type: Boolean, default: true},
    create                  : {
        by                      : {type: mongoose.Schema.Types.ObjectId},
        datetime                : {type: Date, default: Date.now}
    },
    update                  : {
        by                      : {type: mongoose.Schema.Types.ObjectId},
        datetime                : {type: Date, default: null}
    }
});

module.exports = mongoose.model('Setting_Lifecycle_PositionRule', objsSchema, 'Setting_Lifecycle_PositionRule');
