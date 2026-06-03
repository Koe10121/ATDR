'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var objsSchema = new Schema({
    key                         : {type: String, default: null},
    title                       : [{
        key                        : {type: String, default: null},
        value                      : {type: String, default: null}
    }],
    description                 : [{
        key                        : {type: String, default: null},
        value                      : {type: String, default: null}
    }],
    affiliationType             : {type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Lifecycle_AffiliationType', default: null},
    defaultAccessProfiles       : [{type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Lifecycle_AccessProfile'}],
    defaultTargetStatus         : {type: mongoose.Schema.Types.ObjectId, ref: 'Setting_Status', default: null},
    autoProvision               : {type: Boolean, default: true},
    autoDeprovision             : {type: Boolean, default: true},
    revokeSessionsOnDeprovision : {type: Boolean, default: true},
    source                      : {type: String, default: 'SYSTEM'},
    version                     : {type: Number, default: 1},
    isSystem                    : {type: Boolean, default: false},
    state                       : {type: Boolean, default: true},
    create                      : {
        by                          : {type: mongoose.Schema.Types.ObjectId},
        datetime                    : {type: Date, default: Date.now}
    },
    update                      : {
        by                          : {type: mongoose.Schema.Types.ObjectId},
        datetime                    : {type: Date, default: null}
    }
});

module.exports = mongoose.model('Setting_Lifecycle_ProvisioningPolicy', objsSchema, 'Setting_Lifecycle_ProvisioningPolicy');
