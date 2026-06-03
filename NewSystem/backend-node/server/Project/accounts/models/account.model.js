'use strict';
const mongoose = require('mongoose');
var Schema      = mongoose.Schema;
const validateEmail = function(value) {
    const regex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return regex.test(value);
};

const validateStrongPassword = function(value) {
    const regex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*"'()+,-./:;<=>?[\]^_`{|}~]).{8,20}$/;
    return regex.test(value);
};

const validateMobile = function(value) {
    const regex =/^(\([0-9]{3}\) |[0-9]{3}-)[0-9]{3}-[0-9]{4}/;
    return regex.test(value);
};

const validateAssertThaiId = function(value) {
    const regex =/^[0-9]{13}/;
    return regex.test(value);
};


var objsSchema  = new Schema({

    dateTime                : {type: Date, default: null},

    group                   : {type: Schema.ObjectId, ref: 'Setting_Account_Group'},
    code                    : {type: String, default: null},
    email                   : {type: String, default: null},
    authen                  : [{
        type                    : {type: Schema.ObjectId, ref: 'Setting_Authen_Type'},
        username                : {type: String, default: null},
        password                : {type: String, default: null},
        email                   : {type: String, default: null},
        // password                : {type: String, default: null, validate: [validateStrongPassword, "Please enter a valid Password"]},
        // email                   : {type: String, default: null, validate: [validateEmail, "Please enter a valid E-Mail"]},
        oAtuhToken              : {type: String, default: null}
    }],

    userinfo                : {
        prefix              : [{
            key                     : {type: String, default: null},
            value                   : {type: String, default: null},
        }],
        firstName           : [{
            key                     : {type: String, default: null},
            value                   : {type: String, default: null},
        }],
        lastName            : [{
            key                     : {type: String, default: null},
            value                   : {type: String, default: null},
        }],
        image               : {type: String, default: null},
        cardId              : {type: String, default: null},//citizen card id
        birthday            : {type: Date, default: null},
        msisdn              : {type: String, default: null} ,//phone number
        lineId              : {type: String, default: null},
        religion            : {type: String, default: null},
    },

    address                 : [{
        type                    : {type: Schema.ObjectId, ref: 'Setting_AddressType'},
        address                 : {type: String, default: null},
        province                : {type: Schema.ObjectId, ref: 'Setting_Province'},
        district                : {type: Schema.ObjectId, ref: 'Setting_District'},
        subDistrict             : {type: Schema.ObjectId, ref: 'Setting_SubDistrict'},
        zipcode                 : {type: String, default: null},
        gps                     : {
            latitude                : {type: Number, default: null},
            longitude               : {type: Number, default: null},
        }

    }],
    verification            : [{
        type                    : {type: Schema.ObjectId, ref: 'Setting_Verification'},
        dateTime                : {type: Date, default: null},
        expired                 : {type: Date, default: null},
        code                    : {type: String, default: null},
        src                     : {type: String, default: null},
        status                  : {type: Schema.ObjectId, ref: 'Setting_Status', default: new Object("63fb5ffb9c438d82661190bc")},
    }],


    control                 : {
        sso                     : {type: Boolean, default: false}, // singleSignOn
        limit                   : {type: Number, default: 4}, // 0 = on 1 = off
        trustedDevices          : [{
            deviceId                : {type: String, default: null},
            fingerprint             : {type: String, default: null},
            networkKey              : {type: String, default: null},
            userAgent               : {type: String, default: null},
            lastIp                  : {type: String, default: null},
            trustedAt               : {type: Date, default: Date.now},
            expiresAt               : {type: Date, default: null}
        }],
        device                  : [{
            version                 : {type: String, default: null},
            ip                      : {type: String, default: null},
            device                  : {type: String, default: null},
            dateTime                : {type: Date, default: Date.now},
            xAccessToken            : {type: String, default: null}, //user token
            expired_key             : {type: Number, default: 0}, //user expired token defualt 24 h
            deviceId                : {type: String, default: null},
            fingerprint             : {type: String, default: null},
            networkKey              : {type: String, default: null},
            rememberDeviceRequested : {type: Boolean, default: false}
        }]
    },
    hrContext               : {
        movements               : [{
            type                    : {type: String, default: null},
            fromTitle               : {type: String, default: null},
            toTitle                 : {type: String, default: null},
            fromOrgPath             : [{type: String, default: null}],
            toOrgPath               : [{type: String, default: null}],
            effectiveDate           : {type: Date, default: null},
            reason                  : {type: String, default: null},
            referenceNo             : {type: String, default: null},
            approvedBy              : {type: String, default: null},
            impact                  : {type: String, default: null},
            status                  : {type: String, default: null}
        }],
        leaves                  : [{
            type                    : {type: String, default: null},
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            status                  : {type: String, default: null},
            reason                  : {type: String, default: null},
            referenceNo             : {type: String, default: null},
            approvedBy              : {type: String, default: null},
            accessImpact            : {type: String, default: null},
            remarks                 : {type: String, default: null}
        }],
        developments            : [{
            type                    : {type: String, default: null},
            title                   : {type: String, default: null},
            provider                : {type: String, default: null},
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            status                  : {type: String, default: null},
            outcome                 : {type: String, default: null},
            credential              : {type: String, default: null},
            hours                   : {type: Number, default: null},
            linkedLeaveType         : {type: String, default: null},
            remarks                 : {type: String, default: null}
        }],
        assignments             : [{
            type                    : {type: String, default: null},
            title                   : {type: String, default: null},
            orgPath                 : [{type: String, default: null}],
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            status                  : {type: String, default: null},
            scope                   : {type: String, default: null},
            approvedBy              : {type: String, default: null},
            referenceNo             : {type: String, default: null},
            remarks                 : {type: String, default: null},
            temporary               : {type: Boolean, default: true},
            accessProfiles          : [{type: Schema.ObjectId, ref: 'Setting_Lifecycle_AccessProfile'}]
        }],
        snapshot                : {
            positionCode            : {type: String, default: null},
            personnelCode           : {type: String, default: null},
            positionStatus          : {type: String, default: null},
            employmentStatus        : {type: String, default: null},
            workLineCode            : {type: String, default: null},
            workLineName            : {type: String, default: null},
            personnelTypeName       : {type: String, default: null},
            orgGroupName            : {type: String, default: null},
            orgUnitCode             : {type: String, default: null},
            orgUnitName             : {type: String, default: null},
            subUnitName             : {type: String, default: null},
            hireDate                : {type: Date, default: null},
            contractEndDate         : {type: Date, default: null},
            sourceTimestamp         : {type: Date, default: null},
            lastSyncedAt            : {type: Date, default: null}
        }
    },
    lifecycle               : {
        primaryAffiliation      : {type: Schema.ObjectId, ref: 'Setting_Lifecycle_AffiliationType', default: null},
        affiliations            : [{
            type                    : {type: Schema.ObjectId, ref: 'Setting_Lifecycle_AffiliationType', default: null},
            category                : {type: String, default: null},
            orgPath                 : [{type: String, default: null}],
            orgCode                 : {type: String, default: null},
            title                   : {type: String, default: null},
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            source                  : {type: String, default: null},
            status                  : {type: String, default: null},
            isPrimary               : {type: Boolean, default: false}
        }],
        positions               : [{
            code                    : {type: String, default: null},
            title                   : {type: String, default: null},
            type                    : {type: String, default: null},
            orgPath                 : [{type: String, default: null}],
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            isActing                : {type: Boolean, default: false}
        }],
        movements               : [{
            type                    : {type: String, default: null},
            fromTitle               : {type: String, default: null},
            toTitle                 : {type: String, default: null},
            fromOrgPath             : [{type: String, default: null}],
            toOrgPath               : [{type: String, default: null}],
            effectiveDate           : {type: Date, default: null},
            reason                  : {type: String, default: null},
            referenceNo             : {type: String, default: null},
            approvedBy              : {type: String, default: null},
            impact                  : {type: String, default: null},
            status                  : {type: String, default: null}
        }],
        leaves                  : [{
            type                    : {type: String, default: null},
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            status                  : {type: String, default: null},
            reason                  : {type: String, default: null},
            referenceNo             : {type: String, default: null},
            approvedBy              : {type: String, default: null},
            accessImpact            : {type: String, default: null},
            remarks                 : {type: String, default: null}
        }],
        developments            : [{
            type                    : {type: String, default: null},
            title                   : {type: String, default: null},
            provider                : {type: String, default: null},
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            status                  : {type: String, default: null},
            outcome                 : {type: String, default: null},
            credential              : {type: String, default: null},
            hours                   : {type: Number, default: null},
            linkedLeaveType         : {type: String, default: null},
            remarks                 : {type: String, default: null}
        }],
        assignments             : [{
            type                    : {type: String, default: null},
            title                   : {type: String, default: null},
            orgPath                 : [{type: String, default: null}],
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            status                  : {type: String, default: null},
            scope                   : {type: String, default: null},
            approvedBy              : {type: String, default: null},
            referenceNo             : {type: String, default: null},
            remarks                 : {type: String, default: null},
            temporary               : {type: Boolean, default: true},
            accessProfiles          : [{type: Schema.ObjectId, ref: 'Setting_Lifecycle_AccessProfile'}]
        }],
        accessProfiles          : [{
            profile                 : {type: Schema.ObjectId, ref: 'Setting_Lifecycle_AccessProfile', default: null},
            scope                   : {type: String, default: null},
            startDate               : {type: Date, default: null},
            endDate                 : {type: Date, default: null},
            source                  : {type: String, default: null},
            isManual                : {type: Boolean, default: false}
        }],
        provisioning            : {
            state                   : {type: String, default: 'UNPROVISIONED'},
            strategy                : {type: String, default: 'RULE_BASED'},
            joinerDate              : {type: Date, default: null},
            moverDate               : {type: Date, default: null},
            deprovisionDate         : {type: Date, default: null},
            deprovisionReason       : {type: String, default: null},
            lastEvaluatedAt         : {type: Date, default: null},
            lastProvisionedAt       : {type: Date, default: null},
            lastDeprovisionedAt     : {type: Date, default: null},
            lastSyncSource          : {type: String, default: null}
        },
        hrSnapshot              : {
            positionCode            : {type: String, default: null},
            personnelCode           : {type: String, default: null},
            positionStatus          : {type: String, default: null},
            employmentStatus        : {type: String, default: null},
            workLineCode            : {type: String, default: null},
            workLineName            : {type: String, default: null},
            personnelTypeName       : {type: String, default: null},
            orgGroupName            : {type: String, default: null},
            orgUnitCode             : {type: String, default: null},
            orgUnitName             : {type: String, default: null},
            subUnitName             : {type: String, default: null},
            hireDate                : {type: Date, default: null},
            contractEndDate         : {type: Date, default: null},
            sourceTimestamp         : {type: Date, default: null},
            lastSyncedAt            : {type: Date, default: null}
        },
        migration               : {
            legacyPrimaryAffiliation: {type: String, default: null},
            unmappedAffiliations    : [{type: String, default: null}],
            unmappedAccessProfiles  : [{type: String, default: null}],
            lastMigratedAt          : {type: Date, default: null}
        }
    },
    status                  : {type: Schema.ObjectId, ref: 'Setting_Status', default: null},

});


var Information_Accounts = mongoose.model('Information_Accounts', objsSchema, 'Information_Accounts');
module.exports = Information_Accounts;
