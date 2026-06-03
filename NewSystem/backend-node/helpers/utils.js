/**
 * Created by sherlock on 8/5/2017 AD.
 */
var cfg = require('../config/config');
var crypto = require('crypto');
const moment = require('moment');
var key = cfg.key;

exports.createTokens = async function () {
    return await crypto.randomBytes(parseInt(cfg.tokenLength)).toString('hex');
}

exports.createToken = function (cb) {
    crypto.randomBytes(cfg.tokenLength, function (err, token) {
        if (err) {
            cb(err, null);
        } else {
            cb(null, token.toString('hex'));
        }
    });
}

exports.encrypt = function (data) {
    var cipher = crypto.createCipher('aes-256-cbc', key);
    var crypted = cipher.update(data, 'utf-8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

exports.decrypt = function (data) {
    var decipher = crypto.createDecipher('aes-256-cbc', key);
    var decrypted = decipher.update(data, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}


/**
 * Encode a string of text as base64
 *
 * @param data The string of text.
 * @returns The base64 encoded string.
 */
exports.encodeBase64 =  function(data) {
    if (typeof btoa === "function") {
        return btoa(data);
    } else if (typeof Buffer === "function") {
        return Buffer.from(data, "utf-8").toString("base64");
    } else {
        throw new Error("Failed to determine the platform specific encoder");
    }
}

/**
 * Decode a string of base64 as text
 *
 * @param data The string of base64 encoded text
 * @returns The decoded text.
 */
exports.decodeBase64 = function(data) {
    if (typeof atob === "function") {
        return atob(data);
    } else if (typeof Buffer === "function") {
        return Buffer.from(data, "base64").toString("utf-8");
    } else {
        throw new Error("Failed to determine the platform specific decoder");
    }
}


exports.randomString = function(nummber){
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < nummber; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}
exports.randomNumber = function(nummber){
    var text = "";
    var possible = "0123456789";

    for (var i = 0; i < nummber; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}


exports.compareJSON = function(obj1, obj2) {
    const diffs = {};

    for (const key in obj1) {
        if (obj1.hasOwnProperty(key)) {
            if (Array.isArray(obj1[key]) && Array.isArray(obj2[key])) {
                const arrayDiffs = obj1[key].map((item, index) => compareJSON(item, obj2[key][index]));
                diffs[key] = arrayDiffs.filter(diff => Object.keys(diff).length > 0);
            } else if (typeof obj1[key] === 'object' && obj1[key] !== null && obj2[key] !== null) {
                const deepDiff = compareJSON(obj1[key], obj2[key]);
                if (Object.keys(deepDiff).length > 0) {
                    diffs[key] = deepDiff;
                }
            } else if (obj1[key] !== obj2[key]) {
                diffs[key] = { value1: obj1[key], value2: obj2[key] };
            }
        }
    }

    for (const key in obj2) {
        if (obj2.hasOwnProperty(key) && !obj1.hasOwnProperty(key)) {
            diffs[key] = { value1: undefined, value2: obj2[key] };
        }
    }

    return diffs;
}
exports.createNewDataFromDifferences = function(differences) {
    const result = {};

    for (const key in differences) {
        if (Array.isArray(differences[key])) {
            result[key] = differences[key].map(diff => createNewDataFromDifferences(diff));
        } else if (typeof differences[key] === 'object' && differences[key] !== null && 'value1' in differences[key] && 'value2' in differences[key]) {
            result[key] = differences[key].value2; // หรือเลือก value1 ตามที่ต้องการ
        } else if (typeof differences[key] === 'object' && differences[key] !== null) {
            result[key] = createNewDataFromDifferences(differences[key]);
        }
    }

    return result;
}

// Example usage:
// const json1 = {
//     name: "John",
//     age: 30,
//     address: [{
//         city: "New York",
//         zip: "10001"
//     }]
// };
// const json2 = {
//     name: "Johns",
//     age: 31,
//     ap:{code:11},
//     address: [{
//         city: "New York",
//         zip: "10002"
//     }]
// };
//
// const differences = compareJSON(json1, json2);
// const newData = createNewDataFromDifferences(differences);
// console.log(newData);
