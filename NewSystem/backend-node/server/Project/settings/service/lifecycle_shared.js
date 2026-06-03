'use strict';

var mongo = require('mongodb');
const { attachAudit } = require('./request-actor');

function normalizeLangArray(value) {
    if (Array.isArray(value)) {
        return value.map(function (item) {
            return {
                key: item && item.key ? String(item.key).trim().toLowerCase() : '',
                value: item && item.value ? String(item.value) : ''
            };
        }).filter(function (item) {
            return item.key && item.value;
        });
    }
    return [];
}

function normalizeStringArray(value) {
    if (!Array.isArray(value)) return [];
    return value.map(function (item) {
        return item == null ? '' : String(item).trim();
    }).filter(Boolean);
}

module.exports = {
    attachAudit,
    normalizeLangArray,
    normalizeStringArray
};
