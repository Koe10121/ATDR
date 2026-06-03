'use strict';

function normalizeString(value) {
    return String(value == null ? '' : value).trim();
}

function normalizeLangArray(value) {
    if (Array.isArray(value)) {
        return value.map(function (item) {
            return {
                key: item && item.key ? String(item.key).trim().toLowerCase() : '',
                value: item && item.value ? String(item.value).trim() : ''
            };
        }).filter(function (item) {
            return item.key && item.value;
        });
    }
    const normalized = normalizeString(value);
    return normalized ? [{ key: 'th', value: normalized }] : [];
}

function toLangArray(value) {
    if (Array.isArray(value)) return normalizeLangArray(value);
    if (value && typeof value === 'object') {
        return Object.keys(value).map(function (key) {
            return {
                key: String(key || '').trim().toLowerCase(),
                value: normalizeString(value[key])
            };
        }).filter(function (item) {
            return item.key && item.value;
        });
    }
    return normalizeLangArray(value);
}

function pickLangValue(items) {
    const normalized = normalizeLangArray(items);
    const preferred = ['th', 'en'];
    for (const key of preferred) {
        const match = normalized.find(function (item) {
            return item.key === key && item.value;
        });
        if (match) return match.value;
    }
    return normalized.length ? normalized[0].value : null;
}

function slugify(value) {
    return normalizeString(value)
        .toLowerCase()
        .replace(/[^a-z0-9\u0E00-\u0E7F]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

function parseDate(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function compactStringArray(value) {
    if (!Array.isArray(value)) return [];
    const seen = new Set();
    return value.map(normalizeString).filter(function (item) {
        if (!item || seen.has(item)) return false;
        seen.add(item);
        return true;
    });
}

function buildOrgPath(row) {
    return compactStringArray([row && row.orgGroupName, row && row.orgUnitName, row && row.subUnitName]);
}

module.exports = {
    buildOrgPath,
    compactStringArray,
    normalizeLangArray,
    normalizeString,
    parseDate,
    pickLangValue,
    slugify,
    toLangArray
};
