'use strict';
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const LocalizedValueSchema = new Schema({
    key: { type: String, default: null },
    value: { type: String, default: null }
}, { _id: false });

function pickLangValue(items) {
    if (!Array.isArray(items)) return null;
    const preferred = ['th', 'en'];
    for (const key of preferred) {
        const match = items.find(function (item) {
            return item && String(item.key || '').trim().toLowerCase() === key && String(item.value || '').trim();
        });
        if (match) return String(match.value).trim();
    }
    const fallback = items.find(function (item) {
        return item && String(item.value || '').trim();
    });
    return fallback ? String(fallback.value).trim() : null;
}

function attachLocalizedVirtuals(schema) {
    schema.set('toJSON', { virtuals: true });
    schema.set('toObject', { virtuals: true });
    schema.virtual('titleText').get(function () {
        return pickLangValue(this.title);
    });
    schema.virtual('descriptionText').get(function () {
        return pickLangValue(this.description);
    });
    return schema;
}

module.exports = {
    LocalizedValueSchema,
    attachLocalizedVirtuals,
    pickLangValue
};
