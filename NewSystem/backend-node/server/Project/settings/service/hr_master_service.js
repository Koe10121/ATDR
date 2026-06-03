'use strict';

const mongo = require('mongodb');
const resMsg = require('./message');
const { normalizeLangArray, normalizeString, pickLangValue, slugify } = require('./hr_shared');

function decorateLocalizedMaster(item) {
    const title = normalizeLangArray(item && item.title);
    const description = normalizeLangArray(item && item.description);
    return Object.assign({}, item, {
        title: title,
        description: description,
        titleText: pickLangValue(title),
        descriptionText: pickLangValue(description)
    });
}

function resolveKey(payload, fallbackParts) {
    const explicitKey = normalizeString(payload && payload.key);
    if (explicitKey) return explicitKey;
    return (fallbackParts || []).map(function (item) {
        return slugify(item);
    }).filter(Boolean).join(':');
}

function buildBasePayload(body) {
    const title = normalizeLangArray(body && body.title);
    const description = normalizeLangArray(body && body.description);
    const titleText = pickLangValue(title);
    return {
        key: resolveKey(body, [titleText]),
        code: normalizeString(body && body.code) || null,
        title: title,
        description: description,
        source: normalizeString(body && body.source) || 'MANUAL',
        isActive: !(body && body.isActive === false)
    };
}

function sendSuccess(response, data) {
    return resMsg.sendResponse(response, 0, 20000, data);
}

function sendFailure(response, status, message, data) {
    return response.status(status).json({
        status: status,
        message: message,
        data: data || null
    });
}

async function findDependencies(id, definitions) {
    const refs = [];
    for (const definition of definitions || []) {
        const count = await definition.Model.countDocuments({ [definition.field]: new mongo.ObjectId(id) });
        if (count > 0) {
            refs.push({
                field: definition.field,
                label: definition.label,
                count: count
            });
        }
    }
    return refs;
}

function createHrMasterListService(Controller, populate) {
    return createHrMasterCrudService(Controller, {
        populate: populate || [],
        dependencies: []
    });
}

function createHrMasterCrudService(Controller, config) {
    const options = Object.assign({
        populate: [],
        buildPayload: buildBasePayload,
        dependencies: []
    }, config || {});

    return {
        onQuerys: async function (request, response) {
            try {
                const docs = await Controller.onQuerys({}, options.populate, '');
                return sendSuccess(response, Array.isArray(docs) ? docs.map(decorateLocalizedMaster) : []);
            } catch (err) {
                return sendFailure(response, 500, err && err.message ? err.message : 'hr_master_query_failed');
            }
        },
        onCreate: async function (request, response) {
            try {
                const payload = options.buildPayload(request.body || {}, 'create');
                if (!payload.key || !Array.isArray(payload.title) || !payload.title.length) {
                    return sendFailure(response, 422, 'invalid_payload', { fields: ['key', 'title'] });
                }
                const doc = await Controller.onCreate(payload, options.populate, '');
                return sendSuccess(response, decorateLocalizedMaster(doc));
            } catch (err) {
                return sendFailure(response, 500, err && err.message ? err.message : 'hr_master_create_failed');
            }
        },
        onUpdate: async function (request, response) {
            try {
                const id = normalizeString(request.body && request.body._id);
                if (!id) return sendFailure(response, 422, 'missing_id');
                const payload = options.buildPayload(request.body || {}, 'update');
                if (!payload.key || !Array.isArray(payload.title) || !payload.title.length) {
                    return sendFailure(response, 422, 'invalid_payload', { fields: ['key', 'title'] });
                }
                payload._id = id;
                const doc = await Controller.onUpdate({ _id: new mongo.ObjectId(id) }, payload, options.populate, '');
                return sendSuccess(response, decorateLocalizedMaster(doc));
            } catch (err) {
                return sendFailure(response, 500, err && err.message ? err.message : 'hr_master_update_failed');
            }
        },
        onDelete: async function (request, response) {
            try {
                const id = normalizeString((request.body && (request.body.id || request.body._id)) || (request.query && request.query.id));
                if (!id) return sendFailure(response, 422, 'missing_id');
                const refs = await findDependencies(id, options.dependencies);
                if (refs.length) {
                    return sendFailure(response, 409, 'master_in_use', { references: refs });
                }
                const doc = await Controller.onDelete({ _id: new mongo.ObjectId(id) });
                return sendSuccess(response, doc);
            } catch (err) {
                return sendFailure(response, 500, err && err.message ? err.message : 'hr_master_delete_failed');
            }
        }
    };
}

module.exports = {
    buildBasePayload,
    createHrMasterCrudService,
    createHrMasterListService,
    decorateLocalizedMaster
};
