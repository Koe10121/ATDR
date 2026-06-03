'use strict';

function clone(value) {
    if (value instanceof Date) {
        return new Date(value.getTime());
    }
    if (value && typeof value === 'object' && value._bsontype === 'ObjectID') {
        return value;
    }
    if (value && typeof value.toObject === 'function' && !Array.isArray(value)) {
        return clone(value.toObject());
    }
    if (Array.isArray(value)) {
        return Array.prototype.map.call(value, clone);
    }
    if (value && typeof value === 'object') {
        const result = {};
        Object.keys(value).forEach(function (key) {
            result[key] = clone(value[key]);
        });
        return result;
    }
    return value;
}

function ensureObject(value) {
    return value && typeof value === 'object' ? value : {};
}

function ensureArray(value) {
    return Array.isArray(value) ? value : [];
}

function mergeLifecycleWithHrContext(lifecycle, hrContext) {
    const baseLifecycle = clone(ensureObject(lifecycle));
    const sourceHrContext = ensureObject(hrContext);
    if (!baseLifecycle.movements || !baseLifecycle.movements.length) {
        baseLifecycle.movements = clone(ensureArray(sourceHrContext.movements));
    }
    if (!baseLifecycle.leaves || !baseLifecycle.leaves.length) {
        baseLifecycle.leaves = clone(ensureArray(sourceHrContext.leaves));
    }
    if (!baseLifecycle.developments || !baseLifecycle.developments.length) {
        baseLifecycle.developments = clone(ensureArray(sourceHrContext.developments));
    }
    if (!baseLifecycle.assignments || !baseLifecycle.assignments.length) {
        baseLifecycle.assignments = clone(ensureArray(sourceHrContext.assignments));
    }
    if (!baseLifecycle.hrSnapshot && sourceHrContext.snapshot) {
        baseLifecycle.hrSnapshot = clone(sourceHrContext.snapshot);
    }
    return baseLifecycle;
}

function splitLifecycleStorage(lifecycle, currentHrContext) {
    const source = clone(ensureObject(lifecycle));
    const nextHrContext = Object.assign({}, clone(ensureObject(currentHrContext)), {
        movements: clone(ensureArray(source.movements)),
        leaves: clone(ensureArray(source.leaves)),
        developments: clone(ensureArray(source.developments)),
        assignments: clone(ensureArray(source.assignments)),
        snapshot: source.hrSnapshot ? clone(source.hrSnapshot) : clone(ensureObject(currentHrContext && currentHrContext.snapshot))
    });

    delete source.movements;
    delete source.leaves;
    delete source.developments;
    delete source.assignments;
    delete source.hrSnapshot;

    return {
        lifecycle: source,
        hrContext: nextHrContext
    };
}

module.exports = {
    mergeLifecycleWithHrContext,
    splitLifecycleStorage
};
