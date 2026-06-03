'use strict';

const { buildCatalogIndex, evaluateLifecycle, loadLifecycleCatalog, normalizeLifecyclePayload } = require('../../settings/service/lifecycle-master');
const { mergeLifecycleWithHrContext } = require('./lifecycle-boundary');

function normalizeKey(value) {
    return String(value || '').trim().toUpperCase();
}

function toDate(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function pushTimelineEvent(target, event) {
    if (!event || !event.type) return;
    const occurredAt = toDate(event.occurredAt || event.startDate || event.endDate || event.effectiveDate);
    target.push(Object.assign({}, event, {
        occurredAt: occurredAt ? occurredAt.toISOString() : null,
        sortValue: occurredAt ? occurredAt.getTime() : 0
    }));
}

function summarizeSignals(resolvedLifecycle, lifecycle, evaluation, account) {
    const now = new Date();
    const affiliations = Array.isArray(resolvedLifecycle && resolvedLifecycle.affiliations) ? resolvedLifecycle.affiliations : [];
    const leaves = Array.isArray(resolvedLifecycle && resolvedLifecycle.leaves) ? resolvedLifecycle.leaves : [];
    const developments = Array.isArray(resolvedLifecycle && resolvedLifecycle.developments) ? resolvedLifecycle.developments : [];
    const assignments = Array.isArray(resolvedLifecycle && resolvedLifecycle.assignments) ? resolvedLifecycle.assignments : [];
    const positions = Array.isArray(lifecycle && lifecycle.positions) ? lifecycle.positions : [];

    let nextContractEnd = null;
    affiliations.forEach(function (item) {
        const endDate = toDate(item && item.endDate);
        if (!endDate || endDate < now) return;
        if (!nextContractEnd || endDate < nextContractEnd.date) {
            nextContractEnd = {
                date: endDate,
                title: item && item.title ? item.title : '',
                affiliation: item && item.type ? item.type : null
            };
        }
    });

    const activeLeaves = Array.isArray(evaluation && evaluation.activeLeaves) ? evaluation.activeLeaves : [];
    const activeAssignments = assignments.filter(function (item) {
        const status = normalizeKey(item && item.status);
        const startDate = toDate(item && item.startDate);
        const endDate = toDate(item && item.endDate);
        return status !== 'INACTIVE' && (!startDate || startDate <= now) && (!endDate || endDate >= now);
    });

    let latestDevelopment = null;
    developments.forEach(function (item) {
        const compareDate = toDate(item && (item.endDate || item.startDate));
        if (!compareDate) return;
        if (!latestDevelopment || compareDate > latestDevelopment.date) {
            latestDevelopment = {
                date: compareDate,
                title: item && item.title ? item.title : '',
                type: item && item.type ? item.type : ''
            };
        }
    });

    const totalLearningHours = developments.reduce(function (sum, item) {
        const hours = Number(item && item.hours);
        return Number.isFinite(hours) ? sum + hours : sum;
    }, 0);

    return {
        activeLeaveCount: activeLeaves.length,
        activeAssignmentCount: activeAssignments.length,
        movementCount: Array.isArray(lifecycle && lifecycle.movements) ? lifecycle.movements.length : 0,
        developmentCount: developments.length,
        currentPositionCount: positions.length,
        totalLearningHours: totalLearningHours,
        nextContractEnd: nextContractEnd ? {
            date: nextContractEnd.date.toISOString(),
            daysRemaining: Math.ceil((nextContractEnd.date.getTime() - now.getTime()) / 86400000),
            title: nextContractEnd.title,
            affiliationKey: nextContractEnd.affiliation && nextContractEnd.affiliation.key ? nextContractEnd.affiliation.key : ''
        } : null,
        latestDevelopment: latestDevelopment ? {
            date: latestDevelopment.date.toISOString(),
            title: latestDevelopment.title,
            type: latestDevelopment.type
        } : null,
        progressionRisk: activeLeaves.some(function (item) { return normalizeKey(item && item.accessImpact) === 'SUSPEND'; })
            ? 'HIGH'
            : (nextContractEnd && Math.ceil((nextContractEnd.date.getTime() - now.getTime()) / 86400000) <= 60 ? 'MEDIUM' : 'LOW'),
        accountStatusKey: account && account.status && account.status.key ? account.status.key : ''
    };
}

function buildLifecycleTimeline(evaluation, lifecycle, account) {
    const resolved = evaluation && evaluation.lifecycle ? evaluation.lifecycle : {};
    const timeline = [];

    const provisioning = lifecycle && lifecycle.provisioning ? lifecycle.provisioning : {};
    if (provisioning.joinerDate) {
        pushTimelineEvent(timeline, {
            type: 'JOINER',
            label: 'Joined organization',
            occurredAt: provisioning.joinerDate,
            source: 'LIFECYCLE'
        });
    }
    if (provisioning.lastProvisionedAt) {
        pushTimelineEvent(timeline, {
            type: 'PROVISIONED',
            label: 'Provisioned account access',
            occurredAt: provisioning.lastProvisionedAt,
            source: 'LIFECYCLE'
        });
    }
    if (provisioning.deprovisionDate) {
        pushTimelineEvent(timeline, {
            type: 'DEPROVISIONED',
            label: provisioning.deprovisionReason ? 'Deprovisioned: ' + provisioning.deprovisionReason : 'Deprovisioned account access',
            occurredAt: provisioning.deprovisionDate,
            source: 'LIFECYCLE'
        });
    }

    (resolved.affiliations || []).forEach(function (item) {
        pushTimelineEvent(timeline, {
            type: 'AFFILIATION',
            label: (item && item.title) || ((item && item.type && item.type.key) ? item.type.key : 'Affiliation'),
            occurredAt: item && item.startDate,
            endDate: item && item.endDate,
            source: 'AFFILIATION',
            status: item && item.status ? item.status : ''
        });
    });

    (lifecycle && lifecycle.movements || []).forEach(function (item) {
        const fromTitle = item && item.fromTitle ? item.fromTitle : '';
        const toTitle = item && item.toTitle ? item.toTitle : '';
        pushTimelineEvent(timeline, {
            type: 'MOVEMENT',
            label: [fromTitle, toTitle].filter(Boolean).length
                ? [fromTitle || 'Unknown role', toTitle || 'New role'].join(' -> ')
                : (item && item.type ? item.type : 'Movement'),
            occurredAt: item && item.effectiveDate,
            source: 'MOVEMENT',
            status: item && item.status ? item.status : '',
            detail: item && item.reason ? item.reason : ''
        });
    });

    (resolved.leaves || []).forEach(function (item) {
        pushTimelineEvent(timeline, {
            type: 'LEAVE',
            label: item && item.type ? item.type : 'Leave',
            occurredAt: item && item.startDate,
            endDate: item && item.endDate,
            source: 'LEAVE',
            status: item && item.status ? item.status : '',
            detail: item && item.reason ? item.reason : ''
        });
    });

    (resolved.developments || []).forEach(function (item) {
        pushTimelineEvent(timeline, {
            type: 'DEVELOPMENT',
            label: item && item.title ? item.title : (item && item.type ? item.type : 'Development'),
            occurredAt: item && (item.endDate || item.startDate),
            source: 'DEVELOPMENT',
            status: item && item.status ? item.status : '',
            detail: item && item.provider ? item.provider : ''
        });
    });

    (resolved.assignments || []).forEach(function (item) {
        pushTimelineEvent(timeline, {
            type: 'ASSIGNMENT',
            label: item && item.title ? item.title : (item && item.type ? item.type : 'Assignment'),
            occurredAt: item && item.startDate,
            endDate: item && item.endDate,
            source: 'ASSIGNMENT',
            status: item && item.status ? item.status : ''
        });
    });

    if (account && account.createDate) {
        pushTimelineEvent(timeline, {
            type: 'ACCOUNT_CREATED',
            label: 'Account record created',
            occurredAt: account.createDate,
            source: 'ACCOUNT'
        });
    }

    timeline.sort(function (left, right) {
        return (right.sortValue || 0) - (left.sortValue || 0);
    });

    return timeline.map(function (item) {
        const cloned = Object.assign({}, item);
        delete cloned.sortValue;
        return cloned;
    });
}

function buildLifecycleSummaryFromEvaluation(evaluation, lifecycle, account) {
    const resolved = evaluation && evaluation.lifecycle ? evaluation.lifecycle : {};
    const activeAffiliations = Array.isArray(resolved.affiliations)
        ? resolved.affiliations.filter(function (item) { return !!(item && item.type); })
        : [];
    const temporaryAccess = Array.isArray(resolved.accessProfiles)
        ? resolved.accessProfiles.filter(function (item) { return !!(item && item.endDate); })
        : [];
    const movements = Array.isArray(lifecycle && lifecycle.movements) ? lifecycle.movements : [];
    const leaves = Array.isArray(lifecycle && lifecycle.leaves) ? lifecycle.leaves : [];
    const developments = Array.isArray(lifecycle && lifecycle.developments) ? lifecycle.developments : [];
    const assignments = Array.isArray(resolved.assignments) ? resolved.assignments : [];
    const alerts = [];

    (evaluation && evaluation.configurationErrors || []).forEach(function (item) {
        alerts.push(item);
    });
    (evaluation && evaluation.warnings || []).forEach(function (item) {
        alerts.push(item);
    });

    return {
        primaryAffiliation: resolved.primaryAffiliation || null,
        activeAffiliationCount: activeAffiliations.length,
        positionCount: Array.isArray(lifecycle && lifecycle.positions) ? lifecycle.positions.length : 0,
        movementCount: movements.length,
        leaveCount: leaves.length,
        activeLeaveCount: Array.isArray(evaluation && evaluation.activeLeaves) ? evaluation.activeLeaves.length : 0,
        developmentCount: developments.length,
        assignmentCount: assignments.length,
        accessProfileCount: Array.isArray(resolved.accessProfiles) ? resolved.accessProfiles.length : 0,
        recommendedAccessProfileCount: Array.isArray(evaluation && evaluation.recommendedProfiles) ? evaluation.recommendedProfiles.length : 0,
        temporaryAccessCount: temporaryAccess.length,
        provisioningState: lifecycle && lifecycle.provisioning && lifecycle.provisioning.state ? lifecycle.provisioning.state : 'UNPROVISIONED',
        alerts: alerts
    };
}

async function buildLifecycleContext(payload, currentLifecycle, account) {
    const catalog = await loadLifecycleCatalog();
    const index = buildCatalogIndex(catalog);
    const payloadWithHr = mergeLifecycleWithHrContext(payload || {}, account && account.hrContext ? account.hrContext : {});
    const currentWithHr = mergeLifecycleWithHrContext(currentLifecycle || {}, account && account.hrContext ? account.hrContext : {});
    const lifecycle = normalizeLifecyclePayload(payloadWithHr, currentWithHr, index);
    const evaluation = evaluateLifecycle(lifecycle, catalog, account || null);
    const summary = buildLifecycleSummaryFromEvaluation(evaluation, lifecycle, account || null);
    return {
        catalog,
        lifecycle,
        evaluation,
        summary
    };
}

async function buildLifecycleSummary(account) {
    const context = await buildLifecycleContext(account && account.lifecycle ? account.lifecycle : {}, account && account.lifecycle ? account.lifecycle : {}, account || null);
    return context.summary;
}

async function buildProvisioningPlan(account, options) {
    const context = await buildLifecycleContext(account && account.lifecycle ? account.lifecycle : {}, account && account.lifecycle ? account.lifecycle : {}, account || null);
    const policyRecommendations = Array.isArray(context.evaluation && context.evaluation.recommendedProfiles)
        ? context.evaluation.recommendedProfiles
        : [];
    return {
        strategy: normalizeKey(options && options.strategy) || (context.lifecycle.provisioning && context.lifecycle.provisioning.strategy) || 'RULE_BASED',
        targetStatusKey: context.evaluation ? context.evaluation.targetStatusKey : null,
        recommendedProfiles: policyRecommendations,
        matchedRules: context.evaluation ? context.evaluation.matchedRules : [],
        configurationErrors: context.evaluation ? context.evaluation.configurationErrors : [],
        warnings: context.evaluation ? context.evaluation.warnings : []
    };
}

async function buildDeprovisionPlan(account, options) {
    const context = await buildLifecycleContext(account && account.lifecycle ? account.lifecycle : {}, account && account.lifecycle ? account.lifecycle : {}, account || null);
    const revokeSessions = context && context.evaluation && Array.isArray(context.evaluation.lifecycle && context.evaluation.lifecycle.affiliations)
        ? true
        : true;
    return {
        targetStatusKey: normalizeKey(options && options.mode) === 'ARCHIVE'
            ? 'ARCHIVED'
            : normalizeKey(options && options.mode) === 'SUSPEND'
                ? 'SUSPENDED'
                : 'INACTIVE',
        revokeSessions: revokeSessions,
        clearTrustedDevices: true,
        reason: options && options.reason ? String(options.reason) : 'Lifecycle deprovision requested',
        configurationErrors: context.evaluation ? context.evaluation.configurationErrors : [],
        warnings: context.evaluation ? context.evaluation.warnings : []
    };
}

module.exports = {
    buildDeprovisionPlan,
    buildLifecycleContext,
    buildLifecycleTimeline,
    buildLifecycleSummary,
    buildProvisioningPlan,
    summarizeSignals
};
