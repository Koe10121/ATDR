'use strict';

const mongoose = require('mongoose');
const cfg = require('../config/config');

const EmploymentReference = require('../server/Project/employment/models/reference.model');
const OrganizationGroup = require('../server/Project/employment/models/organization_group.model');
const OrganizationUnit = require('../server/Project/employment/models/organization_unit.model');
const EmploymentRecord = require('../server/Project/employment/models/record.model');

function trimText(value) {
    return String(value || '').trim();
}

function referenceTitle(refDoc) {
    if (!refDoc) return '';
    if (Array.isArray(refDoc.title)) {
        const th = refDoc.title.find(item => item && item.key === 'th' && item.value);
        if (th && th.value) return trimText(th.value);
        const first = refDoc.title.find(item => item && item.value);
        if (first && first.value) return trimText(first.value);
    }
    return trimText(refDoc.nameFull);
}

async function upsertOrgGroupFromRef(refDoc) {
    const code = trimText(refDoc.code) || `GRP-REF-${String(refDoc._id).slice(-8).toUpperCase()}`;
    const titleText = referenceTitle(refDoc) || code;
    let group = await OrganizationGroup.findOne({ code }).lean();
    if (!group) {
        group = await OrganizationGroup.create({
            code: code,
            title: [{ key: 'th', value: titleText }],
            description: [],
            state: refDoc.state !== false
        });
    }
    return group;
}

async function upsertOrgUnitFromRef(refDoc, groupId) {
    const code = trimText(refDoc.code) || `UNIT-REF-${String(refDoc._id).slice(-8).toUpperCase()}`;
    const titleText = referenceTitle(refDoc) || code;
    let unit = await OrganizationUnit.findOne({ code, group: groupId }).lean();
    if (!unit) {
        unit = await OrganizationUnit.create({
            code: code,
            title: [{ key: 'th', value: titleText }],
            description: [],
            group: groupId,
            state: refDoc.state !== false
        });
    }
    return unit;
}

async function run() {
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

    const groupRefs = await EmploymentReference.find({ domain: 'ORGANIZATION_GROUP' }).lean();
    const unitRefs = await EmploymentReference.find({ domain: 'ORGANIZATION_UNIT' }).lean();

    const groupMapOldToNew = {};
    const unitMapOldToNew = {};

    for (const ref of groupRefs) {
        const group = await upsertOrgGroupFromRef(ref);
        groupMapOldToNew[String(ref._id)] = String(group._id);
    }

    for (const ref of unitRefs) {
        const oldParent = ref.parent ? String(ref.parent) : null;
        const newGroupId = oldParent ? groupMapOldToNew[oldParent] : null;
        if (!newGroupId) continue;
        const unit = await upsertOrgUnitFromRef(ref, new mongoose.Types.ObjectId(newGroupId));
        unitMapOldToNew[String(ref._id)] = String(unit._id);
    }

    const records = await EmploymentRecord.find({
        $or: [
            { organizationGroup: { $ne: null } },
            { organizationUnit: { $ne: null } }
        ]
    }).lean();

    let updated = 0;
    for (const row of records) {
        const payload = {};
        const oldGroup = row.organizationGroup ? String(row.organizationGroup) : null;
        const oldUnit = row.organizationUnit ? String(row.organizationUnit) : null;

        if (oldGroup && groupMapOldToNew[oldGroup]) {
            payload.organizationGroup = new mongoose.Types.ObjectId(groupMapOldToNew[oldGroup]);
        }
        if (oldUnit && unitMapOldToNew[oldUnit]) {
            payload.organizationUnit = new mongoose.Types.ObjectId(unitMapOldToNew[oldUnit]);
        }
        if (Object.keys(payload).length) {
            await EmploymentRecord.updateOne({ _id: row._id }, { $set: payload });
            updated += 1;
        }
    }

    console.log(JSON.stringify({
        groupsFromRef: groupRefs.length,
        unitsFromRef: unitRefs.length,
        groupsMaster: await OrganizationGroup.countDocuments({}),
        unitsMaster: await OrganizationUnit.countDocuments({}),
        recordsUpdated: updated
    }));

    await mongoose.disconnect();
}

run().catch(async (err) => {
    console.error(err);
    try { await mongoose.disconnect(); } catch (e) {}
    process.exit(1);
});
