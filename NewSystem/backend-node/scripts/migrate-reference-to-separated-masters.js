'use strict';

const mongoose = require('mongoose');
const cfg = require('../config/config');

const EmploymentReference = require('../server/Project/employment/models/reference.model');
const EmploymentRecord = require('../server/Project/employment/models/record.model');
const AcademicRank = require('../server/Project/employment/models/academic_rank.model');
const WorkLine = require('../server/Project/employment/models/work_line.model');
const EmployeeType = require('../server/Project/employment/models/employee_type.model');

function trimText(value) {
    return String(value || '').trim();
}

async function upsertByName(Model, nameFull, code) {
    const cleanName = trimText(nameFull);
    const cleanCode = trimText(code);
    if (!cleanName && !cleanCode) return null;
    let doc = cleanCode
        ? await Model.findOne({ code: cleanCode }).lean()
        : await Model.findOne({ 'title.value': cleanName }).lean();
    if (!doc) {
        doc = await Model.create({
            code: cleanCode || null,
            title: [{ key: 'th', value: cleanName || cleanCode }],
            description: [],
            state: true
        });
    } else if (!doc.code && cleanCode) {
        await Model.updateOne({ _id: doc._id }, { code: cleanCode });
    }
    return doc;
}

function referenceTitle(ref) {
    if (!ref) return '';
    if (Array.isArray(ref.title)) {
        const th = ref.title.find(x => x && x.key === 'th' && x.value);
        if (th && th.value) return String(th.value).trim();
        const first = ref.title.find(x => x && x.value);
        if (first && first.value) return String(first.value).trim();
    }
    return trimText(ref.nameFull);
}

async function migrateField(field, domain, Model) {
    const rows = await EmploymentRecord.find({ [field]: { $ne: null } }).select('_id ' + field).lean();
    const refIds = [...new Set(rows.map(r => String(r[field])).filter(Boolean))];
    const refs = await EmploymentReference.find({ _id: { $in: refIds }, domain }).lean();
    const refMap = {};
    refs.forEach(r => { refMap[String(r._id)] = r; });

    let updated = 0;
    for (const row of rows) {
        const ref = refMap[String(row[field])];
        if (!ref) continue;
        const master = await upsertByName(Model, referenceTitle(ref), ref.code);
        if (!master) continue;
        await EmploymentRecord.updateOne({ _id: row._id }, { $set: { [field]: master._id } });
        updated += 1;
    }
    return { field, domain, records: rows.length, updated };
}

async function run() {
    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

    const r1 = await migrateField('academicRank', 'ACADEMIC_RANK', AcademicRank);
    const r2 = await migrateField('workLine', 'WORK_LINE', WorkLine);
    const r3 = await migrateField('employeeType', 'EMPLOYEE_TYPE', EmployeeType);

    console.log(JSON.stringify({
        academicRank: r1,
        workLine: r2,
        employeeType: r3,
        masters: {
            academicRank: await AcademicRank.countDocuments({}),
            workLine: await WorkLine.countDocuments({}),
            employeeType: await EmployeeType.countDocuments({})
        }
    }));

    await mongoose.disconnect();
}

run().catch(async (err) => {
    console.error(err);
    try { await mongoose.disconnect(); } catch (e) {}
    process.exit(1);
});
