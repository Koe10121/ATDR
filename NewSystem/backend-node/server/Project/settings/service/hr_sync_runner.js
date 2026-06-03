'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const HrSyncRun = require('../models/hr_sync_run.model');
const HrIdentityMaster = require('../models/hr_identity_master.model');
const HrPositionMaster = require('../models/hr_position_master.model');
const Account = require('../../accounts/models/account.model');
const { normalizeHrRow, syncHrRows } = require('./hr-sync');

function loadRows(filePath, sheetName) {
    const home = process.env.HOME || '';
    const candidates = [
        process.env.PYTHON_BIN,
        home ? path.join(home, '.pyenv/versions/3.10.3/bin/python3') : '',
        home ? path.join(home, '.pyenv/shims/python3') : '',
        'python3'
    ].filter(Boolean);
    const pythonBin = candidates.find(function (item) {
        return item === 'python3' || fs.existsSync(item);
    }) || 'python3';
    const pythonCode = `
import json, sys
from openpyxl import load_workbook
path = sys.argv[1]
sheet = sys.argv[2]
wb = load_workbook(path, read_only=True, data_only=True)
ws = wb[sheet] if sheet in wb.sheetnames else wb[wb.sheetnames[0]]
header = next(ws.iter_rows(min_row=1, max_row=1, values_only=True), [])
rows = []
for row in ws.iter_rows(min_row=2, values_only=True):
    rows.append(list(row))
print(json.dumps({"sheet": ws.title, "header": list(header), "rows": rows}, ensure_ascii=False, default=str))
`;
    const command = spawnSync(pythonBin, ['-c', pythonCode, filePath, sheetName], {
        cwd: path.dirname(filePath),
        encoding: 'utf8',
        maxBuffer: 1024 * 1024 * 32
    });
    if (command.status !== 0) {
        throw new Error(command.stderr || 'Failed to parse HR Excel file');
    }
    return JSON.parse(command.stdout || '{}');
}

function buildPreview(rows, header) {
    const normalized = (rows || []).map(normalizeHrRow).filter(function (row) {
        return row && (row.positionCode || row.personnelCode || row.positionTitle);
    });
    const unique = function (mapper) {
        return Array.from(new Set(normalized.map(mapper).filter(Boolean)));
    };
    return {
        header: Array.isArray(header) ? header : [],
        rowCount: normalized.length,
        orgGroupCount: unique(function (row) { return row.orgGroupName; }).length,
        orgUnitCount: unique(function (row) { return row.orgUnitName; }).length,
        subUnitCount: unique(function (row) { return row.subUnitName; }).length,
        personnelCount: unique(function (row) { return row.personnelCode; }).length,
        positionCount: unique(function (row) { return row.positionCode; }).length,
        warnings: normalized.length ? [] : ['No valid HR rows found in selected source file.'],
        sample: normalized.slice(0, 10).map(function (row) {
            return {
                personnelCode: row.personnelCode || null,
                fullName: [row.prefix, row.firstName, row.lastName].filter(Boolean).join(' ').trim() || null,
                positionTitle: row.positionTitle || null,
                orgGroupName: row.orgGroupName || null,
                orgUnitName: row.orgUnitName || null,
                subUnitName: row.subUnitName || null,
                workLineName: row.workLineName || null,
                personnelTypeName: row.personnelTypeName || null
            };
        })
    };
}

async function buildPreviewReport(rows, header, options) {
    const preview = buildPreview(rows, header);
    const normalized = (rows || []).map(normalizeHrRow).filter(function (row) {
        return row && (row.positionCode || row.personnelCode || row.positionTitle);
    });
    const createAccounts = !!(options && options.createAccounts);
    const personnelCodes = Array.from(new Set(normalized.map(function (row) { return row.personnelCode; }).filter(Boolean)));
    const positionCodes = Array.from(new Set(normalized.map(function (row) { return row.positionCode; }).filter(Boolean)));

    const [identities, positions, accounts] = await Promise.all([
        personnelCodes.length ? HrIdentityMaster.find({ personnelCode: { $in: personnelCodes } }).lean() : Promise.resolve([]),
        positionCodes.length ? HrPositionMaster.find({ positionCode: { $in: positionCodes } }).lean() : Promise.resolve([]),
        personnelCodes.length ? Account.find({ code: { $in: personnelCodes } }).lean() : Promise.resolve([])
    ]);

    const identityByCode = new Map(identities.map(function (item) { return [String(item.personnelCode || ''), item]; }));
    const positionByCode = new Map(positions.map(function (item) { return [String(item.positionCode || ''), item]; }));
    const accountByCode = new Map(accounts.map(function (item) { return [String(item.code || ''), item]; }));

    let createIdentityCount = 0;
    let updateIdentityCount = 0;
    let createPositionCount = 0;
    let updatePositionCount = 0;
    let matchedAccountCount = 0;
    let createAccountCandidateCount = 0;
    let updateAccountCandidateCount = 0;

    const sample = normalized.slice(0, 10).map(function (row) {
        const identity = row.personnelCode ? identityByCode.get(row.personnelCode) : null;
        const position = row.positionCode ? positionByCode.get(row.positionCode) : null;
        const account = row.personnelCode ? accountByCode.get(row.personnelCode) : null;
        const identityAction = identity ? 'UPDATE' : 'CREATE';
        const positionAction = position ? 'UPDATE' : 'CREATE';
        const accountAction = account ? 'UPDATE' : (createAccounts && row.personnelCode ? 'CREATE' : 'SKIP');
        const matchStatus = account ? 'MATCHED' : (createAccounts && row.personnelCode ? 'CREATE_ACCOUNT' : 'UNMATCHED');

        if (identityAction === 'CREATE') createIdentityCount += 1;
        else updateIdentityCount += 1;
        if (positionAction === 'CREATE') createPositionCount += 1;
        else updatePositionCount += 1;
        if (accountAction === 'UPDATE') updateAccountCandidateCount += 1;
        else if (accountAction === 'CREATE') createAccountCandidateCount += 1;
        if (matchStatus === 'MATCHED') matchedAccountCount += 1;

        return {
            personnelCode: row.personnelCode || null,
            fullName: [row.prefix, row.firstName, row.lastName].filter(Boolean).join(' ').trim() || null,
            positionTitle: row.positionTitle || null,
            orgGroupName: row.orgGroupName || null,
            orgUnitName: row.orgUnitName || null,
            subUnitName: row.subUnitName || null,
            workLineName: row.workLineName || null,
            personnelTypeName: row.personnelTypeName || null,
            identityAction,
            positionAction,
            accountAction,
            matchStatus
        };
    });

    normalized.slice(10).forEach(function (row) {
        const identity = row.personnelCode ? identityByCode.get(row.personnelCode) : null;
        const position = row.positionCode ? positionByCode.get(row.positionCode) : null;
        const account = row.personnelCode ? accountByCode.get(row.personnelCode) : null;
        if (identity) updateIdentityCount += 1;
        else createIdentityCount += 1;
        if (position) updatePositionCount += 1;
        else createPositionCount += 1;
        if (account) {
            matchedAccountCount += 1;
            updateAccountCandidateCount += 1;
        } else if (createAccounts && row.personnelCode) {
            createAccountCandidateCount += 1;
        }
    });

    return Object.assign({}, preview, {
        createIdentityCount,
        updateIdentityCount,
        createPositionCount,
        updatePositionCount,
        matchedAccountCount,
        createAccountCandidateCount,
        updateAccountCandidateCount,
        sample
    });
}

async function listSyncRuns(limit) {
    return HrSyncRun.find({})
        .sort({ createdAt: -1 })
        .limit(limit || 10)
        .lean();
}

module.exports = {
    buildPreview,
    buildPreviewReport,
    listSyncRuns,
    loadRows,
    syncHrRows
};
