'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
require('dotenv').config();

const cfg = require('../config/config');
const { syncHrRows } = require('../server/Project/settings/service/hr-sync');

function parseArgs(argv) {
    const result = { file: '', sheet: 'HRAutoUpdate', createAccounts: false };
    for (let index = 0; index < argv.length; index += 1) {
        const item = argv[index];
        if (item === '--file') result.file = argv[index + 1] || '';
        if (item === '--sheet') result.sheet = argv[index + 1] || 'HRAutoUpdate';
        if (item === '--create-accounts') result.createAccounts = true;
    }
    return result;
}

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
rows = []
for row in ws.iter_rows(min_row=2, values_only=True):
    rows.append(list(row))
print(json.dumps({"sheet": ws.title, "rows": rows}, ensure_ascii=False, default=str))
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

async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (!args.file) {
        throw new Error('Usage: node scripts/sync-hr-workforce.js --file /absolute/path/to/file.xlsx [--sheet HRAutoUpdate]');
    }

    await mongoose.connect(cfg.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
    const parsed = loadRows(args.file, args.sheet);
    const summary = await syncHrRows(parsed.rows || [], {
        sourceFile: args.file,
        sourceSheet: parsed.sheet || args.sheet,
        autoCreateAccounts: args.createAccounts
    });
    console.log(JSON.stringify(summary, null, 2));
    await mongoose.connection.close();
}

main().catch(async function (error) {
    console.error(error && error.stack ? error.stack : error);
    try {
        await mongoose.connection.close();
    } catch (err) {}
    process.exit(1);
});
