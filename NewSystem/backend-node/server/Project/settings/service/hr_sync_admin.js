'use strict';

const resMsg = require('./message');
const { buildPreviewReport, loadRows, listSyncRuns, syncHrRows } = require('./hr_sync_runner');

exports.onPreview = async function (request, response) {
    try {
        const file = request.body && request.body.file ? String(request.body.file) : '';
        const sheet = request.body && request.body.sheet ? String(request.body.sheet) : 'HRAutoUpdate';
        const createAccounts = !!(request.body && request.body.createAccounts);
        if (!file) {
            return response.status(422).json({ status: 422, message: 'missing_file_path' });
        }
        const parsed = loadRows(file, sheet);
        const preview = await buildPreviewReport(parsed.rows || [], parsed.header || [], { createAccounts: createAccounts });
        const resData = await resMsg.onMessage_Response(0, 20000);
        resData.data = Object.assign({ sourceFile: file, sourceSheet: parsed.sheet || sheet }, preview);
        return response.status(200).json(resData);
    } catch (err) {
        return response.status(500).json({ status: 500, message: err && err.message ? err.message : 'hr_sync_preview_failed' });
    }
};

exports.onRun = async function (request, response) {
    try {
        const file = request.body && request.body.file ? String(request.body.file) : '';
        const sheet = request.body && request.body.sheet ? String(request.body.sheet) : 'HRAutoUpdate';
        const createAccounts = !!(request.body && request.body.createAccounts);
        if (!file) {
            return response.status(422).json({ status: 422, message: 'missing_file_path' });
        }
        const parsed = loadRows(file, sheet);
        const summary = await syncHrRows(parsed.rows || [], {
            sourceFile: file,
            sourceSheet: parsed.sheet || sheet,
            autoCreateAccounts: createAccounts
        });
        const resData = await resMsg.onMessage_Response(0, 20000);
        resData.data = summary;
        return response.status(200).json(resData);
    } catch (err) {
        return response.status(500).json({ status: 500, message: err && err.message ? err.message : 'hr_sync_run_failed' });
    }
};

exports.onRuns = async function (request, response) {
    try {
        const runs = await listSyncRuns(10);
        const resData = await resMsg.onMessage_Response(0, 20000);
        resData.data = runs;
        return response.status(200).json(resData);
    } catch (err) {
        return response.status(500).json({ status: 500, message: err && err.message ? err.message : 'hr_sync_runs_failed' });
    }
};
