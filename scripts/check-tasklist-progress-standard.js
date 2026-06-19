#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

function fail(message) {
  console.error(JSON.stringify({ ok: false, message }, null, 2));
  process.exit(1);
}

function read(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

function listMarkdownFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory)
    .filter((entry) => fs.statSync(path.join(directory, entry)).isFile() && entry.endsWith('.md'))
    .sort();
}

function requireContains(content, needle, label) {
  if (!content.includes(needle)) {
    fail(`${label} is missing required content: ${needle}`);
  }
}

function main() {
  const projectRoot = path.resolve(process.argv[2] || process.cwd());
  const docsDir = path.join(projectRoot, 'docs');
  const tasksDir = path.join(docsDir, 'tasks');
  const templatesDir = path.join(docsDir, 'templates');
  const progressPath = path.join(tasksDir, 'tasklist-progress.md');
  const progressHtmlPath = path.join(tasksDir, 'tasklist-progress.html');
  const taskReadmePath = path.join(tasksDir, 'README.md');
  const docsIndexPath = path.join(docsDir, 'AI-DOCS-INDEX.md');

  if (!fs.existsSync(docsDir)) fail(`docs directory not found: ${docsDir}`);
  if (!fs.existsSync(tasksDir)) fail('docs/tasks directory missing');
  if (!fs.existsSync(progressPath)) fail('canonical progress file missing: docs/tasks/tasklist-progress.md');
  if (!fs.existsSync(progressHtmlPath)) fail('canonical progress HTML view missing: docs/tasks/tasklist-progress.html');
  if (!fs.existsSync(taskReadmePath)) fail('tasklist guide missing: docs/tasks/README.md');
  if (!fs.existsSync(docsIndexPath)) fail('docs index missing: docs/AI-DOCS-INDEX.md');
  if (!fs.existsSync(path.join(templatesDir, 'PROJECT-TASKLIST-TEMPLATE.md'))) {
    fail('tasklist template missing: docs/templates/PROJECT-TASKLIST-TEMPLATE.md');
  }
  if (!fs.existsSync(path.join(templatesDir, 'PROJECT-SYSTEM-PROGRESS-TEMPLATE.md'))) {
    fail('system progress template missing: docs/templates/PROJECT-SYSTEM-PROGRESS-TEMPLATE.md');
  }

  const progress = read(progressPath);
  [
    '## T1. Source Evidence',
    '## T2. Progress Calculation',
    '## T3. Active Tasklist',
    '## T4. Verification Log',
    '## T5. Blockers And Risks',
  ].forEach((heading) => requireContains(progress, heading, 'tasklist-progress.md'));

  [
    'Task ID',
    'Task',
    'Agent',
    'Owner',
    'Status',
    'Progress %',
    'Source Evidence',
    'Tests Evidence',
    'Blocker',
    'Next Action',
    'Output',
  ].forEach((column) => requireContains(progress, column, 'tasklist-progress.md'));

  requireContains(progress, 'atdr/app/main.py', 'tasklist-progress.md');
  requireContains(progress, 'frontend/src/App.tsx', 'tasklist-progress.md');
  requireContains(progress, 'ATDR-TASKLIST-001', 'tasklist-progress.md');

  const html = read(progressHtmlPath);
  requireContains(html, 'Task Board', 'tasklist-progress.html');
  requireContains(html, 'T1. Source Evidence', 'tasklist-progress.html');
  requireContains(html, 'T3. Active Tasklist', 'tasklist-progress.html');

  const forbiddenRuntimeClaims = [
    'ATDR uses Node',
    'ATDR uses Vue',
    'ATDR uses MongoDB',
    'production-ready',
    'automatic response enabled',
    'real firewall blocking enabled',
  ];
  const activeDocs = [
    progressPath,
    taskReadmePath,
    docsIndexPath,
    path.join(docsDir, 'ATDR_AI_WORKFLOW.md'),
    path.join(docsDir, 'prd', 'PRD-ATDR.md'),
  ];

  activeDocs.forEach((filePath) => {
    if (!fs.existsSync(filePath)) return;
    const content = read(filePath);
    forbiddenRuntimeClaims.forEach((claim) => {
      if (content.includes(claim)) {
        fail(`${path.relative(projectRoot, filePath)} contains confusing claim: ${claim}`);
      }
    });
  });

  const rootTaskFiles = listMarkdownFiles(tasksDir);
  const datedSystemProgressFiles = rootTaskFiles.filter((file) => /^\d{4}-\d{2}-\d{2}-.+-system-progress\.md$/.test(file));
  if (datedSystemProgressFiles.length > 0) {
    fail(`dated system progress files must be archived or replaced by docs/tasks/tasklist-progress.md: ${datedSystemProgressFiles.join(', ')}`);
  }

  console.log(JSON.stringify({
    ok: true,
    projectRoot,
    progressFile: path.relative(projectRoot, progressPath),
    progressHtmlFile: path.relative(projectRoot, progressHtmlPath),
    docsIndex: path.relative(projectRoot, docsIndexPath),
    rootTaskFiles,
  }, null, 2));
}

if (require.main === module) {
  main();
}
