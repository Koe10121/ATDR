#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

function fail(message) {
  console.error(JSON.stringify({ ok: false, message }, null, 2));
  process.exit(1);
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderInline(value) {
  return escapeHtml(value)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

function slugify(value) {
  return String(value || 'section')
    .toLowerCase()
    .replace(/`([^`]+)`/g, '$1')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'section';
}

function isTableLine(line) {
  return /^\s*\|.*\|\s*$/.test(line);
}

function isTableSeparator(line) {
  return /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line);
}

function splitTableRow(line) {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((cell) => cell.trim());
}

function normalizeStatus(value) {
  return String(value || '').replace(/`|\*/g, '').trim().toLowerCase();
}

function statusClass(value) {
  const status = normalizeStatus(value);
  if (status === 'done' || status === 'pass') return 'done';
  if (status === 'blocked' || status === 'fail' || status === 'open') return 'blocked';
  if (status === 'verifying') return 'verifying';
  if (status === 'ready') return 'ready';
  if (['in_progress', 'discovery', 'docs_prd'].includes(status)) return 'progress';
  if (status === 'pending' || status === 'not run') return 'pending';
  return '';
}

function renderCell(value, tag) {
  const text = String(value || '').trim();
  const status = statusClass(text);
  const percent = text.match(/^(\d{1,3})%?$/);

  if (percent && tag === 'td') {
    const valueNum = Math.max(0, Math.min(100, Number(percent[1])));
    return `<td><div class="progress"><span>${valueNum}%</span><b style="width:${valueNum}%"></b></div></td>`;
  }

  if (status) {
    return `<${tag}><span class="badge ${status}">${renderInline(text)}</span></${tag}>`;
  }

  return `<${tag}>${renderInline(text)}</${tag}>`;
}

function renderTable(lines) {
  const rows = lines.filter((line) => !isTableSeparator(line)).map(splitTableRow);
  if (!rows.length) return '';
  const header = rows[0];
  const body = rows.slice(1);

  return [
    '<div class="table-wrap">',
    '<table>',
    '<thead><tr>',
    header.map((cell) => renderCell(cell, 'th')).join(''),
    '</tr></thead>',
    '<tbody>',
    body.map((row) => `<tr>${row.map((cell) => renderCell(cell, 'td')).join('')}</tr>`).join('\n'),
    '</tbody>',
    '</table>',
    '</div>',
  ].join('\n');
}

function renderMarkdown(markdown) {
  const lines = String(markdown || '').split(/\r?\n/);
  const html = [];
  let paragraph = [];
  let list = [];
  const seenIds = {};

  function uniqueId(title) {
    const base = slugify(title);
    seenIds[base] = (seenIds[base] || 0) + 1;
    return seenIds[base] === 1 ? base : `${base}-${seenIds[base]}`;
  }

  function flushParagraph() {
    if (!paragraph.length) return;
    html.push(`<p>${renderInline(paragraph.join(' '))}</p>`);
    paragraph = [];
  }

  function flushList() {
    if (!list.length) return;
    html.push(`<ul>${list.map((item) => `<li>${renderInline(item)}</li>`).join('')}</ul>`);
    list = [];
  }

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();

    if (!trimmed) {
      flushParagraph();
      flushList();
      continue;
    }

    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushList();
      const level = heading[1].length;
      const title = heading[2].trim();
      html.push(`<h${level} id="${uniqueId(title)}">${renderInline(title)}</h${level}>`);
      continue;
    }

    if (/^-\s+/.test(trimmed)) {
      flushParagraph();
      list.push(trimmed.replace(/^-\s+/, ''));
      continue;
    }

    if (isTableLine(line)) {
      flushParagraph();
      flushList();
      const table = [];
      while (index < lines.length && isTableLine(lines[index])) {
        table.push(lines[index]);
        index += 1;
      }
      index -= 1;
      html.push(renderTable(table));
      continue;
    }

    paragraph.push(trimmed);
  }

  flushParagraph();
  flushList();
  return html.join('\n');
}

function extractTitle(markdown) {
  const match = String(markdown || '').match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : 'ATDR Tasklist Progress';
}

function extractSection(markdown, number) {
  const pattern = new RegExp(`(^##\\s+T${number}\\.\\s+[^\\n]+\\n[\\s\\S]*?)(?=^##\\s+T\\d+\\.|\\n?$)`, 'm');
  const match = String(markdown || '').match(pattern);
  return match ? match[1].trim() : `## T${number}. Missing\n\nNo data recorded.`;
}

function extractSummary(markdown) {
  const withoutTitle = String(markdown || '').replace(/^#.*\n/, '');
  const match = withoutTitle.match(/^\s*(\|[\s\S]*?\n\s*\n)/);
  return match ? match[1].trim() : '';
}

function extractTaskStatuses(markdown) {
  const section = extractSection(markdown, 3);
  const lines = section.split(/\r?\n/);
  const counts = { done: 0, blocked: 0, verifying: 0, progress: 0, pending: 0 };

  const table = [];
  let inTable = false;
  lines.forEach((line) => {
    if (isTableLine(line)) {
      table.push(line);
      inTable = true;
    } else if (inTable) {
      inTable = false;
    }
  });

  const rows = table.filter((line) => !isTableSeparator(line)).map(splitTableRow);
  if (rows.length < 2) return counts;
  const headers = rows[0].map((header) => header.toLowerCase());
  const statusIndex = headers.indexOf('status');
  if (statusIndex === -1) return counts;

  rows.slice(1).forEach((row) => {
    const status = normalizeStatus(row[statusIndex]);
    if (status === 'done') counts.done += 1;
    else if (status === 'blocked') counts.blocked += 1;
    else if (status === 'verifying') counts.verifying += 1;
    else if (['in_progress', 'discovery', 'docs_prd', 'ready'].includes(status)) counts.progress += 1;
    else counts.pending += 1;
  });

  return counts;
}

function renderPage(markdown) {
  const title = extractTitle(markdown);
  const summary = extractSummary(markdown);
  const counts = extractTaskStatuses(markdown);
  const sections = [1, 2, 3, 4, 5].map((number) => ({
    key: `t${number}`,
    label: `T${number}`,
    html: renderMarkdown(extractSection(markdown, number)),
  }));
  const decision = String(markdown || '').match(/(^##\s+T6\.[\s\S]*)/m);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root { --bg:#f4f7fb; --surface:#fff; --text:#172033; --muted:#667085; --line:#d7dfec; --nav:#10233f; --accent:#1f66d1; --done:#087443; --blocked:#b42318; --warn:#b54708; --pending:#667085; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:Inter,Segoe UI,Arial,sans-serif; line-height:1.5; }
    main { max-width:1440px; margin:0 auto; padding:28px; }
    .hero { background:linear-gradient(120deg,var(--nav),#17497f); color:white; border-radius:14px; padding:24px; margin-bottom:18px; }
    .eyebrow { color:#b9d5ff; font-size:12px; font-weight:800; text-transform:uppercase; }
    h1 { margin:4px 0 0; font-size:30px; letter-spacing:0; }
    h2 { margin:0 0 14px; font-size:20px; }
    h3 { margin:18px 0 8px; font-size:16px; }
    .metrics { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin-bottom:18px; }
    .metric, .panel, .summary { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 10px 28px rgba(16,35,63,.08); }
    .metric { padding:16px; }
    .metric b { display:block; font-size:30px; margin-top:4px; }
    .metric span { color:var(--muted); font-size:12px; font-weight:800; text-transform:uppercase; }
    .summary, .panel { padding:18px; margin-bottom:18px; }
    .tabs { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; }
    button { border:1px solid var(--line); background:white; color:var(--nav); border-radius:999px; padding:8px 12px; font-weight:800; cursor:pointer; }
    button.active { background:var(--nav); color:white; }
    .tab-panel { display:none; }
    .tab-panel.active { display:block; }
    .table-wrap { overflow:auto; border:1px solid var(--line); border-radius:10px; background:white; }
    table { width:100%; min-width:900px; border-collapse:collapse; }
    th, td { padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:14px; }
    th { background:#eef3fb; color:var(--nav); font-size:12px; text-transform:uppercase; }
    code { background:#eef3fb; border:1px solid var(--line); border-radius:4px; padding:1px 4px; }
    .badge { display:inline-flex; align-items:center; border-radius:999px; padding:3px 8px; font-weight:800; font-size:12px; }
    .badge.done { background:#ecfdf3; color:var(--done); }
    .badge.blocked { background:#fef3f2; color:var(--blocked); }
    .badge.verifying, .badge.progress, .badge.ready { background:#fff7ed; color:var(--warn); }
    .badge.pending { background:#f2f4f7; color:var(--pending); }
    .progress { position:relative; min-width:90px; height:22px; background:#eef3fb; border-radius:999px; overflow:hidden; }
    .progress b { position:absolute; inset:0 auto 0 0; background:#9cc3ff; }
    .progress span { position:relative; z-index:1; display:block; padding-left:8px; font-size:12px; font-weight:800; line-height:22px; }
    @media (max-width:900px) { main { padding:16px; } .metrics { grid-template-columns:1fr 1fr; } }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">ATDR Progress Board</div>
      <h1>${renderInline(title)}</h1>
    </section>
    <section class="metrics">
      <div class="metric"><span>Done</span><b>${counts.done}</b></div>
      <div class="metric"><span>Blocked</span><b>${counts.blocked}</b></div>
      <div class="metric"><span>Verifying</span><b>${counts.verifying}</b></div>
      <div class="metric"><span>In Progress</span><b>${counts.progress}</b></div>
      <div class="metric"><span>Pending</span><b>${counts.pending}</b></div>
    </section>
    <section class="summary">${renderMarkdown(summary)}</section>
    <section class="panel" aria-label="Task Board">
      <h2>Task Board</h2>
      <div class="tabs">
        ${sections.map((section, index) => `<button type="button" class="${index === 2 ? 'active' : ''}" data-tab="${section.key}">${section.label}</button>`).join('\n        ')}
      </div>
      ${sections.map((section, index) => `<div class="tab-panel ${index === 2 ? 'active' : ''}" data-panel="${section.key}">${section.html}</div>`).join('\n      ')}
    </section>
    ${decision ? `<section class="panel">${renderMarkdown(decision[1])}</section>` : ''}
  </main>
  <script>
    const buttons = Array.from(document.querySelectorAll('[data-tab]'));
    const panels = Array.from(document.querySelectorAll('[data-panel]'));
    buttons.forEach((button) => {
      button.addEventListener('click', () => {
        buttons.forEach((item) => item.classList.toggle('active', item === button));
        panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.panel === button.dataset.tab));
      });
    });
  </script>
</body>
</html>
`;
}

function resolvePaths(argument, outputArgument) {
  const input = path.resolve(argument || process.cwd());
  const isMarkdownFile = input.endsWith('.md');
  const markdownPath = isMarkdownFile ? input : path.join(input, 'docs/tasks/tasklist-progress.md');
  const outputPath = outputArgument ? path.resolve(outputArgument) : markdownPath.replace(/\.md$/, '.html');
  return { markdownPath, outputPath };
}

function main() {
  const paths = resolvePaths(process.argv[2], process.argv[3]);
  if (!fs.existsSync(paths.markdownPath)) fail(`tasklist progress markdown not found: ${paths.markdownPath}`);
  const markdown = fs.readFileSync(paths.markdownPath, 'utf8');
  const html = renderPage(markdown);
  fs.mkdirSync(path.dirname(paths.outputPath), { recursive: true });
  fs.writeFileSync(paths.outputPath, html, 'utf8');
  console.log(JSON.stringify({
    ok: true,
    source: paths.markdownPath,
    output: paths.outputPath,
    outputFileUrl: pathToFileURL(paths.outputPath).href,
  }, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = { renderMarkdown, renderPage };

