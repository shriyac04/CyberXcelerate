#!/usr/bin/env python3
"""
JSON Explorer — a web app for viewing JSON files in the browser.

Usage:
    python json_explorer.py
"""

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from urllib.parse import parse_qs, urlparse

# ── HTML template (self-contained, no external dependencies) ──────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JSON Explorer</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap');

  :root {
    --bg:        #0d0f14;
    --panel:     #13161e;
    --border:    #1e2330;
    --accent:    #00e5ff;
    --accent2:   #7b61ff;
    --danger:    #ff4d6d;
    --success:   #00e096;
    --warn:      #ffb627;
    --text:      #c8cfe0;
    --muted:     #555d75;
    --key:       #7b9cff;
    --str:       #80ffb4;
    --num:       #ffd080;
    --bool:      #ff9f7b;
    --null:      #ff6b8a;
    --mono:      'JetBrains Mono', monospace;
    --display:   'Syne', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    height: 100vh;
    display: grid;
    grid-template-rows: 56px 1fr;
    grid-template-columns: 280px 1fr;
    overflow: hidden;
  }

  /* ── Header ── */
  header {
    grid-column: 1 / -1;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 0 20px;
  }
  header h1 {
    font-family: var(--display);
    font-size: 18px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #fff;
    white-space: nowrap;
  }
  header h1 span { color: var(--accent); }
  #filename {
    font-size: 11px;
    color: var(--muted);
    padding: 3px 10px;
    background: var(--bg);
    border-radius: 4px;
    border: 1px solid var(--border);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 260px;
  }
  #search-wrap {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 8px;
    max-width: 420px;
    margin-left: auto;
  }
  #search {
    flex: 1;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 12px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 12px;
    outline: none;
    transition: border-color .2s;
  }
  #search:focus { border-color: var(--accent); }
  #search::placeholder { color: var(--muted); }
  #search-info { font-size: 11px; color: var(--muted); white-space: nowrap; }
  .btn {
    background: var(--border);
    border: none;
    border-radius: 5px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 11px;
    padding: 5px 10px;
    cursor: pointer;
    transition: background .15s, color .15s;
    white-space: nowrap;
  }
  .btn:hover { background: var(--accent); color: #000; }
  .btn.active { background: var(--accent); color: #000; }

  /* ── Sidebar ── */
  #sidebar {
    background: var(--panel);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 12px 0;
  }
  #sidebar::-webkit-scrollbar { width: 4px; }
  #sidebar::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .sidebar-section { margin-bottom: 4px; }
  .sidebar-label {
    font-family: var(--display);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    padding: 8px 16px 4px;
  }
  .sidebar-key {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 16px;
    cursor: pointer;
    border-left: 2px solid transparent;
    transition: all .15s;
    color: var(--text);
    font-size: 12px;
  }
  .sidebar-key:hover { background: var(--border); color: #fff; }
  .sidebar-key.active {
    border-left-color: var(--accent);
    background: rgba(0,229,255,.06);
    color: var(--accent);
  }
  .sidebar-key .badge {
    margin-left: auto;
    font-size: 10px;
    color: var(--muted);
    background: var(--bg);
    border-radius: 3px;
    padding: 1px 5px;
  }
  .sidebar-key .type-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot-obj  { background: var(--key); }
  .dot-arr  { background: var(--accent2); }
  .dot-str  { background: var(--str); }
  .dot-num  { background: var(--num); }
  .dot-bool { background: var(--bool); }
  .dot-null { background: var(--null); }

  /* ── Main panel ── */
  #main {
    overflow-y: auto;
    padding: 20px;
    position: relative;
  }
  #main::-webkit-scrollbar { width: 6px; }
  #main::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  /* Breadcrumb */
  #breadcrumb {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--muted);
    margin-bottom: 16px;
    flex-wrap: wrap;
  }
  .crumb { cursor: pointer; color: var(--accent); }
  .crumb:hover { text-decoration: underline; }
  .crumb-sep { color: var(--border); }

  /* JSON tree */
  .tree { line-height: 1.9; }
  .node { display: flex; align-items: flex-start; gap: 4px; }
  .toggle {
    cursor: pointer;
    user-select: none;
    color: var(--muted);
    width: 14px;
    flex-shrink: 0;
    margin-top: 1px;
    font-size: 10px;
    transition: transform .15s;
  }
  .toggle:hover { color: var(--accent); }
  .children { padding-left: 22px; border-left: 1px solid var(--border); margin-left: 4px; }
  .children.hidden { display: none; }

  .k { color: var(--key); }
  .s { color: var(--str); }
  .n { color: var(--num); }
  .b { color: var(--bool); }
  .nl { color: var(--null); }
  .colon { color: var(--muted); margin: 0 3px; }
  .meta { font-size: 11px; color: var(--muted); margin-left: 4px; }

  /* Long string truncation */
  .str-full { display: none; }
  .str-short { cursor: pointer; }
  .str-short:hover { color: #fff; }
  .str-short.expanded + .str-full { display: inline; }
  .str-short.expanded { display: none; }

  /* Search highlights */
  mark {
    background: rgba(255,182,39,.35);
    color: var(--warn);
    border-radius: 2px;
    padding: 0 1px;
  }
  mark.current { background: var(--warn); color: #000; }

  /* Stats cards */
  #stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 10px;
    margin-bottom: 20px;
  }
  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
  }
  .stat-card .label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
  .stat-card .value { font-family: var(--display); font-size: 20px; font-weight: 800; color: var(--accent); }
  .stat-card .sub { font-size: 10px; color: var(--muted); margin-top: 2px; }

  /* Empty / loading states */
  .placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 60%;
    gap: 12px;
    color: var(--muted);
  }
  .placeholder .icon { font-size: 48px; opacity: .3; }

  /* Copy button */
  #copy-btn {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--accent2);
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 9px 16px;
    font-family: var(--mono);
    font-size: 12px;
    cursor: pointer;
    transition: background .2s;
    z-index: 10;
  }
  #copy-btn:hover { background: var(--accent); color: #000; }

  /* Scrollbar for the whole app */
  html::-webkit-scrollbar { width: 0; }
</style>
</head>
<body>

<header>
  <h1>JSON <span>Explorer</span></h1>
  <div id="filename">—</div>
  <button class="btn" onclick="showUpload()">New File</button>
  <div id="search-wrap">
    <input id="search" type="text" placeholder="Search keys and values… (Ctrl+F)" autocomplete="off">
    <span id="search-info"></span>
    <button class="btn" id="prev-match">↑</button>
    <button class="btn" id="next-match">↓</button>
    <button class="btn" id="expand-all-btn" onclick="expandAll()">Expand all</button>
    <button class="btn" id="collapse-all-btn" onclick="collapseAll()">Collapse all</button>
  </div>
</header>

<nav id="sidebar"></nav>

<main id="main">
  <div class="placeholder">
    <div class="icon">⟨⟩</div>
    <div>Select a section from the sidebar</div>
  </div>
</main>

<button id="copy-btn" onclick="copyPath()">⎘ Copy path</button>

<script>
// ── State ────────────────────────────────────────────────────────────────────
let DATA = null;
let currentKey = null;
let currentPath = [];
let searchMatches = [];
let searchIdx = 0;

// ── Bootstrap ────────────────────────────────────────────────────────────────
function showUpload() {
  DATA = null;
  currentKey = null;
  currentPath = [];
  document.getElementById('filename').textContent = '—';
  document.getElementById('sidebar').innerHTML = '';
  clearSearch();
  const main = document.getElementById('main');
  main.innerHTML = `
    <div class="placeholder">
      <div class="icon">⬆</div>
      <div>Upload a JSON file to explore</div>
      <form id="uploadForm" style="margin-top:16px;">
        <input type="file" id="jsonInput" name="jsonfile" accept=".json" style="margin-bottom:8px;">
        <br>
        <button type="submit" id="submitBtn" class="btn" disabled>Upload & Analyze</button>
        <div id="uploadError" style="margin-top:8px; color:var(--danger); font-size:12px; display:none;"></div>
      </form>
    </div>
  `;
  
  // Setup file input listener
  const fileInput = document.getElementById('jsonInput');
  const submitBtn = document.getElementById('submitBtn');
  const uploadForm = document.getElementById('uploadForm');
  
  fileInput.addEventListener('change', (e) => {
    submitBtn.disabled = !e.target.files.length;
  });
  
  uploadForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const errorDiv = document.getElementById('uploadError');
    
    if (!fileInput.files.length) {
      errorDiv.textContent = 'Please select a JSON file';
      errorDiv.style.display = 'block';
      return;
    }
    
    const file = fileInput.files[0];
    if (!file.name.endsWith('.json')) {
      errorDiv.textContent = 'Please select a valid JSON file (.json)';
      errorDiv.style.display = 'block';
      return;
    }
    
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        JSON.parse(event.target.result);
        // Valid JSON, proceed with upload
        const formData = new FormData();
        formData.append('jsonfile', file);
        
        fetch('/upload', {
          method: 'POST',
          body: formData
        }).then(r => {
          if (r.ok) location.reload();
          else throw new Error('Upload failed');
        }).catch(() => {
          errorDiv.textContent = 'Upload failed. Please try again.';
          errorDiv.style.display = 'block';
        });
      } catch {
        errorDiv.textContent = 'Invalid JSON file. Please check the file format.';
        errorDiv.style.display = 'block';
      }
    };
    reader.readAsText(file);
  });
}

async function init() {
  try {
    const r = await fetch('/data');
    if (!r.ok) throw new Error();
    DATA = await r.json();
    document.getElementById('filename').textContent = DATA.__meta__.filename;
    buildSidebar();
    showStats();
  } catch {
    showUpload();
  }
}

// ── Sidebar ──────────────────────────────────────────────────────────────────
function buildSidebar() {
  const sb = document.getElementById('sidebar');
  sb.innerHTML = '';

  // Summary link
  const sumEl = mkSidebarKey('📊 Summary', 'obj', null, '__summary__');
  sb.appendChild(sumEl);

  const divider = document.createElement('div');
  divider.className = 'sidebar-label';
  divider.textContent = 'Top-level keys';
  sb.appendChild(divider);

  const root = DATA.__data__;
  for (const [k, v] of Object.entries(root)) {
    sb.appendChild(mkSidebarKey(k, typeOf(v), v, k));
  }
}

function mkSidebarKey(label, type, val, key) {
  const el = document.createElement('div');
  el.className = 'sidebar-key';
  el.dataset.key = key;

  const dot = document.createElement('span');
  dot.className = `type-dot dot-${type}`;

  const name = document.createElement('span');
  name.textContent = label;

  el.appendChild(dot);
  el.appendChild(name);

  if (val !== null && typeof val === 'object') {
    const count = Array.isArray(val) ? val.length : Object.keys(val).length;
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = Array.isArray(val) ? `[${count}]` : `{${count}}`;
    el.appendChild(badge);
  }

  el.onclick = () => {
    document.querySelectorAll('.sidebar-key').forEach(e => e.classList.remove('active'));
    el.classList.add('active');
    if (key === '__summary__') { showStats(); }
    else { renderSection(key); }
  };
  return el;
}

// ── Stats view ───────────────────────────────────────────────────────────────
function showStats() {
  currentKey = null;
  currentPath = [];
  const root = DATA.__data__;
  const meta = DATA.__meta__;
  const main = document.getElementById('main');

  const types = { object: 0, array: 0, string: 0, number: 0, boolean: 0, null: 0 };
  function walk(v) {
    const t = typeOf(v);
    types[t] = (types[t] || 0) + 1;
    if (t === 'object') Object.values(v).forEach(walk);
    else if (t === 'array') v.forEach(walk);
  }
  walk(root);

  const totalKeys = Object.keys(root).length;
  const sizeKB = Math.round(meta.size / 1024);

  main.innerHTML = `
    <div style="font-family:var(--display);font-size:22px;font-weight:800;color:#fff;margin-bottom:18px;">
      File Overview
    </div>
    <div id="stats-grid">
      <div class="stat-card"><div class="label">File size</div><div class="value">${sizeKB} KB</div></div>
      <div class="stat-card"><div class="label">Top keys</div><div class="value">${totalKeys}</div></div>
      <div class="stat-card"><div class="label">Objects</div><div class="value" style="color:var(--key)">${types.object}</div></div>
      <div class="stat-card"><div class="label">Arrays</div><div class="value" style="color:var(--accent2)">${types.array}</div></div>
      <div class="stat-card"><div class="label">Strings</div><div class="value" style="color:var(--str)">${types.string}</div></div>
      <div class="stat-card"><div class="label">Numbers</div><div class="value" style="color:var(--num)">${types.number}</div></div>
      <div class="stat-card"><div class="label">Booleans</div><div class="value" style="color:var(--bool)">${types.boolean}</div></div>
      <div class="stat-card"><div class="label">Nulls</div><div class="value" style="color:var(--null)">${types.null}</div></div>
    </div>
    <div style="font-family:var(--display);font-size:16px;font-weight:700;color:#fff;margin:18px 0 10px;">
      Key index
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;">
      ${Object.keys(root).map(k => `<span class="btn" style="cursor:pointer" onclick="sidebarClick('${k}')">${k}</span>`).join('')}
    </div>
  `;
}

function sidebarClick(key) {
  document.querySelectorAll('.sidebar-key').forEach(e => {
    e.classList.toggle('active', e.dataset.key === key);
  });
  renderSection(key);
}

// ── Section renderer ─────────────────────────────────────────────────────────
function renderSection(key) {
  currentKey = key;
  currentPath = [key];
  clearSearch();

  const val = DATA.__data__[key];
  const main = document.getElementById('main');
  main.innerHTML = '';

  // Breadcrumb
  main.appendChild(makeBreadcrumb([key]));

  // Tree
  const tree = document.createElement('div');
  tree.className = 'tree';
  tree.appendChild(buildNode(val, key, [key]));
  main.appendChild(tree);
}

function makeBreadcrumb(path) {
  const bc = document.createElement('div');
  bc.id = 'breadcrumb';
  bc.innerHTML = `<span class="crumb" onclick="showStats()">root</span>`;
  path.forEach((p, i) => {
    bc.innerHTML += `<span class="crumb-sep">/</span>
      <span class="crumb" onclick="drillPath(${i})">${p}</span>`;
  });
  return bc;
}

function drillPath(idx) {
  // navigate up to idx in currentPath
  const path = currentPath.slice(0, idx + 1);
  renderSection(path[0]);
}

// ── Tree builder ─────────────────────────────────────────────────────────────
function buildNode(val, label, path, isLast = true) {
  const t = typeOf(val);
  const wrap = document.createElement('div');

  if (t === 'object' || t === 'array') {
    const isArr = t === 'array';
    const count = isArr ? val.length : Object.keys(val).length;
    const [open, close] = isArr ? ['[', ']'] : ['{', '}'];

    const row = document.createElement('div');
    row.className = 'node';

    const tog = document.createElement('span');
    tog.className = 'toggle';
    tog.textContent = '▾';

    const lbl = document.createElement('span');
    if (label !== null) {
      lbl.innerHTML = `<span class="k">"${esc(label)}"</span><span class="colon">:</span>`;
    }
    lbl.innerHTML += `${open}<span class="meta">${count} ${isArr ? 'items' : 'keys'}</span>`;

    // Inline preview (first few values)
    const preview = document.createElement('span');
    preview.style.cssText = 'color:var(--muted);font-size:11px;margin-left:4px;';

    row.appendChild(tog);
    row.appendChild(lbl);
    row.appendChild(preview);

    const children = document.createElement('div');
    children.className = 'children';

    // Lazy render children on first expand
    let rendered = false;
    tog.onclick = () => {
      if (!rendered) {
        rendered = true;
        const entries = isArr
          ? val.map((v, i) => [i, v])
          : Object.entries(val);
        entries.forEach(([k, v], idx) => {
          children.appendChild(buildNode(v, isArr ? null : k, [...path, k], idx === entries.length - 1));
        });
        const closeRow = document.createElement('div');
        closeRow.style.color = 'var(--muted)';
        closeRow.textContent = close;
        children.appendChild(closeRow);
      }
      const hidden = children.classList.toggle('hidden');
      tog.textContent = hidden ? '▸' : '▾';
    };

    // Start collapsed if large
    if (count > 20) {
      children.classList.add('hidden');
      tog.textContent = '▸';
    } else {
      // Render immediately
      rendered = true;
      const entries = isArr
        ? val.map((v, i) => [i, v])
        : Object.entries(val);
      entries.forEach(([k, v], idx) => {
        children.appendChild(buildNode(v, isArr ? null : k, [...path, k], idx === entries.length - 1));
      });
      const closeRow = document.createElement('div');
      closeRow.style.color = 'var(--muted)';
      closeRow.textContent = close;
      children.appendChild(closeRow);
    }

    wrap.appendChild(row);
    wrap.appendChild(children);

  } else {
    const row = document.createElement('div');
    row.className = 'node';
    const span = document.createElement('span');

    let labelHtml = '';
    if (label !== null) {
      labelHtml = `<span class="k">"${esc(label)}"</span><span class="colon">:</span>`;
    }

    if (t === 'string') {
      const MAX = 120;
      const escaped = esc(val);
      if (val.length > MAX) {
        span.innerHTML = `${labelHtml}<span class="s str-short" onclick="this.classList.toggle('expanded')">"${escaped.slice(0, MAX)}<span style="color:var(--muted)">… (${val.length} chars)</span>"</span><span class="s str-full">"${escaped}"</span>`;
      } else {
        span.innerHTML = `${labelHtml}<span class="s">"${escaped}"</span>`;
      }
    } else if (t === 'number') {
      span.innerHTML = `${labelHtml}<span class="n">${val}</span>`;
    } else if (t === 'boolean') {
      span.innerHTML = `${labelHtml}<span class="b">${val}</span>`;
    } else {
      span.innerHTML = `${labelHtml}<span class="nl">null</span>`;
    }

    row.appendChild(span);
    wrap.appendChild(row);
  }

  return wrap;
}

// ── Search ───────────────────────────────────────────────────────────────────
let searchTimeout;
document.getElementById('search').addEventListener('input', e => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => doSearch(e.target.value.trim()), 300);
});

document.getElementById('prev-match').onclick = () => stepSearch(-1);
document.getElementById('next-match').onclick = () => stepSearch(1);

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    e.preventDefault();
    document.getElementById('search').focus();
  }
});

function doSearch(q) {
  // Remove old marks
  document.querySelectorAll('mark').forEach(m => {
    m.outerHTML = m.innerHTML;
  });
  searchMatches = [];
  searchIdx = 0;

  if (!q) { document.getElementById('search-info').textContent = ''; return; }

  const main = document.getElementById('main');
  const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT);
  const nodes = [];
  let n;
  while ((n = walker.nextNode())) nodes.push(n);

  const re = new RegExp(escRegex(q), 'gi');
  nodes.forEach(node => {
    if (!re.test(node.textContent)) return;
    re.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0, m;
    while ((m = re.exec(node.textContent)) !== null) {
      frag.appendChild(document.createTextNode(node.textContent.slice(last, m.index)));
      const mark = document.createElement('mark');
      mark.textContent = m[0];
      searchMatches.push(mark);
      frag.appendChild(mark);
      last = re.lastIndex;
    }
    frag.appendChild(document.createTextNode(node.textContent.slice(last)));
    node.parentNode.replaceChild(frag, node);
  });

  document.getElementById('search-info').textContent =
    searchMatches.length ? `1 / ${searchMatches.length}` : 'No matches';

  if (searchMatches.length) {
    searchMatches[0].classList.add('current');
    searchMatches[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

function stepSearch(dir) {
  if (!searchMatches.length) return;
  searchMatches[searchIdx].classList.remove('current');
  searchIdx = (searchIdx + dir + searchMatches.length) % searchMatches.length;
  searchMatches[searchIdx].classList.add('current');
  searchMatches[searchIdx].scrollIntoView({ behavior: 'smooth', block: 'center' });
  document.getElementById('search-info').textContent = `${searchIdx + 1} / ${searchMatches.length}`;
}

function clearSearch() {
  document.getElementById('search').value = '';
  document.getElementById('search-info').textContent = '';
  searchMatches = [];
  searchIdx = 0;
}

// ── Expand / collapse all ────────────────────────────────────────────────────
function expandAll() {
  document.querySelectorAll('.children.hidden').forEach(c => {
    c.classList.remove('hidden');
    const tog = c.previousSibling?.querySelector?.('.toggle');
    if (tog) tog.textContent = '▾';
  });
}
function collapseAll() {
  document.querySelectorAll('.children:not(.hidden)').forEach(c => {
    c.classList.add('hidden');
    const tog = c.previousSibling?.querySelector?.('.toggle');
    if (tog) tog.textContent = '▸';
  });
}

// ── Copy path ─────────────────────────────────────────────────────────────────
function copyPath() {
  navigator.clipboard.writeText(currentPath.join('.'));
  const btn = document.getElementById('copy-btn');
  btn.textContent = '✓ Copied!';
  setTimeout(() => btn.textContent = '⎘ Copy path', 1500);
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function escRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

init();
</script>
</body>
</html>
"""


# ── Server ────────────────────────────────────────────────────────────────────
def parse_multipart(fp, content_type, content_length):
    """Simple multipart form data parser (no external dependencies)"""
    boundary = re.search(r'boundary=([^\s;]+)', content_type)
    if not boundary:
        return None
    
    boundary = boundary.group(1).encode()
    body = fp.read(content_length)
    parts = body.split(b'--' + boundary)
    
    for part in parts:
        if not part or part == b'--\r\n' or part == b'--':
            continue
        
        try:
            header_end = part.find(b'\r\n\r\n')
            if header_end == -1:
                header_end = part.find(b'\n\n')
                if header_end == -1:
                    continue
                headers = part[:header_end].decode('utf-8', errors='ignore')
                content = part[header_end + 2:]
            else:
                headers = part[:header_end].decode('utf-8', errors='ignore')
                content = part[header_end + 4:]
            
            # Extract filename
            filename_match = re.search(r'filename="([^"]*)"', headers)
            if filename_match:
                filename = filename_match.group(1)
                # Remove trailing \r\n
                content = content.rstrip(b'\r\n')
                return filename, content
        except Exception:
            continue
    
    return None


class Handler(BaseHTTPRequestHandler):
    current_data = None

    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def _send_cors_headers(self):
        """Add CORS headers so the frontend (port 3000) can talk to us (port 9000)."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(HTML.encode())

        elif parsed.path == '/data':
            if Handler.current_data is None:
                self.send_response(404)
                self._send_cors_headers()
                self.end_headers()
            else:
                payload = json.dumps(Handler.current_data, ensure_ascii=False)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(payload.encode())

        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/upload':
            content_length = int(self.headers.get('Content-Length', 0))
            content_type = self.headers.get('Content-Type', '')
            
            result = parse_multipart(self.rfile, content_type, content_length)
            if result:
                filename, file_content = result
                try:
                    raw = file_content.decode('utf-8')
                    data = json.loads(raw)
                    Handler.current_data = {
                        '__meta__': {
                            'filename': filename,
                            'size': len(file_content),
                        },
                        '__data__': data,
                    }
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({'ok': True}).encode())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self.send_response(400)
                    self._send_cors_headers()
                    self.end_headers()
            else:
                self.send_response(400)
                self._send_cors_headers()
                self.end_headers()
        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()


def main():
    host = os.environ.get('CAPE_EXPLORER_HOST', '0.0.0.0')
    port = int(os.environ.get('CAPE_EXPLORER_PORT', 9000))
    server = HTTPServer((host, port), Handler)
    print(f'JSON Explorer running on http://{host}:{port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()