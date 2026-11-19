#!/usr/bin/env node
// Sync the flagship Scalix skills from a local checkout of
// scalixworld/scalix-cloud-mcp (skills/*/SKILL.md) into skills/<id>/SKILL.md
// here, so the catalog can never drift from the published skills. The catalog
// copy's frontmatter gains a `metadata:` block (author, version, trust,
// categories, tags, surfaces, source.repository) that survives re-syncs;
// name/description/body always come from the source.
//
// Usage:
//   node scripts/sync-skills.mjs [--from <scalix-cloud-mcp dir>] [--version <semver>]
//
// --from defaults to the sibling path ../apps/scalix-cloud-mcp.
// --version defaults to the version in <from>/package.json.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const from = path.resolve(REPO_ROOT, arg('--from', '../apps/scalix-cloud-mcp'));
const skillsSrc = path.join(from, 'skills');
if (!fs.existsSync(skillsSrc)) {
  console.error(`skills source not found: ${skillsSrc}`);
  process.exit(1);
}

const pkgVersion = JSON.parse(fs.readFileSync(path.join(from, 'package.json'), 'utf-8')).version;
const version = arg('--version', pkgVersion);

function splitFrontmatter(text) {
  if (!text.startsWith('---')) throw new Error('SKILL.md must start with a --- frontmatter block');
  const parts = text.split('---');
  // parts: ['', '\nname: ...\n', '\nbody...']
  if (parts.length < 3) throw new Error('SKILL.md frontmatter not terminated');
  return { frontmatter: parts[1], body: parts.slice(2).join('---') };
}

function scalarField(frontmatter, key) {
  const m = frontmatter.match(new RegExp(`^${key}:\\s*(.*)$`, 'm'));
  return m ? m[1].trim() : '';
}

function metadataBlockOf(frontmatter) {
  const lines = frontmatter.split('\n');
  const start = lines.findIndex(l => l === 'metadata:');
  if (start < 0) return null;
  const block = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === '' ) continue;
    if (!line.startsWith(' ')) break;
    block.push(line);
  }
  return block.join('\n');
}

function yamlScalar(v) {
  return /^[-A-Za-z0-9_./ ]+$/.test(v) && !/^\s|\s$/.test(v) && !/[:,#]/.test(v) ? v : JSON.stringify(v);
}

function defaultMetadata(name) {
  const suffix = name.replace(/^scalix-/, '');
  return [
    '  author: Scalix World',
    `  version: ${version}`,
    '  trust: official',
    '  categories:',
    '    - development',
    '  tags:',
    '    - scalix',
    `    - ${suffix}`,
    '  surfaces:',
    '    - coder',
    '    - ide',
    '    - editor',
    '  source:',
    '    repository: scalixworld/scalix-cloud-mcp',
  ].join('\n');
}

let synced = 0;
for (const dir of fs.readdirSync(skillsSrc, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name).sort()) {
  const srcFile = path.join(skillsSrc, dir, 'SKILL.md');
  if (!fs.existsSync(srcFile)) continue;
  const { frontmatter, body } = splitFrontmatter(fs.readFileSync(srcFile, 'utf-8'));
  const name = scalarField(frontmatter, 'name');
  const description = scalarField(frontmatter, 'description');
  if (!name || !description) {
    console.error(`${srcFile}: missing name/description frontmatter`);
    process.exit(1);
  }
  if (name !== dir) {
    console.error(`${srcFile}: frontmatter name "${name}" does not match directory "${dir}"`);
    process.exit(1);
  }

  const targetDir = path.join(REPO_ROOT, 'skills', name);
  fs.mkdirSync(targetDir, { recursive: true });
  const targetFile = path.join(targetDir, 'SKILL.md');
  const existingMeta = fs.existsSync(targetFile)
    ? metadataBlockOf(splitFrontmatter(fs.readFileSync(targetFile, 'utf-8')).frontmatter)
    : null;

  const out =
    '---\n' +
    `name: ${name}\n` +
    `description: ${yamlScalar(description)}\n` +
    'metadata:\n' +
    (existingMeta ?? defaultMetadata(name)) +
    '\n---\n' +
    body;
  fs.writeFileSync(targetFile, out);
  console.log(`synced skills/${name}/SKILL.md (version ${version})`);
  synced++;
}

if (synced === 0) {
  console.error('no skills found to sync');
  process.exit(1);
}