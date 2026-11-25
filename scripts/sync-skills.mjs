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
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

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
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) throw new Error('SKILL.md must start with a terminated --- frontmatter block');
  const data = parseYaml(match[1]);
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('SKILL.md frontmatter must be a YAML mapping');
  }
  return { frontmatter: match[1], body: text.slice(match[0].length), data };
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
    '  homepage_url: https://scalix.world/mcp',
    '  icon_url: https://scalix.world/scalix-logo.svg',
    '  source:',
    '    repository: scalixworld/scalix-cloud-mcp',
  ].join('\n');
}

let synced = 0;
for (const dir of fs.readdirSync(skillsSrc, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name).sort()) {
  const srcFile = path.join(skillsSrc, dir, 'SKILL.md');
  if (!fs.existsSync(srcFile)) continue;
  const { body, data } = splitFrontmatter(fs.readFileSync(srcFile, 'utf-8'));
  const name = typeof data.name === 'string' ? data.name : '';
  const description = typeof data.description === 'string' ? data.description : '';
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
    stringifyYaml({ name, description }) +
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