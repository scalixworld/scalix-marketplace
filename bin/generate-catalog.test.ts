import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildCatalog,
  buildIndex,
  isValidListingId,
  isValidVersion,
  isSafeRelativePath,
  isSafeFileName,
  isEnvName,
  isBareCommand,
  isPublicHttpsUrl,
  isPrivateHost,
  validatePublicHttpsUrlDns,
  looksLikeSecret,
  validateMcpPayload,
  validateSkillPayload,
  validateFilePayload,
  resolveGeneratedAt,
  writeCatalog,
} from './generate-catalog.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'scalix-marketplace-'));
}

function writeFixture(root: string, rel: string, content: string): void {
  const target = path.join(root, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

const validMcpPayload = {
  kind: 'mcp',
  transport: 'http',
  serverLabel: 'demo',
  serverUrl: 'https://example.com/mcp',
  authorizationEnv: 'DEMO_API_KEY',
  requiredEnv: ['DEMO_API_KEY'],
};

test('listing ids', () => {
  assert.equal(isValidListingId('scalix-cloud'), true);
  assert.equal(isValidListingId('a'), true);
  assert.equal(isValidListingId('a'.repeat(64)), true);
  assert.equal(isValidListingId('a'.repeat(65)), false);
  assert.equal(isValidListingId('Scalix'), false);
  assert.equal(isValidListingId('-lead'), false);
  assert.equal(isValidListingId('under_score'), false);
  assert.equal(isValidListingId('has space'), false);
});

test('versions', () => {
  assert.equal(isValidVersion('1.5.0'), true);
  assert.equal(isValidVersion('1.5.0-rc.1'), true);
  assert.equal(isValidVersion('1.5.0-alpha'), true);
  assert.equal(isValidVersion('1.5.0+build.7'), true);
  assert.equal(isValidVersion('1.5'), false);
  assert.equal(isValidVersion('v1.5.0'), false);
  assert.equal(isValidVersion('1.5.0; DROP TABLE'), false);
  assert.equal(isValidVersion('1.5.0.1'), false);
  for (const invalid of ['01.2.3', '1.0.0-', '1.0.0+', '1.0.0-rc_1', '1.0.0-rc..1', '1.0.0-01']) {
    assert.equal(isValidVersion(invalid), false, `must reject non-SemVer ${invalid}`);
  }
});

test('env names and commands', () => {
  assert.equal(isEnvName('SCALIX_API_KEY'), true);
  assert.equal(isEnvName('A'), true);
  assert.equal(isEnvName('scalix_api_key'), false);
  assert.equal(isEnvName('1_LEADING'), false);
  assert.equal(isEnvName('sk-live-123'), false);
  assert.equal(isBareCommand('npx'), true);
  assert.equal(isBareCommand('cmd.exe'), true);
  assert.equal(isBareCommand('/bin/sh'), false);
  assert.equal(isBareCommand('./npx'), false);
  assert.equal(isBareCommand('npx; rm -rf /'), false);
  assert.equal(isBareCommand('npx && curl'), false);
  assert.equal(isBareCommand('..'), false);
  assert.equal(isBareCommand('npx'.repeat(40)), false);
});

test('safe relative paths', () => {
  assert.equal(isSafeRelativePath('SKILL.md'), true);
  assert.equal(isSafeRelativePath('references/api-tiers.md'), true);
  assert.equal(isSafeRelativePath('scripts/run.sh'), true);
  for (const bad of [
    '../escape.md',
    '/etc/passwd',
    '..\\windows\\system32',
    'a//b.md',
    'SKILL.md/../../x.md',
    './SKILL.md',
    'a/./b.md',
    'dir/',
    '-leading.md',
    'C:/x.md',
  ]) {
    assert.equal(isSafeRelativePath(bad), false, `must refuse path ${bad}`);
  }
  assert.equal(isSafeRelativePath('a/'.repeat(7) + 'b.md'), false);
});

test('safe file names', () => {
  assert.equal(isSafeFileName('scalix-cloud.md'), true);
  assert.equal(isSafeFileName('bug triager.md'), true);
  assert.equal(isSafeFileName('.hidden'), true);
  assert.equal(isSafeFileName('..'), false);
  assert.equal(isSafeFileName('-lead.md'), false);
  assert.equal(isSafeFileName('a/b.md'), false);
  assert.equal(isSafeFileName('a\\b.md'), false);
});

test('private hosts and public https urls (SSRF parity)', () => {
  const blockedUrls = [
    'http://example.com/mcp',
    'ftp://example.com/mcp',
    'https://127.0.0.1/mcp',
    'https://127.0.0.2/mcp',
    'https://localhost/mcp',
    'https://localhost./mcp',
    'https://service.internal./mcp',
    'https://169.254.169.254/latest/meta-data',
    'https://10.0.0.5/mcp',
    'https://172.16.0.1/mcp',
    'https://192.168.1.1/mcp',
    'https://[::1]/mcp',
    'https://[::ffff:127.0.0.1]/mcp',
    'https://[::ffff:169.254.169.254]/mcp',
    'https://[::ffff:7f00:1]/mcp',
    'https://[fc00::1]/mcp',
    'https://[fd12::1]/mcp',
    'https://[fe80::1]/mcp',
    'https://[2001:db8::1]/mcp',
    'https://[ff02::1]/mcp',
    'https://2130706433/mcp',
    'https://0x7f000001/mcp',
    'https://127.1/mcp',
    'https://user:pass@example.com/mcp',
    'https://service.internal/mcp',
    'https://localhost.localdomain/mcp',
    'https://box.local/mcp',
    'https://100.100.100.200/latest',
    'https://100.64.0.1/mcp',
    'not a url',
  ];
  for (const url of blockedUrls) {
    assert.equal(isPublicHttpsUrl(url), false, `must refuse ${url}`);
  }
  const allowedUrls = [
    'https://api.githubcopilot.com/mcp/',
    'https://mcp.context7.com/mcp',
    'https://mcp.sentry.dev/mcp',
    'https://mcp.deepwiki.com/mcp',
    'https://api.scalix.world/v1/mcp',
    'https://fcm.googleapis.com/mcp',
    'https://fedora.org/mcp',
    'https://example.com',
    'https://8.8.8.8/mcp',
  ];
  for (const url of allowedUrls) {
    assert.equal(isPublicHttpsUrl(url), true, `must allow ${url}`);
  }
  assert.equal(isPrivateHost('metadata.google.internal'), true);
  assert.equal(isPrivateHost('instance-data'), true);
  assert.equal(isPrivateHost('localhost.'), true);
  assert.equal(isPrivateHost('8.8.8.8'), false);
});

test('DNS policy rejects private answers and fails closed without real network access', async () => {
  const publicLookup = async () => [{ address: '8.8.8.8', family: 4 }];
  assert.equal(await validatePublicHttpsUrlDns('https://example.com/mcp', publicLookup), null);

  const privateLookup = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '127.0.0.1', family: 4 },
  ];
  assert.match(
    (await validatePublicHttpsUrlDns('https://foo.127.0.0.1.nip.io/mcp', privateLookup)) ?? '',
    /private or special-use/,
  );
  assert.match(
    (await validatePublicHttpsUrlDns('https://example.com/mcp', async () => [])) ?? '',
    /no addresses/,
  );
  assert.match(
    (await validatePublicHttpsUrlDns('https://example.com/mcp', async () => { throw new Error('ENOTFOUND'); })) ?? '',
    /DNS resolution failed/,
  );
});

test('credential-shaped values are refused', () => {
  assert.equal(looksLikeSecret('sk-abcdefghijklmnop1234'), true);
  assert.equal(looksLikeSecret('sk-proj-abcdefghijklmnop1234'), true);
  assert.equal(looksLikeSecret('sk-ant-abcdefghijklmnop1234'), true);
  assert.equal(looksLikeSecret('Basic dXNlcjpwYXNz'), true);
  assert.equal(looksLikeSecret('ghp_abcdefghijklmnopqrstuvwxyz0123456789'), true);
  assert.equal(looksLikeSecret('gho_abcdefghijklmnopqrstuvwxyz0123456789'), true);
  assert.equal(looksLikeSecret('Bearer abcdefghijklmnop1234'), true);
  assert.equal(looksLikeSecret('api_key=abc12345678'), true);
  assert.equal(looksLikeSecret('-----BEGIN PRIVATE KEY-----'), true);
  assert.equal(looksLikeSecret('scalix_at_k9x2mn4pq'), true);
  assert.equal(looksLikeSecret('xoxb-1234-5678'), true);
  assert.equal(looksLikeSecret('GITHUB_PERSONAL_ACCESS_TOKEN'), false);
  assert.equal(looksLikeSecret('https://api.scalix.world/v1/mcp'), false);
  assert.equal(looksLikeSecret('@modelcontextprotocol/server-sequential-thinking'), false);
  assert.equal(looksLikeSecret('task-tracking skill'), false);
  assert.equal(looksLikeSecret('requires the bearer key'), false);
  assert.equal(looksLikeSecret('Authorization: Bearer $SCALIX_API_KEY'), false);
  assert.equal(looksLikeSecret('bearer ${MY_TOKEN}'), false);
  assert.equal(looksLikeSecret('export SCALIX_API_KEY=scalix_at_...'), false);
  assert.equal(looksLikeSecret('a Full Access Key has prefix `scalix_at_...`'), false);
  assert.equal(looksLikeSecret('sk-live-abc123'), false);
});

test('mcp payload validation', () => {
  assert.deepEqual(validateMcpPayload({ ...validMcpPayload }), []);
  assert.deepEqual(
    validateMcpPayload({
      kind: 'mcp',
      transport: 'stdio',
      serverLabel: 'demo',
      command: 'npx',
      args: ['-y', '@scope/pkg@1.2.3'],
    }),
    [],
  );

  assert.ok(validateMcpPayload({ ...validMcpPayload, kind: 'skill' }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, evil: true }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, serverLabel: 'x' }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, transport: 'tcp' }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, serverUrl: 'http://api.scalix.world/mcp' }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, serverUrl: 'https://169.254.169.254/mcp' }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, authorizationEnv: 'lower_case' }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, requiredEnv: ['not-an-env'] }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, headers: { Authorization: 'Bearer sk-abcdefghijklmnop1234' } }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, headers: { Authorization: 'Basic dXNlcjpwYXNz' } }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, headers: { 'X-Key': 'sk-proj-abcdefghijklmnop1234' } }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, headers: { 'Bad Key': 'v' } }).length > 0);
  assert.ok(validateMcpPayload({ ...validMcpPayload, command: 'npx' }).length > 0);
  assert.ok(
    validateMcpPayload({ kind: 'mcp', transport: 'stdio', serverLabel: 'demo', command: '/bin/sh', args: ['-c', 'x'] }).length > 0,
  );
  assert.ok(validateMcpPayload({ kind: 'mcp', transport: 'stdio', serverLabel: 'demo', command: 'npx', serverUrl: 'https://x.example' }).length > 0);
  assert.ok(
    validateMcpPayload({
      kind: 'mcp',
      transport: 'stdio',
      serverLabel: 'demo',
      command: 'npx',
      args: Array.from({ length: 21 }, () => 'x'),
    }).length > 0,
  );
  assert.ok(
    validateMcpPayload({
      kind: 'mcp',
      transport: 'stdio',
      serverLabel: 'demo',
      command: 'npx',
      args: ['x'.repeat(513)],
    }).length > 0,
  );
  assert.ok(
    validateMcpPayload({
      kind: 'mcp',
      transport: 'stdio',
      serverLabel: 'demo',
      command: 'npx',
      args: ['ok', '\u0000'],
    }).length > 0,
  );
  for (const args of [['-y', '@scope/pkg'], ['-y', '@scope/pkg@latest'], ['-y', 'pkg@^1.2.3'], ['-y']]) {
    assert.ok(
      validateMcpPayload({ kind: 'mcp', transport: 'stdio', serverLabel: 'demo', command: 'npx', args }).some(error => error.includes('npm')),
      `must reject mutable/missing npm package spec: ${args.join(' ')}`,
    );
  }
  assert.ok(
    validateMcpPayload({
      kind: 'mcp', transport: 'stdio', serverLabel: 'demo', command: 'npx', args: ['-y', '@scope/pkg@1.2.3'],
      authorizationEnv: 'DEMO_KEY', headers: { Authorization: 'Basic dXNlcjpwYXNz' },
    }).some(error => error.includes('HTTP')),
  );
});

test('skill payload validation', () => {
  const files = [{ path: 'SKILL.md', content: '# demo' }];
  assert.deepEqual(validateSkillPayload('demo', files), []);
  assert.ok(validateSkillPayload('a', files).some(error => error.includes('2..=64')));
  assert.ok(validateSkillPayload('../escape', files).length > 0);
  assert.ok(validateSkillPayload('demo', []).length > 0);
  assert.ok(validateSkillPayload('demo', [{ path: 'docs/x.md', content: 'x' }]).length > 0);
  assert.ok(validateSkillPayload('demo', [{ path: '../x.md', content: 'x' }]).length > 0);
  assert.ok(
    validateSkillPayload('demo', [
      { path: 'SKILL.md', content: 'a' },
      { path: 'SKILL.md', content: 'b' },
    ]).length > 0,
  );
  assert.ok(validateSkillPayload('demo', [{ path: 'SKILL.md', content: 'x'.repeat(256 * 1024 + 1) }]).length > 0);
  assert.ok(
    validateSkillPayload(
      'demo',
      Array.from({ length: 11 }, (_, i) => ({ path: `f${i}.md`, content: 'x' })),
    ).length > 0,
  );
  assert.ok(validateSkillPayload('demo', [{ path: 'SKILL.md', content: 'use ghp_abcdefghijklmnopqrstuvwxyz0123456789' }]).length > 0);
});

test('rule and subagent payload validation', () => {
  assert.deepEqual(validateFilePayload('rule', 'rule.md', '# body'), []);
  assert.deepEqual(validateFilePayload('subagent', 'agent.md', '# body'), []);
  assert.ok(validateFilePayload('rule', 'rule.txt', '# body').length > 0);
  assert.ok(validateFilePayload('rule', 'rule.md', '').length > 0);
  assert.ok(validateFilePayload('rule', '../rule.md', '# body').length > 0);
  assert.ok(validateFilePayload('rule', 'rule.md', 'export sk-abcdefghijklmnop1234').length > 0);
  assert.ok(validateFilePayload('subagent', 'agent.md', 'x'.repeat(256 * 1024 + 1)).length > 0);
});

test('real catalog in this repo builds clean', () => {
  const { details, errors } = buildCatalog(REPO_ROOT);
  assert.deepEqual(errors, []);
  assert.ok(details.length >= 12, `expected at least 12 listings, got ${details.length}`);
  const ids = details.map(d => d.id);
  assert.equal(new Set(ids).size, ids.length, 'ids are unique');
  const scalixCloud = details.find(d => d.id === 'scalix-cloud');
  assert.ok(scalixCloud);
  assert.equal(scalixCloud.kind, 'mcp');
  assert.equal(scalixCloud.trust, 'official');
  assert.equal(scalixCloud.payload.kind, 'mcp');
  if (scalixCloud.payload.kind === 'mcp') {
    assert.equal(scalixCloud.payload.transport, 'http');
    assert.equal(scalixCloud.payload.serverUrl, 'https://api.scalix.world/v1/mcp');
    assert.equal(scalixCloud.payload.authorizationEnv, 'SCALIX_API_KEY');
  }
  for (const detail of details) {
    assert.ok(detail.surfaces.length > 0, `${detail.id} has surfaces`);
    if (detail.kind === 'skill') {
      assert.equal(detail.payload.kind, 'skill');
      if (detail.payload.kind === 'skill') {
        assert.ok(detail.payload.files.some(f => f.path === 'SKILL.md'), `${detail.id} ships SKILL.md`);
      }
    }
    if (detail.kind === 'rule' || detail.kind === 'subagent') {
      assert.equal(detail.payload.kind, detail.kind);
      if (detail.payload.kind === 'rule' || detail.payload.kind === 'subagent') {
        assert.ok(detail.payload.fileName.endsWith('.md'));
      }
    }
  }
});

test('duplicate ids across kinds are rejected', () => {
  const root = tmpDir();
  try {
    const meta = (id: string) =>
      `id: ${id}\nname: ${id}\nsummary: dup\nauthor: Scalix World\ntrust: official\nversion: 1.0.0\n`;
    writeFixture(root, 'mcps/dup/MCP.yaml', `${meta('dup')}payload:\n  kind: mcp\n  transport: http\n  serverLabel: dup\n  serverUrl: https://example.com/mcp\n`);
    writeFixture(root, 'rules/dup.md', `---\n${meta('dup')}---\nbody\n`);
    const { errors } = buildCatalog(root);
    assert.ok(errors.some(e => e.includes('duplicate listing id')), `expected duplicate-id error, got: ${errors.join(' | ')}`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('malformed fixtures produce loud errors', () => {
  const root = tmpDir();
  try {
    writeFixture(root, 'mcps/ssrf/MCP.yaml', 'id: ssrf\nname: ssrf\nsummary: s\nauthor: a\ntrust: official\nversion: 1.0.0\npayload:\n  kind: mcp\n  transport: http\n  serverLabel: ssrf\n  serverUrl: https://169.254.169.254/mcp\n');
    writeFixture(root, 'mcps/leak/MCP.yaml', 'id: leak\nname: leak\nsummary: l\nauthor: a\ntrust: official\nversion: 1.0.0\npayload:\n  kind: mcp\n  transport: http\n  serverLabel: leak\n  serverUrl: https://example.com/mcp\n  headers:\n    Authorization: "Bearer sk-abcdefghijklmnop1234"\n');
    writeFixture(root, 'rules/BADID.md', '---\nid: BADID\nname: bad\nsummary: s\nauthor: a\ntrust: official\nversion: 1.0.0\n---\nbody\n');
    writeFixture(root, 'skills/no-frontmatter/SKILL.md', '# no frontmatter\n');
    const { details, errors } = buildCatalog(root);
    assert.ok(details.length === 0, `no listing should build, got ${details.length}`);
    assert.ok(errors.some(e => e.includes('serverUrl')), `expected SSRF refusal, got: ${errors.join(' | ')}`);
    assert.ok(errors.some(e => e.includes('credential')), `expected secret refusal, got: ${errors.join(' | ')}`);
    assert.ok(errors.some(e => e.includes('id "BADID"') || e.includes('must match')), `expected id refusal, got: ${errors.join(' | ')}`);
    assert.ok(errors.some(e => e.includes('frontmatter')), `expected frontmatter refusal, got: ${errors.join(' | ')}`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('catalog metadata cannot smuggle credentials into public JSON', () => {
  const root = tmpDir();
  try {
    writeFixture(
      root,
      'mcps/leak/MCP.yaml',
      `id: leak
name: Leak
summary: Demonstrates metadata validation for a hosted MCP integration.
description: "sk-proj-abcdefghijklmnop1234"
author: Example
trust: community
version: 1.0.0
payload:
  kind: mcp
  transport: http
  serverLabel: leak
  serverUrl: https://example.com/mcp
`,
    );
    const { details, errors } = buildCatalog(root);
    assert.equal(details.length, 0);
    assert.ok(errors.some(error => error.includes('description looks like a credential')), errors.join(' | '));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('writeCatalog emits index and per-id detail files', () => {
  const root = tmpDir();
  try {
    const { details } = buildCatalog(REPO_ROOT);
    const outDir = path.join(root, 'listings');
    const index = writeCatalog(outDir, details, '2026-11-18T00:00:00Z');
    assert.equal(index.generated_at, '2026-11-18T00:00:00Z');
    assert.equal(index.count, details.length);
    assert.ok(fs.existsSync(path.join(outDir, 'index.json')));
    for (const detail of details) {
      const file = path.join(outDir, `${detail.id}.json`);
      assert.ok(fs.existsSync(file), `missing ${detail.id}.json`);
      const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
      assert.equal(parsed.id, detail.id);
      assert.equal(parsed.kind, detail.kind);
      assert.equal(parsed.payload.kind, detail.kind);
    }
    const indexParsed = JSON.parse(fs.readFileSync(path.join(outDir, 'index.json'), 'utf-8'));
    assert.ok(Array.isArray(indexParsed.listings));
    for (const entry of indexParsed.listings) {
      assert.equal(typeof entry.id, 'string');
      assert.equal(typeof entry.summary, 'string');
      assert.ok(Array.isArray(entry.surfaces));
    }
    const reordered = buildIndex([details[details.length - 1], details[0]], '2026-11-18T00:00:00Z');
    assert.equal(reordered.count, 2);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('resolveGeneratedAt preserves timestamp when catalog content is unchanged', () => {
  const root = tmpDir();
  try {
    const { details } = buildCatalog(REPO_ROOT);
    const outDir = path.join(root, 'listings');
    const pinned = '2026-11-18T00:00:00.000Z';
    writeCatalog(outDir, details, pinned);
    assert.equal(resolveGeneratedAt(outDir, details), pinned);

    const modified = details.map((d, i) => (i === 0 ? { ...d, summary: `${d.summary} updated` } : d));
    const next = resolveGeneratedAt(outDir, modified);
    assert.notEqual(next, pinned);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});