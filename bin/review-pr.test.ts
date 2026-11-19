import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildCatalog, writeCatalog } from './generate-catalog.js';
import {
  BOT_MARKER,
  buildMaintainerChecks,
  checkCatalogDrift,
  formatReviewComment,
  lintListingText,
  runAiSemanticReview,
  runReview,
  scanTextForSecrets,
} from './review-pr.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'scalix-review-bot-'));
}

function writeFile(root: string, rel: string, content: string): void {
  const target = path.join(root, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

const VALID_MCP_YAML = `id: demo-cloud
name: Demo Cloud
summary: Provisions and manages Demo Cloud databases and storage from a single API key.
description: Hosted MCP server over Streamable HTTP for creating and querying Demo Cloud resources.
author: Demo Org
homepage_url: https://github.com/demo/demo-mcp
trust: community
version: 1.0.0
categories:
  - development
surfaces:
  - coder
  - ide
payload:
  kind: mcp
  transport: http
  serverLabel: demo-cloud
  serverUrl: https://mcp.demo.example/v1/mcp
  authorizationEnv: DEMO_API_KEY
  requiredEnv:
    - DEMO_API_KEY
`;

test('flags hardcoded tool count and marketing taglines as SUGGESTION', () => {
  const badYaml = VALID_MCP_YAML.replace(
    'summary: Provisions and manages Demo Cloud databases and storage from a single API key.',
    'summary: "53 tools, one API key for the world\'s first revolutionary cloud."',
  );
  const findings = lintListingText('mcps/demo-cloud/MCP.yaml', badYaml, false);
  assert.ok(findings.some(f => f.severity === 'SUGGESTION' && f.title.includes('Hardcoded count')));
  assert.ok(findings.some(f => f.severity === 'SUGGESTION' && f.title.includes('Marketing tagline')));
  assert.equal(findings.filter(f => f.severity === 'CRITICAL').length, 0);

  const clean = lintListingText('mcps/demo-cloud/MCP.yaml', VALID_MCP_YAML, false);
  assert.deepEqual(clean, []);
});

test('flags prose em dash and overly short or long summary', () => {
  const emDashYaml = VALID_MCP_YAML.replace(
    'summary: Provisions and manages Demo Cloud databases and storage from a single API key.',
    'summary: "Demo Cloud — provisions databases and storage across your environments."',
  );
  const emFindings = lintListingText('mcps/demo-cloud/MCP.yaml', emDashYaml, false);
  assert.ok(emFindings.some(f => f.severity === 'SUGGESTION' && f.title.includes('em dash')));

  const shortYaml = VALID_MCP_YAML.replace(
    'summary: Provisions and manages Demo Cloud databases and storage from a single API key.',
    'summary: Too short.',
  );
  const shortFindings = lintListingText('mcps/demo-cloud/MCP.yaml', shortYaml, false);
  assert.ok(shortFindings.some(f => f.severity === 'SUGGESTION' && f.title.includes('too short')));
});

test('blocks external PR claiming trust: official as CRITICAL while allowing internal', () => {
  const officialYaml = VALID_MCP_YAML.replace('trust: community', 'trust: official');
  const externalFindings = lintListingText('mcps/demo-cloud/MCP.yaml', officialYaml, true);
  assert.ok(externalFindings.some(f => f.severity === 'CRITICAL' && f.title.includes('trust: official')));

  const internalFindings = lintListingText('mcps/demo-cloud/MCP.yaml', officialYaml, false);
  assert.equal(internalFindings.filter(f => f.title.includes('trust: official')).length, 0);
});

test('flags SSRF and insecure MCP serverUrl values as CRITICAL', () => {
  for (const badUrl of [
    'http://169.254.169.254/latest/meta-data',
    'http://localhost:3000/mcp',
    'https://10.0.0.1/mcp',
  ]) {
    const bad = VALID_MCP_YAML.replace('https://mcp.demo.example/v1/mcp', badUrl);
    const findings = lintListingText('mcps/demo-cloud/MCP.yaml', bad, false);
    assert.ok(
      findings.some(f => f.severity === 'CRITICAL' && f.title.includes('SSRF')),
      `expected CRITICAL SSRF finding for ${badUrl}`,
    );
  }
});

test('detects hardcoded secrets while allowing env-var placeholders', () => {
  const badLines = [
    { line: 4, text: 'Authorization: "Bearer scalix_at_abcdef1234567890"' },
    { line: 5, text: 'key = "sk-abcdefghijklmnop123456"' },
    { line: 6, text: 'aws = "AKIAIOSFODNN7EXAMPLE"' },
    { line: 7, text: 'token={{FOO}} aws=AKIAIOSFODNN7EXAMPLE' },
  ];
  const findings = scanTextForSecrets('mcps/demo-cloud/MCP.yaml', badLines);
  assert.equal(findings.length, 4);
  assert.ok(findings.every(f => f.severity === 'CRITICAL'));

  const safeLines = [
    { line: 4, text: 'Authorization: "Bearer $SCALIX_API_KEY"' },
    { line: 5, text: 'Authorization: "Bearer {{SCALIX_API_KEY}}"' },
    { line: 6, text: 'authorizationEnv: SCALIX_API_KEY' },
  ];
  assert.deepEqual(scanTextForSecrets('mcps/demo-cloud/MCP.yaml', safeLines), []);
});

test('detects drift when dist/listings is stale or missing', () => {
  const root = tmpDir();
  try {
    writeFile(root, 'mcps/demo-cloud/MCP.yaml', VALID_MCP_YAML);
    const { details, errors } = buildCatalog(root);
    assert.deepEqual(errors, []);

    const missingFindings = checkCatalogDrift(root, details);
    assert.ok(missingFindings.some(f => f.severity === 'CRITICAL' && f.file === 'dist/listings/index.json'));

    writeCatalog(path.join(root, 'dist', 'listings'), details, '2026-11-19T00:00:00Z');
    assert.deepEqual(checkCatalogDrift(root, details), []);

    writeFile(
      root,
      'mcps/demo-cloud/MCP.yaml',
      VALID_MCP_YAML.replace('version: 1.0.0', 'version: 1.0.1'),
    );
    const updated = buildCatalog(root).details;
    const staleFindings = checkCatalogDrift(root, updated);
    assert.ok(staleFindings.some(f => f.severity === 'CRITICAL' && f.file === 'dist/listings/index.json'));
    assert.ok(staleFindings.some(f => f.severity === 'CRITICAL' && f.file === 'dist/listings/demo-cloud.json'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('generates Maintainer Quick-Verify commands for http and stdio MCPs', () => {
  const root = tmpDir();
  try {
    writeFile(root, 'mcps/demo-cloud/MCP.yaml', VALID_MCP_YAML);
    writeFile(
      root,
      'mcps/local-tool/MCP.yaml',
      `id: local-tool
name: Local Tool
summary: Runs a local CLI helper via npx for workspace analysis.
author: Demo
trust: community
version: 1.0.0
payload:
  kind: mcp
  transport: stdio
  serverLabel: local-tool
  command: npx
  args:
    - "-y"
    - "@demo/mcp"
`,
    );
    const checks = buildMaintainerChecks(root, ['mcps/demo-cloud/MCP.yaml', 'mcps/local-tool/MCP.yaml']);
    assert.ok(checks.some(c => c.includes('gh api repos/demo/demo-mcp')));
    assert.ok(checks.some(c => c.includes('tools/list') && c.includes('https://mcp.demo.example/v1/mcp')));
    assert.ok(checks.some(c => c.includes('npx -y @demo/mcp')));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('formats idempotent PR comment for pass and fail states without em dashes', () => {
  const passComment = formatReviewComment({
    status: 'pass',
    recommendation: 'Merge',
    counts: { critical: 0, warning: 0, suggestion: 0 },
    ai_review_status: 'skipped',
    ai_review_note: 'AI semantic pass skipped (SCALIX_REVIEW_BOT_API_KEY not set); deterministic checks ran.',
    findings: [],
    maintainer_checks: ['Verify upstream repo (`mcps/demo-cloud/MCP.yaml`): `gh api repos/demo/demo-mcp`'],
    reviewed_files: ['mcps/demo-cloud/MCP.yaml'],
  });
  assert.ok(passComment.startsWith(BOT_MARKER));
  assert.ok(passComment.includes('**Status:** No Issues Found | **Recommendation:** Merge'));
  assert.equal(passComment.includes('—'), false);

  const failComment = formatReviewComment({
    status: 'fail',
    recommendation: 'Address before merge',
    counts: { critical: 0, warning: 0, suggestion: 1 },
    ai_review_status: 'completed',
    ai_review_note: 'AI semantic pass completed (openai/gpt-4o-mini).',
    findings: [
      {
        severity: 'SUGGESTION',
        file: 'mcps/demo-cloud/MCP.yaml',
        line: 3,
        title: 'Hardcoded count ("53 tools") in summary',
        explanation: 'Replace with capability phrasing.',
        source: 'deterministic',
      },
    ],
    maintainer_checks: [],
    reviewed_files: ['mcps/demo-cloud/MCP.yaml'],
  });
  assert.ok(failComment.includes('**Status:** 1 Issue Found | **Recommendation:** Address before merge'));
  assert.ok(failComment.includes('| SUGGESTION | `mcps/demo-cloud/MCP.yaml` | 3 |'));
  assert.equal(failComment.includes('—'), false);
});

test('runAiSemanticReview degrades gracefully without key and parses mocked JSON response', async () => {
  const skipped = await runAiSemanticReview({
    repoRoot: REPO_ROOT,
    diffText: '+id: demo',
  });
  assert.equal(skipped.status, 'skipped');
  assert.deepEqual(skipped.findings, []);

  const mockFetch = (async () =>
    new Response(
      JSON.stringify({
        choices: [
          {
            message: {
              content: JSON.stringify({
                findings: [
                  {
                    severity: 'WARNING',
                    file: 'mcps/demo/MCP.yaml',
                    line: 12,
                    title: 'Unverified endpoint',
                    explanation: 'Verify endpoint ownership before merge.',
                  },
                ],
              }),
            },
          },
        ],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )) as unknown as typeof fetch;

  const completed = await runAiSemanticReview({
    repoRoot: REPO_ROOT,
    diffText: '+id: demo',
    apiKey: 'test-token-placeholder',
    fetchImpl: mockFetch,
  });
  assert.equal(completed.status, 'completed');
  assert.equal(completed.findings.length, 1);
  assert.equal(completed.findings[0].severity, 'WARNING');
  assert.equal(completed.findings[0].source, 'ai');
});

test('real catalog in this repo passes full scalix-review-bot audit with zero findings', async () => {
  const report = await runReview({
    repoRoot: REPO_ROOT,
    checkAll: true,
    skipAi: true,
  });
  assert.deepEqual(report.findings, [], `unexpected findings: ${JSON.stringify(report.findings, null, 2)}`);
  assert.equal(report.status, 'pass');
  assert.equal(report.recommendation, 'Merge');
  assert.ok(report.reviewed_files.length >= 16);
});
