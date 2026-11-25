#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import {
  buildCatalog,
  buildIndex,
  isPlainRecord,
  isPublicHttpsUrl,
  looksLikeSecret,
  validateCatalogDns,
  type CatalogDnsLookup,
  type ListingDetail,
} from './generate-catalog.js';

export type ReviewSeverity = 'CRITICAL' | 'WARNING' | 'SUGGESTION';

export interface ReviewFinding {
  severity: ReviewSeverity;
  file: string;
  line: number;
  title: string;
  explanation: string;
  source: 'deterministic' | 'ai';
}

export interface ReviewCounts {
  critical: number;
  warning: number;
  suggestion: number;
}

export interface ReviewReport {
  status: 'pass' | 'fail';
  recommendation: 'Merge' | 'Address before merge';
  counts: ReviewCounts;
  ai_review_status: 'completed' | 'skipped' | 'error';
  ai_review_note: string;
  findings: ReviewFinding[];
  maintainer_checks: string[];
  reviewed_files: string[];
  comment_markdown: string;
}

export interface ReviewOptions {
  repoRoot: string;
  changedFiles?: string[];
  addedLines?: Array<{ file: string; line: number; text: string }>;
  diffText?: string;
  isExternal?: boolean;
  skipAi?: boolean;
  aiApiKey?: string;
  aiBaseUrl?: string;
  aiModel?: string;
  checkAll?: boolean;
  /** Test seam for deterministic DNS policy checks; production uses dns.lookup. */
  dnsLookup?: CatalogDnsLookup;
}

export const BOT_MARKER = '<!-- scalix-review-bot -->';

const HARDCODED_COUNT_RE = /\b\d+\+?\s+(?:platform\s+)?(?:tools?|endpoints?|models?|integrations?|apis?|commands?|skills?)\b/i;
const MARKETING_HYPE_RE = /\b(?:world['’]s\s+first|world-class|#1|number\s+one|revolutionary|game[- ]changing|best[- ]in[- ]class|unmatched|next[- ]gen(?:eration)?|ultimate|seamlessly|supercharge|unlock\s+the\s+power)\b/i;
const EXTRA_SECRET_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'raw Bearer credential', re: /\bBearer\s+(?![${<])[A-Za-z0-9._-]{16,}\b/i },
];

const SOURCE_FILE_RE = /^(?:mcps\/[^/]+\/MCP\.yaml|skills\/[^/]+\/SKILL\.md|rules\/[^/]+\.md|subagents\/[^/]+\.md)$/;
const SEVERITY_ORDER: Record<ReviewSeverity, number> = { CRITICAL: 0, WARNING: 1, SUGGESTION: 2 };

function findKeyLine(text: string, key: string): number {
  const lines = text.split(/\r?\n/);
  const keyRe = new RegExp(`^\\s*${key}\\s*:`);
  const idx = lines.findIndex(line => keyRe.test(line));
  return idx >= 0 ? idx + 1 : 1;
}

function splitMarkdownFrontmatter(text: string): { data: Record<string, unknown>; body: string } | null {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) return null;
  try {
    const parsed = parseYaml(match[1]);
    if (!isPlainRecord(parsed)) return null;
    return { data: parsed, body: text.slice(match[0].length) };
  } catch {
    return null;
  }
}

function parseSourceMetadata(relFile: string, text: string): {
  kind: 'mcp' | 'skill' | 'rule' | 'subagent';
  doc: Record<string, unknown>;
} | null {
  if (relFile.startsWith('mcps/') && relFile.endsWith('/MCP.yaml')) {
    try {
      const parsed = parseYaml(text);
      return isPlainRecord(parsed) ? { kind: 'mcp', doc: parsed } : null;
    } catch {
      return null;
    }
  }
  const fm = splitMarkdownFrontmatter(text);
  if (!fm) return null;
  if (relFile.startsWith('skills/')) return { kind: 'skill', doc: fm.data };
  if (relFile.startsWith('rules/')) return { kind: 'rule', doc: fm.data };
  if (relFile.startsWith('subagents/')) return { kind: 'subagent', doc: fm.data };
  return null;
}

export function lintListingText(relFile: string, text: string, isExternal = false): ReviewFinding[] {
  const findings: ReviewFinding[] = [];
  const parsed = parseSourceMetadata(relFile, text);
  if (!parsed) return findings;

  const { kind, doc } = parsed;
  const meta = isPlainRecord(doc.metadata) ? doc.metadata : {};
  const trust = kind === 'skill' ? meta.trust : doc.trust;

  if (isExternal && trust === 'official') {
    findings.push({
      severity: 'CRITICAL',
      file: relFile,
      line: findKeyLine(text, 'trust'),
      title: 'External PR cannot claim trust: official',
      explanation: 'External contributions must use "community" (or "verified" with maintainer sign-off). Set trust: community.',
      source: 'deterministic',
    });
  }

  const summary = kind === 'skill'
    ? (typeof meta.summary === 'string' ? meta.summary : typeof doc.description === 'string' ? doc.description : '')
    : (typeof doc.summary === 'string' ? doc.summary : '');
  const description = typeof doc.description === 'string' ? doc.description : '';
  const hasExplicitSkillSummary = kind === 'skill' && typeof meta.summary === 'string';

  const summaryLine = findKeyLine(text, kind === 'skill' && !hasExplicitSkillSummary ? 'description' : 'summary');
  const descLine = findKeyLine(text, 'description');

  if (summary.length > 0) {
    const maxLen = kind === 'skill' && !hasExplicitSkillSummary ? 420 : 220;
    if (summary.length < 20) {
      findings.push({
        severity: 'SUGGESTION',
        file: relFile,
        line: summaryLine,
        title: 'Summary is too short for catalog discovery',
        explanation: `Summary is ${summary.length} chars; aim for 20..${maxLen} chars describing concrete capabilities.`,
        source: 'deterministic',
      });
    } else if (summary.length > maxLen) {
      findings.push({
        severity: 'SUGGESTION',
        file: relFile,
        line: summaryLine,
        title: 'Summary exceeds recommended discovery length',
        explanation: `Summary is ${summary.length} chars (target <= ${maxLen}). Tighten to one clear capability sentence.`,
        source: 'deterministic',
      });
    }
  }

  const textFields: Array<{ label: string; value: string; line: number }> = [];
  if (summary) textFields.push({ label: 'summary', value: summary, line: summaryLine });
  if (description && description !== summary) textFields.push({ label: 'description', value: description, line: descLine });

  for (const field of textFields) {
    const countMatch = field.value.match(HARDCODED_COUNT_RE);
    if (countMatch) {
      findings.push({
        severity: 'SUGGESTION',
        file: relFile,
        line: field.line,
        title: `Hardcoded count ("${countMatch[0]}") in ${field.label}`,
        explanation: `Hardcoded counts like "${countMatch[0]}" go stale as the server evolves and cannot be verified statically. Replace with capability phrasing.`,
        source: 'deterministic',
      });
    }
    const hypeMatch = field.value.match(MARKETING_HYPE_RE);
    if (hypeMatch) {
      findings.push({
        severity: 'SUGGESTION',
        file: relFile,
        line: field.line,
        title: `Marketing tagline phrasing ("${hypeMatch[0]}") in ${field.label}`,
        explanation: `Catalog ${field.label} copy should describe concrete capabilities rather than marketing claims ("${hypeMatch[0]}").`,
        source: 'deterministic',
      });
    }
    if (field.value.includes('—')) {
      findings.push({
        severity: 'SUGGESTION',
        file: relFile,
        line: field.line,
        title: `Prose em dash in ${field.label}`,
        explanation: 'Per Scalix house style, replace em dashes with colons, commas, or parentheses.',
        source: 'deterministic',
      });
    }
  }

  if (kind === 'mcp' && isPlainRecord(doc.payload)) {
    const serverUrl = doc.payload.serverUrl;
    if (doc.payload.transport === 'http' && typeof serverUrl === 'string' && !isPublicHttpsUrl(serverUrl)) {
      findings.push({
        severity: 'CRITICAL',
        file: relFile,
        line: findKeyLine(text, 'serverUrl'),
        title: 'MCP serverUrl fails public HTTPS / SSRF check',
        explanation: `serverUrl "${serverUrl}" must be https:// on a public non-private host (no localhost, RFC1918, link-local, or metadata hosts).`,
        source: 'deterministic',
      });
    }
  }

  for (const urlField of ['homepage_url', 'icon_url'] as const) {
    const raw = kind === 'skill' ? meta[urlField] : doc[urlField];
    if (typeof raw === 'string' && raw.length > 0 && !isPublicHttpsUrl(raw)) {
      findings.push({
        severity: 'WARNING',
        file: relFile,
        line: findKeyLine(text, urlField),
        title: `${urlField} is not a public HTTPS URL`,
        explanation: `${urlField} "${raw}" should be a public https:// URL.`,
        source: 'deterministic',
      });
    }
  }

  return findings;
}

export function scanTextForSecrets(relFile: string, lines: Array<{ line: number; text: string }>): ReviewFinding[] {
  const findings: ReviewFinding[] = [];
  for (const entry of lines) {
    if (looksLikeSecret(entry.text)) {
      findings.push({
        severity: 'CRITICAL',
        file: relFile,
        line: entry.line,
        title: 'Potential hardcoded secret or credential detected',
        explanation: 'Never commit credential values or live tokens. Use environment variable names (SCALIX_API_KEY) or {{ENV_VAR}} placeholders.',
        source: 'deterministic',
      });
      continue;
    }
    for (const pattern of EXTRA_SECRET_PATTERNS) {
      if (pattern.re.test(entry.text)) {
        findings.push({
          severity: 'CRITICAL',
          file: relFile,
          line: entry.line,
          title: `Potential ${pattern.label} detected`,
          explanation: 'Never commit real keys or Bearer tokens. Reference an environment variable name instead.',
          source: 'deterministic',
        });
        break;
      }
    }
  }
  return findings;
}

export function checkCatalogDrift(repoRoot: string, details: ListingDetail[]): ReviewFinding[] {
  const findings: ReviewFinding[] = [];
  const outDir = path.join(repoRoot, 'dist', 'listings');
  const indexPath = path.join(outDir, 'index.json');
  if (!fs.existsSync(indexPath)) {
    findings.push({
      severity: 'CRITICAL',
      file: 'dist/listings/index.json',
      line: 1,
      title: 'Generated catalog index.json is missing',
      explanation: 'Run `pnpm run generate` and commit updated files under dist/listings/.',
      source: 'deterministic',
    });
    return findings;
  }

  let existingIndex: { generated_at?: unknown; count?: unknown; listings?: unknown };
  try {
    existingIndex = JSON.parse(fs.readFileSync(indexPath, 'utf-8')) as typeof existingIndex;
  } catch {
    findings.push({
      severity: 'CRITICAL',
      file: 'dist/listings/index.json',
      line: 1,
      title: 'Generated catalog index.json is invalid JSON',
      explanation: 'Run `pnpm run generate` to regenerate dist/listings/.',
      source: 'deterministic',
    });
    return findings;
  }

  const expectedIndex = buildIndex(details, typeof existingIndex.generated_at === 'string' ? existingIndex.generated_at : '');
  if (
    existingIndex.count !== expectedIndex.count ||
    JSON.stringify(existingIndex.listings) !== JSON.stringify(expectedIndex.listings)
  ) {
    findings.push({
      severity: 'CRITICAL',
      file: 'dist/listings/index.json',
      line: 1,
      title: 'Generated dist/listings/index.json is out of date',
      explanation: 'Source entries changed without regenerating dist/listings/. Run `pnpm run generate` and commit the updated output.',
      source: 'deterministic',
    });
  }

  const expectedIds = new Set(details.map(d => d.id));
  for (const detail of details) {
    const detailRel = `dist/listings/${detail.id}.json`;
    const detailPath = path.join(outDir, `${detail.id}.json`);
    if (!fs.existsSync(detailPath)) {
      findings.push({
        severity: 'CRITICAL',
        file: detailRel,
        line: 1,
        title: `Missing generated catalog file ${detailRel}`,
        explanation: 'Run `pnpm run generate` and commit the generated listing file.',
        source: 'deterministic',
      });
      continue;
    }
    const actual = fs.readFileSync(detailPath, 'utf-8');
    const expected = `${JSON.stringify(detail, null, 2)}\n`;
    if (actual !== expected) {
      findings.push({
        severity: 'CRITICAL',
        file: detailRel,
        line: 1,
        title: `Generated file ${detailRel} is out of sync with source`,
        explanation: 'Run `pnpm run generate` and commit the regenerated listing file.',
        source: 'deterministic',
      });
    }
  }

  for (const entry of fs.readdirSync(outDir)) {
    if (entry === 'index.json' || !entry.endsWith('.json')) continue;
    const id = entry.slice(0, -'.json'.length);
    if (!expectedIds.has(id)) {
      findings.push({
        severity: 'CRITICAL',
        file: `dist/listings/${entry}`,
        line: 1,
        title: `Orphaned generated file dist/listings/${entry}`,
        explanation: 'Run `pnpm run generate` to remove stale generated JSON files.',
        source: 'deterministic',
      });
    }
  }

  return findings;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function inlineCode(value: string): string {
  return `\`${value.replace(/`/g, '%60')}\``;
}

function normalizedPublicUrl(value: unknown): string | null {
  if (typeof value !== 'string' || !isPublicHttpsUrl(value)) return null;
  return new URL(value).href;
}

export function buildMaintainerChecks(repoRoot: string, changedFiles: string[]): string[] {
  const checks: string[] = [];
  const seen = new Set<string>();
  const add = (item: string): void => {
    if (!seen.has(item)) {
      seen.add(item);
      checks.push(item);
    }
  };

  for (const relFile of changedFiles) {
    if (!SOURCE_FILE_RE.test(relFile)) continue;
    const absPath = path.join(repoRoot, relFile);
    if (!fs.existsSync(absPath)) continue;
    const parsed = parseSourceMetadata(relFile, fs.readFileSync(absPath, 'utf-8'));
    if (!parsed) continue;
    const { kind, doc } = parsed;
    const meta = isPlainRecord(doc.metadata) ? doc.metadata : {};
    const homepage = normalizedPublicUrl(kind === 'skill' ? meta.homepage_url : doc.homepage_url);
    if (homepage) {
      const ghMatch = homepage.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:[/?#]|$)/);
      if (ghMatch) {
        add(`Verify upstream repo (\`${relFile}\`): ${inlineCode(`gh api repos/${ghMatch[1].replace(/\.git$/, '')}`)}`);
      } else {
        add(`Verify homepage (\`${relFile}\`): ${inlineCode(`curl -fsSI ${shellQuote(homepage)}`)}`);
      }
    }
    if (kind === 'mcp' && isPlainRecord(doc.payload)) {
      const serverUrl = normalizedPublicUrl(doc.payload.serverUrl);
      if (doc.payload.transport === 'http' && serverUrl) {
        add(
          `Probe MCP discovery (\`${relFile}\`): ${inlineCode(`curl -sS -X POST ${shellQuote(serverUrl)} -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`)}`,
        );
      } else if (doc.payload.transport === 'stdio' && doc.payload.command === 'npx' && Array.isArray(doc.payload.args)) {
        const npmSpec = doc.payload.args.find(arg =>
          typeof arg === 'string' && /^(?:@[a-z0-9._-]+\/[a-z0-9._-]+|[a-z0-9._-]+)@(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/i.test(arg),
        );
        if (npmSpec) {
          add(`Inspect stdio package release (\`${relFile}\`): ${inlineCode(`npm view ${npmSpec} version dist.integrity --json`)}`);
        }
      }
    }
  }
  return checks;
}

function mapBuildErrorToFinding(repoRoot: string, errMsg: string): ReviewFinding {
  const colonIdx = errMsg.indexOf(': ');
  if (colonIdx > 0) {
    const maybeFile = errMsg.slice(0, colonIdx).trim();
    if (fs.existsSync(path.join(repoRoot, maybeFile))) {
      return {
        severity: 'CRITICAL',
        file: maybeFile,
        line: 1,
        title: 'Catalog schema/validation error',
        explanation: errMsg.slice(colonIdx + 2),
        source: 'deterministic',
      };
    }
  }
  return {
    severity: 'CRITICAL',
    file: 'catalog',
    line: 1,
    title: 'Catalog validation error',
    explanation: errMsg,
    source: 'deterministic',
  };
}

function listAllSourceFiles(repoRoot: string): string[] {
  const files: string[] = [];
  const mcpsDir = path.join(repoRoot, 'mcps');
  if (fs.existsSync(mcpsDir)) {
    for (const d of fs.readdirSync(mcpsDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (d.isDirectory() && fs.existsSync(path.join(mcpsDir, d.name, 'MCP.yaml'))) {
        files.push(`mcps/${d.name}/MCP.yaml`);
      }
    }
  }
  const skillsDir = path.join(repoRoot, 'skills');
  if (fs.existsSync(skillsDir)) {
    for (const d of fs.readdirSync(skillsDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (d.isDirectory() && fs.existsSync(path.join(skillsDir, d.name, 'SKILL.md'))) {
        files.push(`skills/${d.name}/SKILL.md`);
      }
    }
  }
  for (const folder of ['rules', 'subagents'] as const) {
    const dir = path.join(repoRoot, folder);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (f.isFile() && f.name.endsWith('.md')) files.push(`${folder}/${f.name}`);
    }
  }
  return files;
}

function parseUnifiedDiffAddedLines(diffText: string): Array<{ file: string; line: number; text: string }> {
  const added: Array<{ file: string; line: number; text: string }> = [];
  let currentFile = '';
  let currentLine = 0;

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith('+++ b/')) {
      currentFile = rawLine.slice('+++ b/'.length);
      continue;
    }
    if (rawLine.startsWith('+++ ')) {
      currentFile = '';
      continue;
    }
    const hunk = rawLine.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      currentLine = Number(hunk[1]);
      continue;
    }
    if (!currentFile) continue;
    if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      added.push({ file: currentFile, line: currentLine, text: rawLine.slice(1) });
      currentLine++;
    } else if (!rawLine.startsWith('-') && !rawLine.startsWith('\\')) {
      currentLine++;
    }
  }
  return added;
}

function gitChangedFiles(repoRoot: string, baseRef: string, headRef: string): {
  changedFiles: string[];
  diffText: string;
} {
  const range = `${baseRef}...${headRef}`;
  let changedOut = '';
  let diffText = '';
  try {
    changedOut = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMRT', range], {
      cwd: repoRoot,
      encoding: 'utf-8',
    });
    diffText = execFileSync('git', ['diff', '--unified=0', range], {
      cwd: repoRoot,
      encoding: 'utf-8',
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch {
    const fallbackRange = baseRef;
    changedOut = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMRT', fallbackRange], {
      cwd: repoRoot,
      encoding: 'utf-8',
    });
    diffText = execFileSync('git', ['diff', '--unified=0', fallbackRange], {
      cwd: repoRoot,
      encoding: 'utf-8',
      maxBuffer: 8 * 1024 * 1024,
    });
  }
  const untracked = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], {
    cwd: repoRoot,
    encoding: 'utf-8',
  });
  const set = new Set<string>();
  for (const line of [...changedOut.split(/\r?\n/), ...untracked.split(/\r?\n/)]) {
    const trimmed = line.trim();
    if (trimmed) set.add(trimmed);
  }
  return { changedFiles: [...set].sort(), diffText };
}

export async function runAiSemanticReview(params: {
  repoRoot: string;
  diffText: string;
  apiKey?: string;
  baseUrl?: string;
  model?: string;
  skipAi?: boolean;
  fetchImpl?: typeof fetch;
}): Promise<{
  status: 'completed' | 'skipped' | 'error';
  note: string;
  findings: ReviewFinding[];
}> {
  if (params.skipAi) {
    return { status: 'skipped', note: 'AI semantic pass disabled (--no-ai); deterministic checks ran.', findings: [] };
  }
  if (!params.apiKey) {
    return {
      status: 'skipped',
      note: 'AI semantic pass skipped (SCALIX_REVIEW_BOT_API_KEY not set); deterministic checks ran.',
      findings: [],
    };
  }
  if (!params.diffText.trim()) {
    return { status: 'skipped', note: 'AI semantic pass skipped (empty diff); deterministic checks ran.', findings: [] };
  }

  const contribPath = path.join(params.repoRoot, 'CONTRIBUTING.md');
  const contributing = fs.existsSync(contribPath) ? fs.readFileSync(contribPath, 'utf-8').slice(0, 8000) : '';
  const diffSnippet = params.diffText.slice(0, 24_000);
  const baseUrl = (params.baseUrl || 'https://api.scalix.world/v1').replace(/\/+$/, '');
  const model = params.model || 'openai/gpt-4o-mini';
  const fetchFn = params.fetchImpl ?? fetch;

  const systemPrompt = [
    'You are scalix-review-bot, the automated PR maintainer for Scalix Marketplace.',
    'Review the PR diff strictly against CONTRIBUTING.md and security/catalog quality rules.',
    'Never praise. Only report concrete issues with exact file path and line number.',
    'Return valid JSON ONLY in this exact shape: {"findings":[{"severity":"CRITICAL|WARNING|SUGGESTION","file":"path","line":1,"title":"short headline","explanation":"why and concrete fix"}]}.',
    'If there are no issues, return {"findings":[]}.',
  ].join(' ');

  const userPrompt = `## CONTRIBUTING.md\n${contributing}\n\n## PR Diff\n\`\`\`diff\n${diffSnippet}\n\`\`\``;

  try {
    const res = await fetchFn(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${params.apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      return {
        status: 'error',
        note: `AI semantic pass degraded (HTTP ${res.status}); deterministic checks ran.`,
        findings: [],
      };
    }
    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const rawContent = data.choices?.[0]?.message?.content?.trim() ?? '';
    const jsonMatch = rawContent.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        status: 'error',
        note: 'AI semantic pass degraded (non-JSON response); deterministic checks ran.',
        findings: [],
      };
    }
    const parsed = JSON.parse(jsonMatch[0]) as { findings?: unknown };
    if (!Array.isArray(parsed.findings)) {
      return {
        status: 'error',
        note: 'AI semantic pass degraded (missing findings array); deterministic checks ran.',
        findings: [],
      };
    }
    const findings: ReviewFinding[] = [];
    for (const item of parsed.findings) {
      if (!isPlainRecord(item)) continue;
      const sev = item.severity;
      if (sev !== 'CRITICAL' && sev !== 'WARNING' && sev !== 'SUGGESTION') continue;
      if (typeof item.file !== 'string' || typeof item.title !== 'string' || typeof item.explanation !== 'string') continue;
      const line = typeof item.line === 'number' && Number.isFinite(item.line) && item.line > 0 ? Math.floor(item.line) : 1;
      findings.push({
        severity: sev,
        file: item.file,
        line,
        title: item.title,
        explanation: item.explanation,
        source: 'ai',
      });
    }
    return { status: 'completed', note: `AI semantic pass completed (${model}).`, findings };
  } catch (err) {
    return {
      status: 'error',
      note: `AI semantic pass degraded (${(err as Error).message}); deterministic checks ran.`,
      findings: [],
    };
  }
}

function dedupeFindings(findings: ReviewFinding[]): ReviewFinding[] {
  const seen = new Set<string>();
  const out: ReviewFinding[] = [];
  for (const f of findings) {
    const key = `${f.severity}|${f.file}|${f.line}|${f.title.trim().toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  out.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const fileDiff = a.file.localeCompare(b.file);
    if (fileDiff !== 0) return fileDiff;
    return a.line - b.line;
  });
  return out;
}

function escapeCell(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/@/g, '&#64;')
    .replace(/`/g, '\\`')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

export function formatReviewComment(report: Omit<ReviewReport, 'comment_markdown'>): string {
  const total = report.findings.length;
  const statusLine =
    total === 0
      ? '**Status:** No Issues Found | **Recommendation:** Merge'
      : `**Status:** ${total} ${total === 1 ? 'Issue' : 'Issues'} Found | **Recommendation:** Address before merge`;

  const lines: string[] = [
    BOT_MARKER,
    '',
    '## Scalix Maintainer Review Summary',
    '',
    statusLine,
    '',
    '| Severity | Count |',
    '|---|---|',
    `| CRITICAL | ${report.counts.critical} |`,
    `| WARNING | ${report.counts.warning} |`,
    `| SUGGESTION | ${report.counts.suggestion} |`,
    '',
  ];

  if (total > 0) {
    lines.push('### Findings', '| Severity | File | Line | Issue |', '|---|---|---|---|');
    for (const f of report.findings) {
      lines.push(`| ${f.severity} | \`${escapeCell(f.file)}\` | ${f.line} | ${escapeCell(f.title)}: ${escapeCell(f.explanation)} |`);
    }
    lines.push('');
  } else {
    lines.push('All catalog schema, security, house-style, and generated-output checks passed.', '');
  }

  lines.push(`**Review Passes:** Deterministic checks passed${total > 0 ? ' with findings' : ''}; ${report.ai_review_note}`, '');

  if (report.maintainer_checks.length > 0) {
    lines.push('### Maintainer Quick-Verify', 'External URLs and endpoints are not fetched during PR CI. Maintainer checks:');
    for (const check of report.maintainer_checks) {
      lines.push(`- ${check}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function listingSourceFile(detail: ListingDetail): string {
  if (detail.kind === 'mcp') return `mcps/${detail.id}/MCP.yaml`;
  if (detail.kind === 'skill') return `skills/${detail.id}/SKILL.md`;
  return `${detail.kind === 'rule' ? 'rules' : 'subagents'}/${detail.id}.md`;
}

export async function runReview(options: ReviewOptions): Promise<ReviewReport> {
  const repoRoot = path.resolve(options.repoRoot);
  const changedFiles = options.changedFiles ?? (options.checkAll ? listAllSourceFiles(repoRoot) : []);
  const findings: ReviewFinding[] = [];

  const { details, errors } = buildCatalog(repoRoot);
  for (const err of errors) {
    findings.push(mapBuildErrorToFinding(repoRoot, err));
  }
  if (errors.length === 0) {
    const byId = new Map(details.map(detail => [detail.id, detail]));
    for (const issue of await validateCatalogDns(details, options.dnsLookup)) {
      const detail = byId.get(issue.id);
      findings.push({
        severity: 'CRITICAL',
        file: detail ? listingSourceFile(detail) : 'catalog',
        line: 1,
        title: `${issue.field} fails DNS public-network validation`,
        explanation: `${issue.reason}. Every DNS answer must be a public address; private, loopback, link-local, and special-use addresses are forbidden.`,
        source: 'deterministic',
      });
    }
  }

  for (const relFile of changedFiles) {
    if (!SOURCE_FILE_RE.test(relFile)) continue;
    const absPath = path.join(repoRoot, relFile);
    if (!fs.existsSync(absPath)) continue;
    const text = fs.readFileSync(absPath, 'utf-8');
    findings.push(...lintListingText(relFile, text, options.isExternal === true));
    const fileLines = text.split(/\r?\n/).map((lineText, idx) => ({ line: idx + 1, text: lineText }));
    findings.push(...scanTextForSecrets(relFile, fileLines));
  }

  if (options.addedLines && options.addedLines.length > 0) {
    const byFile = new Map<string, Array<{ line: number; text: string }>>();
    for (const entry of options.addedLines) {
      if (SOURCE_FILE_RE.test(entry.file)) continue; // already scanned full file above
      if (entry.file.startsWith('dist/')) continue;
      if (!byFile.has(entry.file)) byFile.set(entry.file, []);
      byFile.get(entry.file)!.push({ line: entry.line, text: entry.text });
    }
    for (const [file, lines] of byFile) {
      findings.push(...scanTextForSecrets(file, lines));
    }
  }

  if (errors.length === 0) {
    findings.push(...checkCatalogDrift(repoRoot, details));
  }

  const aiResult = await runAiSemanticReview({
    repoRoot,
    diffText: options.diffText ?? '',
    apiKey: options.aiApiKey,
    baseUrl: options.aiBaseUrl,
    model: options.aiModel,
    skipAi: options.skipAi,
  });
  findings.push(...aiResult.findings);

  const deduped = dedupeFindings(findings);
  const counts: ReviewCounts = {
    critical: deduped.filter(f => f.severity === 'CRITICAL').length,
    warning: deduped.filter(f => f.severity === 'WARNING').length,
    suggestion: deduped.filter(f => f.severity === 'SUGGESTION').length,
  };
  const status: 'pass' | 'fail' = deduped.length === 0 ? 'pass' : 'fail';
  const recommendation: 'Merge' | 'Address before merge' = status === 'pass' ? 'Merge' : 'Address before merge';
  const maintainer_checks = buildMaintainerChecks(repoRoot, changedFiles);

  const partial = {
    status,
    recommendation,
    counts,
    ai_review_status: aiResult.status,
    ai_review_note: aiResult.note,
    findings: deduped,
    maintainer_checks,
    reviewed_files: changedFiles,
  };

  return {
    ...partial,
    comment_markdown: formatReviewComment(partial),
  };
}

function argValue(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  return idx >= 0 && process.argv[idx + 1] ? process.argv[idx + 1] : undefined;
}

async function main(): Promise<void> {
  const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const repoRoot = path.resolve(argValue('--repo-root') ?? defaultRoot);
  const baseRef = argValue('--base');
  const headRef = argValue('--head') ?? 'HEAD';
  const outputPath = argValue('--output');
  const isExternal = process.argv.includes('--external');
  const skipAi = process.argv.includes('--no-ai');
  const checkAll = process.argv.includes('--all') || !baseRef;

  let changedFiles: string[] = [];
  let diffText = '';
  let addedLines: Array<{ file: string; line: number; text: string }> = [];

  if (baseRef) {
    const gitRes = gitChangedFiles(repoRoot, baseRef, headRef);
    changedFiles = gitRes.changedFiles;
    diffText = gitRes.diffText;
    addedLines = parseUnifiedDiffAddedLines(diffText);
  }
  if (checkAll && changedFiles.length === 0) {
    changedFiles = listAllSourceFiles(repoRoot);
  }

  const report = await runReview({
    repoRoot,
    changedFiles,
    addedLines,
    diffText,
    isExternal,
    skipAi,
    checkAll,
    aiApiKey: process.env.SCALIX_REVIEW_BOT_API_KEY,
    aiBaseUrl: process.env.SCALIX_AI_BASE_URL,
    aiModel: process.env.SCALIX_REVIEW_BOT_MODEL,
  });

  if (outputPath) {
    fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(report, null, 2)}\n`);
  }

  console.log(report.comment_markdown);
  if (report.status === 'fail') {
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => {
    console.error('scalix-review-bot failed:', err);
    process.exit(1);
  });
}
