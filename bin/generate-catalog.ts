#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

export const KINDS = ['mcp', 'skill', 'rule', 'subagent'] as const;
export type MarketplaceKind = (typeof KINDS)[number];
export const TRUSTS = ['official', 'verified', 'community'] as const;
export type MarketplaceTrust = (typeof TRUSTS)[number];
export const SURFACES = ['coder', 'ide', 'editor'] as const;
export type Surface = (typeof SURFACES)[number];

export const LISTING_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-_]{0,32})?$/;
export const ENV_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
export const BARE_COMMAND_RE = /^[A-Za-z0-9._@-]{1,64}$/;
const SAFE_PATH_SEGMENT_RE = /^[A-Za-z0-9._ -]+$/;

const MAX_FILES = 10;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_PAYLOAD_BYTES = 1024 * 1024;
const MAX_ARGS = 20;
const MAX_ARG_BYTES = 512;
const MAX_HEADERS = 16;
const MAX_HEADER_KEY = 128;
const MAX_HEADER_VALUE = 1024;
const MAX_ENV_NAMES = 8;
const MAX_URL_BYTES = 2048;
const MAX_SUMMARY = 512;
const MAX_NAME = 128;

const SECRET_PATTERNS: RegExp[] = [
  /sk-[a-z0-9]{12,}/,
  /sk_live/,
  /sk_test/,
  /bearer [a-z0-9._-]{16,}/,
  /ghp_[a-z0-9]{8,}/,
  /gho_[a-z0-9]{8,}/,
  /ghu_[a-z0-9]{8,}/,
  /github_pat_[a-z0-9]{8,}/,
  /glpat-[a-z0-9]{8,}/,
  /xoxb-[a-z0-9-]{8,}/,
  /xoxp-[a-z0-9-]{8,}/,
  /scalix_at_[a-z0-9]{8,}/,
  /api_key=\s*[a-z0-9]{8,}/,
  /apikey=\s*[a-z0-9]{8,}/,
  /api-key:\s*[a-z0-9]{8,}/,
  /token=\s*[a-z0-9]{8,}/,
  /access_token\s*[:=]\s*[a-z0-9]{8,}/,
  /refresh_token\s*[:=]\s*[a-z0-9]{8,}/,
  /secret=\s*[a-z0-9]{8,}/,
  /password=\s*[a-z0-9]{8,}/,
  /passwd=\s*[a-z0-9]{8,}/,
  /aws_secret/,
  /private_key\s*[:=]\s*[a-z0-9]{8,}/,
  /-----begin/,
];

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(v => typeof v === 'string');
}

export function isValidListingId(id: string): boolean {
  return LISTING_ID_RE.test(id);
}

export function isValidVersion(version: string): boolean {
  return VERSION_RE.test(version);
}

export function isEnvName(name: string): boolean {
  return name.length > 0 && name.length <= 64 && ENV_RE.test(name);
}

export function isBareCommand(command: string): boolean {
  if (command.length === 0 || command.length > 64) return false;
  if (command.includes('/') || command.includes('\\') || command.includes('..')) return false;
  return BARE_COMMAND_RE.test(command);
}

export function isSafeFileName(name: string): boolean {
  if (name.length === 0 || name.length > MAX_NAME) return false;
  if (name.includes('/') || name.includes('\\') || name.includes('..')) return false;
  if (name === '.' || name.startsWith('-')) return false;
  return /^[A-Za-z0-9._ -]+$/.test(name);
}

export function isSafeRelativePath(rel: string): boolean {
  if (rel.length === 0 || rel.length > 256) return false;
  if (rel.startsWith('/') || rel.startsWith('\\') || rel.includes('\\')) return false;
  if (rel.includes('..')) return false;
  if (rel.endsWith('/') || rel.includes('//')) return false;
  const segments = rel.split('/');
  if (segments.length > 6) return false;
  return segments.every(segment => {
    if (segment.length === 0 || segment === '.' || segment.startsWith('-')) return false;
    if (segment.includes(':')) return false;
    return SAFE_PATH_SEGMENT_RE.test(segment);
  });
}

function canonicalizeIpv4(host: string): string | null {
  const raw = host.replace(/^\[|\]$/g, '');
  const part = (token: string, allowHex: boolean): number | null => {
    if (allowHex && /^0x[0-9a-f]{1,2}$/i.test(token)) return parseInt(token.slice(2), 16);
    if (/^\d{1,3}$/.test(token)) return Number(token);
    return null;
  };
  if (/^\d+$/.test(raw)) {
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value > 0xffffffff) return null;
    return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.');
  }
  if (/^0x[0-9a-f]{1,8}$/i.test(raw)) {
    const value = parseInt(raw, 16);
    if (!Number.isSafeInteger(value) || value > 0xffffffff) return null;
    return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.');
  }
  const tokens = raw.split('.');
  if (tokens.length < 2 || tokens.length > 4) return null;
  const last = part(tokens.pop()!, true);
  if (last === null || last > 255) return null;
  const head: number[] = [];
  for (const token of tokens) {
    const value = part(token, false);
    if (value === null || value > 255) return null;
    head.push(value);
  }
  const restMax = Math.pow(256, 4 - head.length);
  if (last >= restMax) return null;
  let value = last;
  for (let i = 0; i < head.length; i++) {
    value += head[i] * Math.pow(256, 3 - i);
  }
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.');
}

const PRIVATE_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'instance-data',
  '0.0.0.0',
  '::',
  '::1',
]);
const PRIVATE_SUFFIXES = ['.localhost', '.localdomain', '.local', '.internal'];
const PRIVATE_CIDRS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^192\.0\.0\./,
  /^192\.0\.2\./,
  /^198\.18\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
  /^24[0-9]\./,
  /^25[0-5]\./,
  /^0\./,
];

function isPrivateIpv4Octets(o: [number, number, number, number]): boolean {
  return (
    o[0] === 0 ||
    o[0] === 10 ||
    o[0] === 127 ||
    (o[0] === 169 && o[1] === 254) ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    (o[0] === 100 && o[1] >= 64 && o[1] <= 127) ||
    (o[0] === 192 && o[1] === 0 && o[2] === 0) ||
    (o[0] === 192 && o[1] === 0 && o[2] === 2) ||
    (o[0] === 198 && o[1] === 18) ||
    (o[0] === 198 && o[1] === 51 && o[2] === 100) ||
    (o[0] === 203 && o[1] === 0 && o[2] === 113) ||
    o[0] >= 240
  );
}

function isPrivateIpv6(host: string): boolean {
  const a = host.toLowerCase().split('%')[0];
  if (!a.includes(':')) return false;
  if (a === '::' || a === '::1' || a === '0:0:0:0:0:0:0:1') return true;
  const m = a.match(/^::(?:ffff:)?([0-9a-f.:]+)$/);
  if (m) {
    if (m[1].includes('.')) {
      const dotted = canonicalizeIpv4(m[1]);
      if (!dotted) return true;
      const parts = dotted.split('.').map(Number) as [number, number, number, number];
      return isPrivateIpv4Octets(parts);
    }
    const hx = m[1].match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hx) {
      const n = (parseInt(hx[1], 16) * 0x10000) + parseInt(hx[2], 16);
      return isPrivateIpv4Octets([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
    }
    return true;
  }
  const head = parseInt(a.split(':')[0] || 'z', 16);
  if (!Number.isFinite(head)) return true;
  if ((head & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((head & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((head & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  return false;
}

export function isPrivateHost(host: string): boolean {
  const raw = host.trim().replace(/^\[|\]$/g, '');
  const lower = raw.toLowerCase();
  if (!lower) return true;
  if (PRIVATE_HOSTNAMES.has(lower)) return true;
  const canonical = canonicalizeIpv4(lower);
  const candidate = canonical ?? lower;
  if (PRIVATE_HOSTNAMES.has(candidate)) return true;
  if (PRIVATE_SUFFIXES.some(suffix => candidate.endsWith(suffix))) return true;
  if (PRIVATE_CIDRS.some(re => re.test(candidate))) return true;
  return isPrivateIpv6(lower);
}

export function isPublicHttpsUrl(raw: string): boolean {
  if (raw.length === 0 || raw.length > MAX_URL_BYTES) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  if (url.username !== '' || url.password !== '') return false;
  const host = url.hostname;
  if (host.length === 0) return false;
  return !isPrivateHost(host);
}

export function looksLikeSecret(value: string): boolean {
  const lower = value.toLowerCase();
  return SECRET_PATTERNS.some(pattern => pattern.test(lower));
}

function scanSecrets(field: string, value: string): string[] {
  if (looksLikeSecret(value)) {
    return [`${field} looks like a credential value: the catalog stores env-var NAMES only`];
  }
  return [];
}

function hasControlChars(value: string): boolean {
  return /[\x00-\x1f\x7f]/.test(value);
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

export interface PayloadFile {
  path: string;
  content: string;
}

export interface McpPayload {
  kind: 'mcp';
  transport: 'http' | 'stdio';
  serverLabel: string;
  serverUrl?: string;
  authorizationEnv?: string;
  headers?: Record<string, string>;
  requiredEnv?: string[];
  command?: string;
  args?: string[];
}

export interface SkillPayload {
  kind: 'skill';
  name: string;
  files: PayloadFile[];
}

export interface FilePayload {
  kind: 'rule' | 'subagent';
  fileName: string;
  content: string;
}

export type MarketplacePayload = McpPayload | SkillPayload | FilePayload;

export function validateMcpPayload(raw: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (raw.kind !== 'mcp') errors.push('payload.kind must be "mcp"');
  const transport = raw.transport;
  if (transport !== 'http' && transport !== 'stdio') {
    errors.push('mcp.transport must be "http" or "stdio"');
    return errors;
  }
  const allowed = new Set(['kind', 'transport', 'serverLabel', 'serverUrl', 'authorizationEnv', 'headers', 'requiredEnv', 'command', 'args']);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) errors.push(`payload has unknown field "${key}"`);
  }
  const serverLabel = raw.serverLabel;
  if (typeof serverLabel !== 'string' || serverLabel.length < 2 || !isSafeFileName(serverLabel)) {
    errors.push('mcp.serverLabel must be 2..=128 chars of [A-Za-z0-9._ -]');
  }
  if (transport === 'http') {
    const serverUrl = raw.serverUrl;
    if (typeof serverUrl !== 'string' || !isPublicHttpsUrl(serverUrl)) {
      errors.push('mcp.serverUrl must be an https URL on a public host');
    }
    if (raw.command !== undefined || raw.args !== undefined) {
      errors.push('mcp http transport must not carry a stdio command');
    }
  } else {
    const command = raw.command;
    if (typeof command !== 'string' || !isBareCommand(command)) {
      errors.push('mcp.command must be a bare command name (no paths, no shell metacharacters)');
    }
    if (raw.serverUrl !== undefined) {
      errors.push('mcp stdio transport must not carry serverUrl');
    }
    if (raw.args !== undefined) {
      if (!Array.isArray(raw.args)) {
        errors.push('mcp.args must be an array');
      } else {
        if (raw.args.length > MAX_ARGS) errors.push(`mcp.args carries more than ${MAX_ARGS} entries`);
        raw.args.forEach((arg, index) => {
          if (typeof arg !== 'string' || arg.length === 0 || arg.length > MAX_ARG_BYTES || hasControlChars(arg)) {
            errors.push(`mcp.args[${index}] must be 1..=${MAX_ARG_BYTES} printable chars`);
          }
          if (typeof arg === 'string') errors.push(...scanSecrets(`mcp.args[${index}]`, arg));
        });
      }
    }
  }
  if (raw.authorizationEnv !== undefined) {
    if (typeof raw.authorizationEnv !== 'string' || !isEnvName(raw.authorizationEnv)) {
      errors.push('mcp.authorizationEnv must be an env-var NAME');
    }
  }
  if (raw.requiredEnv !== undefined) {
    if (!Array.isArray(raw.requiredEnv)) {
      errors.push('mcp.requiredEnv must be an array');
    } else {
      if (raw.requiredEnv.length > MAX_ENV_NAMES) errors.push(`mcp.requiredEnv carries more than ${MAX_ENV_NAMES} names`);
      raw.requiredEnv.forEach((name, index) => {
        if (typeof name !== 'string' || !isEnvName(name)) errors.push(`mcp.requiredEnv[${index}] must be an env-var NAME`);
      });
    }
  }
  if (raw.headers !== undefined) {
    if (!isPlainRecord(raw.headers)) {
      errors.push('mcp.headers must be an object');
    } else {
      const entries = Object.entries(raw.headers);
      if (entries.length > MAX_HEADERS) errors.push(`mcp.headers carries more than ${MAX_HEADERS} entries`);
      for (const [key, value] of entries) {
        if (key.length === 0 || key.length > MAX_HEADER_KEY || !/^[A-Za-z0-9_-]+$/.test(key)) {
          errors.push(`mcp.headers key "${key}" must be token-shaped`);
        }
        if (typeof value !== 'string' || value.length === 0 || value.length > MAX_HEADER_VALUE || hasControlChars(value)) {
          errors.push(`mcp.headers[${JSON.stringify(key)}] must be 1..=${MAX_HEADER_VALUE} printable chars`);
        } else {
          errors.push(...scanSecrets(`mcp.headers[${JSON.stringify(key)}]`, value));
        }
      }
    }
  }
  if (typeof raw.serverLabel === 'string') errors.push(...scanSecrets('mcp.serverLabel', raw.serverLabel));
  if (typeof raw.serverUrl === 'string') errors.push(...scanSecrets('mcp.serverUrl', raw.serverUrl));
  if (typeof raw.command === 'string') errors.push(...scanSecrets('mcp.command', raw.command));
  return errors;
}

export function validateSkillPayload(id: string, files: PayloadFile[]): string[] {
  const errors: string[] = [];
  if (files.length === 0 || files.length > MAX_FILES) {
    errors.push(`skill payload must carry 1..=${MAX_FILES} files (got ${files.length})`);
  }
  let total = 0;
  const seen = new Set<string>();
  for (const file of files) {
    if (!isSafeRelativePath(file.path)) {
      errors.push(`skill file path "${file.path}" is not a safe relative path`);
      continue;
    }
    if (seen.has(file.path)) {
      errors.push(`skill file path "${file.path}" appears twice`);
    }
    seen.add(file.path);
    if (typeof file.content !== 'string') {
      errors.push(`skill file "${file.path}" content must be a string`);
      continue;
    }
    if (byteLength(file.content) > MAX_FILE_BYTES) {
      errors.push(`skill file "${file.path}" exceeds the ${MAX_FILE_BYTES}-byte cap`);
    }
    total += byteLength(file.content);
    errors.push(...scanSecrets(`skill file "${file.path}"`, file.content));
  }
  if (total > MAX_PAYLOAD_BYTES) {
    errors.push('skill payload exceeds the 1 MB total cap');
  }
  if (!files.some(file => file.path === 'SKILL.md')) {
    errors.push('skill payload must include a root SKILL.md');
  }
  return errors;
}

export function validateFilePayload(kind: 'rule' | 'subagent', fileName: string, content: string): string[] {
  const errors: string[] = [];
  if (!isSafeFileName(fileName)) {
    errors.push(`${kind}.fileName must be a bare file name`);
  }
  if (!fileName.endsWith('.md')) {
    errors.push(`${kind}.fileName must end in .md`);
  }
  if (content.length === 0 || byteLength(content) > MAX_FILE_BYTES) {
    errors.push(`${kind}.content must be 1..=${MAX_FILE_BYTES} bytes`);
  }
  errors.push(...scanSecrets(`${kind}.content`, content));
  return errors;
}

function validateCommon(fields: Record<string, unknown>, kind: MarketplaceKind, id: string): string[] {
  const errors: string[] = [];
  if (!isValidListingId(id)) errors.push(`id "${id}" must match ${LISTING_ID_RE}`);
  if (!KINDS.includes(kind)) errors.push(`unknown listing kind "${kind}"`);
  if (!isNonEmptyString(fields.name) || fields.name.length > MAX_NAME) {
    errors.push('name must be a 1..=128 char string');
  }
  if (!isNonEmptyString(fields.summary) || fields.summary.length > MAX_SUMMARY) {
    errors.push('summary must be a 1..=512 char string');
  }
  if (!isNonEmptyString(fields.author)) errors.push('author must be a non-empty string');
  if (!TRUSTS.includes(fields.trust as MarketplaceTrust)) errors.push('trust must be one of official | verified | community');
  if (typeof fields.version !== 'string' || !isValidVersion(fields.version)) {
    errors.push('version must be semver (1.2.3 with optional short suffix)');
  }
  if (fields.featured !== undefined && typeof fields.featured !== 'boolean') errors.push('featured must be a boolean');
  if (fields.categories !== undefined && !isStringArray(fields.categories)) errors.push('categories must be an array of strings');
  if (fields.tags !== undefined && !isStringArray(fields.tags)) errors.push('tags must be an array of strings');
  if (fields.surfaces !== undefined) {
    if (!isStringArray(fields.surfaces)) {
      errors.push('surfaces must be an array of strings');
    } else {
      for (const surface of fields.surfaces) {
        if (!SURFACES.includes(surface as Surface)) errors.push(`surface "${surface}" must be one of ${SURFACES.join(', ')}`);
      }
    }
  }
  if (fields.description !== undefined && typeof fields.description !== 'string') errors.push('description must be a string');
  if (fields.homepage_url !== undefined && (typeof fields.homepage_url !== 'string' || fields.homepage_url.length === 0)) {
    errors.push('homepage_url must be a non-empty string');
  }
  if (fields.icon_url !== undefined && (typeof fields.icon_url !== 'string' || fields.icon_url.length === 0)) {
    errors.push('icon_url must be a non-empty string');
  }
  return errors;
}

export interface ListingDetail {
  id: string;
  kind: MarketplaceKind;
  name: string;
  summary: string;
  description: string;
  author: string;
  homepage_url: string;
  icon_url: string;
  trust: MarketplaceTrust;
  install_count: number;
  version: string;
  featured: boolean;
  categories: string[];
  tags: string[];
  surfaces: Surface[];
  payload: MarketplacePayload;
}

function splitFrontmatter(text: string): { data: Record<string, unknown>; body: string } {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) throw new Error('missing YAML frontmatter (--- block)');
  const data = parseYaml(match[1]);
  if (!isPlainRecord(data)) throw new Error('frontmatter must be a YAML mapping');
  return { data, body: text.slice(match[0].length) };
}

function readSkillFiles(dir: string): PayloadFile[] {
  const files: PayloadFile[] = [];
  const walk = (relDir: string): void => {
    for (const entry of fs.readdirSync(path.join(dir, relDir), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.name.startsWith('.')) continue;
      const rel = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(rel);
      } else if (entry.isFile()) {
        files.push({ path: rel, content: fs.readFileSync(path.join(dir, rel), 'utf-8') });
      }
    }
  };
  walk('');
  files.sort((a, b) => {
    if (a.path === 'SKILL.md') return -1;
    if (b.path === 'SKILL.md') return 1;
    return a.path.localeCompare(b.path);
  });
  return files;
}

function asStringOr(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

function asStringArrayOr(value: unknown, fallback: string[]): string[] {
  return isStringArray(value) ? value : fallback;
}

function loadMcp(repoRoot: string, dir: string, errors: string[]): ListingDetail | null {
  const id = path.basename(dir);
  const file = path.join(repoRoot, 'mcps', id, 'MCP.yaml');
  let doc: Record<string, unknown>;
  try {
    const parsed = parseYaml(fs.readFileSync(file, 'utf-8'));
    if (!isPlainRecord(parsed)) throw new Error('MCP.yaml must be a YAML mapping');
    doc = parsed;
  } catch (err) {
    errors.push(`${path.relative(repoRoot, file)}: ${(err as Error).message}`);
    return null;
  }
  const dirErrors = validateCommon(doc, 'mcp', id);
  if (doc.id !== undefined && doc.id !== id) dirErrors.push(`id "${String(doc.id)}" does not match directory "${id}"`);
  if (!isPlainRecord(doc.payload)) {
    dirErrors.push('payload must be a mapping');
  } else {
    dirErrors.push(...validateMcpPayload(doc.payload));
  }
  if (dirErrors.length > 0) {
    errors.push(`${path.relative(repoRoot, file)}: ${dirErrors.join('; ')}`);
    return null;
  }
  return {
    id,
    kind: 'mcp',
    name: doc.name as string,
    summary: doc.summary as string,
    description: typeof doc.description === 'string' ? doc.description : '',
    author: doc.author as string,
    homepage_url: typeof doc.homepage_url === 'string' ? doc.homepage_url : '',
    icon_url: typeof doc.icon_url === 'string' ? doc.icon_url : '',
    trust: doc.trust as MarketplaceTrust,
    install_count: 0,
    version: doc.version as string,
    featured: doc.featured === true,
    categories: asStringArrayOr(doc.categories, []),
    tags: asStringArrayOr(doc.tags, []),
    surfaces: asStringArrayOr(doc.surfaces, ['coder', 'ide', 'editor']) as Surface[],
    payload: doc.payload as unknown as MarketplacePayload,
  };
}

function loadSkill(repoRoot: string, dir: string, errors: string[]): ListingDetail | null {
  const id = path.basename(dir);
  const file = path.join(repoRoot, 'skills', id, 'SKILL.md');
  let data: Record<string, unknown>;
  let files: PayloadFile[];
  try {
    const parsed = splitFrontmatter(fs.readFileSync(file, 'utf-8'));
    data = parsed.data;
    files = readSkillFiles(path.dirname(file));
  } catch (err) {
    errors.push(`${path.relative(repoRoot, file)}: ${(err as Error).message}`);
    return null;
  }
  const description = asStringOr(data.description, '');
  if (description.length === 0) {
    errors.push(`${path.relative(repoRoot, file)}: missing description frontmatter`);
    return null;
  }
  const name = asStringOr(data.name, id);
  if (name !== id) {
    errors.push(`${path.relative(repoRoot, file)}: frontmatter name "${name}" does not match directory "${id}"`);
    return null;
  }
  const metadata = isPlainRecord(data.metadata) ? data.metadata : {};
  const payloadErrors = validateSkillPayload(id, files);
  if (payloadErrors.length > 0) {
    errors.push(`${path.relative(repoRoot, file)}: ${payloadErrors.join('; ')}`);
    return null;
  }
  const summary = asStringOr(metadata.summary, description);
  const detail = validateCommon(
    {
      name,
      summary,
      description,
      author: asStringOr(metadata.author, 'Scalix World'),
      trust: asStringOr(metadata.trust, 'community'),
      version: asStringOr(metadata.version, '1.0.0'),
      featured: metadata.featured,
      categories: metadata.categories,
      tags: metadata.tags,
      surfaces: metadata.surfaces,
    },
    'skill',
    id,
  );
  if (detail.length > 0) {
    errors.push(`${path.relative(repoRoot, file)}: ${detail.join('; ')}`);
    return null;
  }
  if (byteLength(summary) > MAX_SUMMARY) {
    errors.push(`${path.relative(repoRoot, file)}: summary exceeds ${MAX_SUMMARY} chars`);
    return null;
  }
  return {
    id,
    kind: 'skill',
    name,
    summary,
    description,
    author: asStringOr(metadata.author, 'Scalix World'),
    homepage_url: asStringOr(metadata.homepage_url, ''),
    icon_url: asStringOr(metadata.icon_url, ''),
    trust: asStringOr(metadata.trust, 'community') as MarketplaceTrust,
    install_count: 0,
    version: asStringOr(metadata.version, '1.0.0'),
    featured: metadata.featured === true,
    categories: asStringArrayOr(metadata.categories, []),
    tags: asStringArrayOr(metadata.tags, []),
    surfaces: asStringArrayOr(metadata.surfaces, ['coder', 'ide', 'editor']) as Surface[],
    payload: { kind: 'skill', name: id, files },
  };
}

function loadMarkdownListing(repoRoot: string, kind: 'rule' | 'subagent', filePath: string, errors: string[]): ListingDetail | null {
  const id = path.basename(filePath, '.md');
  let data: Record<string, unknown>;
  let body: string;
  try {
    const parsed = splitFrontmatter(fs.readFileSync(filePath, 'utf-8'));
    data = parsed.data;
    body = parsed.body;
    if (body.trim() === '') throw new Error('body after frontmatter is empty');
  } catch (err) {
    errors.push(`${path.relative(repoRoot, filePath)}: ${(err as Error).message}`);
    return null;
  }
  if (data.id !== undefined && data.id !== id) {
    errors.push(`${path.relative(repoRoot, filePath)}: id "${String(data.id)}" does not match file name "${id}.md"`);
    return null;
  }
  const summary = asStringOr(data.summary, asStringOr(data.description, ''));
  const detail = validateCommon(
    {
      name: data.name,
      summary,
      description: data.description,
      author: data.author,
      trust: data.trust,
      version: data.version,
      featured: data.featured,
      categories: data.categories,
      tags: data.tags,
      surfaces: data.surfaces,
      homepage_url: data.homepage_url,
      icon_url: data.icon_url,
    },
    kind,
    id,
  );
  const payloadErrors = validateFilePayload(kind, `${id}.md`, body);
  if (detail.length > 0 || payloadErrors.length > 0) {
    errors.push(`${path.relative(repoRoot, filePath)}: ${[...detail, ...payloadErrors].join('; ')}`);
    return null;
  }
  return {
    id,
    kind,
    name: data.name as string,
    summary: summary as string,
    description: typeof data.description === 'string' ? data.description : '',
    author: data.author as string,
    homepage_url: typeof data.homepage_url === 'string' ? data.homepage_url : '',
    icon_url: typeof data.icon_url === 'string' ? data.icon_url : '',
    trust: data.trust as MarketplaceTrust,
    install_count: 0,
    version: data.version as string,
    featured: data.featured === true,
    categories: asStringArrayOr(data.categories, []),
    tags: asStringArrayOr(data.tags, []),
    surfaces: asStringArrayOr(data.surfaces, ['coder', 'ide', 'editor']) as Surface[],
    payload: { kind, fileName: `${id}.md`, content: body },
  };
}

export interface BuildResult {
  details: ListingDetail[];
  errors: string[];
}

export function buildCatalog(repoRoot: string): BuildResult {
  const errors: string[] = [];
  const details: ListingDetail[] = [];

  const collect = (entries: ListingDetail | null): void => {
    if (entries) details.push(entries);
  };

  const mcpRoot = path.join(repoRoot, 'mcps');
  if (fs.existsSync(mcpRoot)) {
    for (const entry of fs.readdirSync(mcpRoot, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue;
      collect(loadMcp(repoRoot, entry.name, errors));
    }
  }

  const skillRoot = path.join(repoRoot, 'skills');
  if (fs.existsSync(skillRoot)) {
    for (const entry of fs.readdirSync(skillRoot, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue;
      collect(loadSkill(repoRoot, entry.name, errors));
    }
  }

  for (const kind of ['rule', 'subagent'] as const) {
    const root = path.join(repoRoot, kind === 'rule' ? 'rules' : 'subagents');
    if (!fs.existsSync(root)) continue;
    for (const entry of fs.readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
      collect(loadMarkdownListing(repoRoot, kind, path.join(root, entry.name), errors));
    }
  }

  const seen = new Set<string>();
  for (const detail of details) {
    if (seen.has(detail.id)) errors.push(`duplicate listing id "${detail.id}" across kinds`);
    seen.add(detail.id);
  }

  details.sort((a, b) => {
    if (a.featured !== b.featured) return a.featured ? -1 : 1;
    return a.id.localeCompare(b.id);
  });

  return { details, errors };
}

export interface CatalogIndex {
  generated_at: string;
  count: number;
  listings: Array<{
    id: string;
    kind: MarketplaceKind;
    name: string;
    summary: string;
    author: string;
    trust: MarketplaceTrust;
    install_count: number;
    version: string;
    featured: boolean;
    categories: string[];
    tags: string[];
    surfaces: Surface[];
  }>;
}

export function buildIndex(details: ListingDetail[], generatedAt: string): CatalogIndex {
  return {
    generated_at: generatedAt,
    count: details.length,
    listings: details.map(detail => ({
      id: detail.id,
      kind: detail.kind,
      name: detail.name,
      summary: detail.summary,
      author: detail.author,
      trust: detail.trust,
      install_count: detail.install_count,
      version: detail.version,
      featured: detail.featured,
      categories: detail.categories,
      tags: detail.tags,
      surfaces: detail.surfaces,
    })),
  };
}

export function resolveGeneratedAt(outDir: string, details: ListingDetail[], explicit?: string): string {
  if (explicit) return explicit;
  const indexPath = path.join(outDir, 'index.json');
  try {
    if (!fs.existsSync(indexPath)) return new Date().toISOString();
    const existing = JSON.parse(fs.readFileSync(indexPath, 'utf-8')) as {
      generated_at?: unknown;
      listings?: unknown;
    };
    if (typeof existing.generated_at !== 'string' || !Array.isArray(existing.listings)) {
      return new Date().toISOString();
    }
    const nextListings = buildIndex(details, existing.generated_at).listings;
    if (JSON.stringify(existing.listings) !== JSON.stringify(nextListings)) {
      return new Date().toISOString();
    }
    for (const detail of details) {
      const detailPath = path.join(outDir, `${detail.id}.json`);
      if (!fs.existsSync(detailPath)) return new Date().toISOString();
      if (fs.readFileSync(detailPath, 'utf-8') !== `${JSON.stringify(detail, null, 2)}\n`) {
        return new Date().toISOString();
      }
    }
    return existing.generated_at;
  } catch {
    return new Date().toISOString();
  }
}

export function writeCatalog(outDir: string, details: ListingDetail[], generatedAt: string): CatalogIndex {
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  const index = buildIndex(details, generatedAt);
  fs.writeFileSync(path.join(outDir, 'index.json'), `${JSON.stringify(index, null, 2)}\n`);
  for (const detail of details) {
    fs.writeFileSync(path.join(outDir, `${detail.id}.json`), `${JSON.stringify(detail, null, 2)}\n`);
  }
  return index;
}

function main(): void {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const outDir = path.join(repoRoot, 'dist', 'listings');
  const { details, errors } = buildCatalog(repoRoot);
  if (errors.length > 0) {
    console.error('catalog generation failed:');
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
  }
  const generatedAt = resolveGeneratedAt(outDir, details, process.env.CATALOG_GENERATED_AT);
  const index = writeCatalog(outDir, details, generatedAt);
  console.log(`wrote ${index.count} listings to ${path.relative(process.cwd(), outDir)}/`);
  for (const detail of details) {
    console.log(`  ${detail.id.padEnd(24)} ${detail.kind.padEnd(9)} ${detail.trust.padEnd(9)} v${detail.version}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}