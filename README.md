# scalix-marketplace

[![Catalog CI](https://github.com/scalixworld/scalix-marketplace/actions/workflows/build-catalog.yml/badge.svg)](https://github.com/scalixworld/scalix-marketplace/actions/workflows/build-catalog.yml)

**Scalix Marketplace**: the static, Git-backed catalog of coding agents (MCP servers, skills, rules, and subagents) consumed by Scalix Coder, the Scalix IDE agent, and Scalix Editor.

There is no runtime server or database: the catalog is plain files in Git, compiled to JSON by `bin/generate-catalog.ts`, browsable on the web, and served as static files at:

- `https://scalix.world/marketplace` (browsable web catalog)
- `https://scalix.world/agent-catalog/listings` (JSON index)
- `https://scalix.world/agent-catalog/listings/<id>` (JSON listing detail)

The same JSON is what the clients consume; they re-validate every payload client-side (path traversal, SSRF hosts, credential shapes, size caps) before a byte touches the workspace, so a compromised catalog can never write outside a project's config directory.

## Layout

| path | what |
|---|---|
| `mcps/<id>/MCP.yaml` | MCP server listings (http or stdio transport) |
| `skills/<id>/SKILL.md` | Skill listings (+ optional `references/`, `scripts/`, `examples/` companions, up to 10 files / 1 MB) |
| `rules/<id>.md` | Rule listings (markdown body installs as `.scalix/rules/<id>.md`) |
| `subagents/<id>.md` | Subagent listings (markdown body installs as `.scalix/agents/<id>.md`) |
| `bin/generate-catalog.ts` | Compiles the sources into `dist/listings/*.json` with full validation |
| `bin/generate-catalog.test.ts` | Test suite (mirrors the client parsers; negative tests for SSRF, traversal, secrets, ids) |
| `bin/review-pr.ts` | Automated PR review checks (`scalix-review-bot`) covering schema, trust tier, drift, secrets, SSRF, and copy |
| `dist/listings/` | Generated output (committed so static hosting never needs a build step) |
| `scripts/sync-skills.mjs` | Re-syncs flagship Scalix skills from a local `scalixworld/scalix-cloud-mcp` checkout (`--from <path>`) |

## Build & test

```bash
pnpm install
pnpm run generate   # writes dist/listings/index.json + dist/listings/<id>.json
pnpm test           # validation and bot test suite
pnpm run check      # tsc --noEmit
```

CI (`.github/workflows/build-catalog.yml`) runs these checks on every push and pull request.

## JSON contract

`dist/listings/index.json`:

```json
{
  "generated_at": "2026-11-18T00:00:00Z",
  "count": 16,
  "listings": [
    {
      "id": "scalix-cloud",
      "kind": "mcp",
      "name": "Scalix Cloud",
      "summary": "Provisions and manages Scalix Cloud resources ...",
      "author": "Scalix World",
      "trust": "official",
      "install_count": 0,
      "version": "1.6.0",
      "featured": true,
      "categories": ["cloud", "development"],
      "tags": ["scalix", "cloud", "postgres", "sandboxes", "functions", "ai"],
      "surfaces": ["coder", "ide", "editor"]
    }
  ]
}
```

`dist/listings/<id>.json` adds `description`, `homepage_url`, `icon_url` and the install `payload` (tagged by `kind`: `mcp` http/stdio, `skill` files, or `rule`/`subagent` fileName + content).

Field names inside the payload are camelCase on purpose: they match the `mcp-services.json` engine dialect, so an installed payload is a near verbatim copy into the workspace config.

## Security model

Everything in this repo is published to every client, so every source file goes through strict validation gates (mirrored client-side too):

- listing `id` must match `^[a-z0-9][a-z0-9-]{0,63}$` and equal the file/folder stem; ids are unique across all four kinds.
- `serverUrl` must be `https://` on a public host: loopback, RFC1918, link-local, metadata, `.local`, `.localdomain`, and `.internal` names are refused, including dotted/hex/numeric/IPv4-mapped IPv6 forms.
- stdio `command` must be a bare name (no paths, no shell metacharacters); clients require explicit user confirmation before spawning it.
- env vars travel as NAMES only (`SCALIX_API_KEY`), never values; header values and file contents are scanned for credential shapes (`sk-...`, `ghp_...`, `Bearer <token>`, `-----BEGIN`, ...). Env-var references like `Bearer $SCALIX_API_KEY` are the one allowed form.
- skills: 1 to 10 files, each <= 256 KB, <= 1 MB total, safe relative paths only, root `SKILL.md` required.
- `surfaces` subset of `coder | ide | editor`; `trust` in `official | verified | community`.

`pnpm test` fails the build on any violation, and CI runs it on every PR.

## Static distribution

`dist/listings/` is committed so static hosting never needs a build step. The website (`https://scalix.world/marketplace` and `https://scalix.world/agent-catalog/listings`) mirrors `dist/listings/` during deployment.

## Adding a listing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Short version: add one folder or file, run `pnpm run generate && pnpm test && pnpm run check`, and open a pull request. Every PR runs automatically through `scalix-review-bot` (`.github/workflows/scalix-review-bot.yml`) before a maintainer merges.
