# Contributing to the Scalix Marketplace catalog

This repo is a curated, Git-backed catalog. There is no submission endpoint and no runtime database: a listing exists because a reviewed file is in Git. That is the whole security model; keep it that way.

## Adding a listing

1. Pick the kind and create the source file:

   - **MCP server:** `mcps/<id>/MCP.yaml`
   - **Skill:** `skills/<id>/SKILL.md` (companions allowed in the same folder: `references/`, `scripts/`, `examples/`, `assets/`)
   - **Rule:** `rules/<id>.md`
   - **Subagent:** `subagents/<id>.md`

2. The `id` must match `^[a-z0-9][a-z0-9-]{0,63}$`, must equal the folder (or file) stem, and must be unique across all four kinds.

3. Frontmatter (YAML) fields:

   ```yaml
   id: my-thing            # optional for skills; must match the folder if present
   name: My Thing          # required
   summary: One line.      # required (skills may fall back to `description`)
   description: Longer...  # optional for mcp; required for skills
   author: Your Name       # required
   trust: community        # official | verified | community
   version: 1.0.0          # required, semver
   featured: false         # optional
   categories: [devtools]  # optional, array of strings
   tags: [one, two]        # optional, array of strings
   surfaces: [coder, ide, editor]  # optional, defaults to all three
   homepage_url: https://example.com # optional
   icon_url: https://example.com/icon.svg # optional
   ```

   `official` = published by Scalix. `verified` = operated by the upstream vendor and reviewed by a Scalix maintainer. `community` = everything else. External pull requests cannot claim `trust: official`.

4. Payloads:

   - **MCP (http):** `payload.transport: http`, `serverUrl` must be `https://` on a public host, `serverLabel` 2 to 128 chars, optional `authorizationEnv` / `requiredEnv` (env-var NAMES only, `^[A-Z][A-Z0-9_]{0,63}$`) and `headers` (max 16, token-shaped keys).
   - **MCP (stdio):** `payload.transport: stdio`, `command` a bare name (no `/`, `\`, `..`; `^[A-Za-z0-9._@-]{1,64}$`), optional `args` (<= 20 entries, <= 512 chars each). Clients require explicit user confirmation before installing a stdio server.
   - **Skill:** `SKILL.md` is required at the skill root; total <= 10 files, <= 256 KB each, <= 1 MB overall; paths must be safe relative paths (no leading `/`, no `\`, no `..`, <= 6 segments).
   - **Rule / Subagent:** the markdown body after the frontmatter becomes `payload.content`; the file name becomes `payload.fileName` (`<id>.md`).

5. Never put credential VALUES anywhere in this repo; env-var names and `Bearer $ENV_VAR` references are the only allowed form. The generator scans every payload and fails the build on credential-shaped strings.

6. Regenerate and validate:

   ```bash
   pnpm install
   pnpm run generate
   pnpm test
   pnpm run check
   ```

   All checks must pass before you open a PR, and `dist/listings/` must match `pnpm run generate` with zero diff.

7. Open a PR against `main`. Every PR runs through `scalix-review-bot` (`.github/workflows/scalix-review-bot.yml`), which checks schema validity, trust tier, `dist/listings/` freshness, leaked credentials, SSRF URLs, and copy quality before a maintainer merges.

## Maintainer skill sync

Flagship Scalix skills (`scalix-ai`, `scalix-database`, `scalix-functions`, `scalix-platform`) are synced from `scalixworld/scalix-cloud-mcp`; avoid editing those files by hand:

```bash
node scripts/sync-skills.mjs --from <path-to-scalix-cloud-mcp>
pnpm run generate && pnpm test && pnpm run check
```

## Serving

`dist/listings/` is committed so static hosting never needs a build step. The website mirrors these compiled files to `https://scalix.world/agent-catalog/listings` and `https://scalix.world/marketplace`. If you change the payload schema in a way clients must adopt, coordinate with the client repositories (`scalix-coder`, `scalix-ide`, `scalix-editor`); they each re-validate payloads before installing.

## Trust and removal

- A listing can be demoted (`trust: community`) or removed by deleting its source folder/file and regenerating. Removal is a breaking change for anyone who installed it: prefer `deprecated` messaging in the summary first.
- `install_count` is always `0` in the static catalog; clients treat install telemetry as best-effort.
