## Listing summary

- **Kind:** `mcp` / `skill` / `rule` / `subagent`
- **Listing ID:**
- **Source / Homepage URL:**
- **Summary of change:**

## Checklist

- [ ] `id` matches `^[a-z0-9][a-z0-9-]{0,63}$` and matches the folder or file stem.
- [ ] External contributions use `trust: community` or `trust: verified` (never `trust: official`).
- [ ] Zero hardcoded credentials, API keys, or bearer tokens (env-var names and `$ENV_VAR` references only).
- [ ] HTTP MCP `serverUrl` uses a public `https://` endpoint; stdio MCP `command` is a bare executable name.
- [ ] Copy is factual and concise (no hardcoded tool counts, no marketing hype, no em dashes).
- [ ] Ran `pnpm run generate && pnpm test && pnpm run check` locally and included updated `dist/listings/` output.
