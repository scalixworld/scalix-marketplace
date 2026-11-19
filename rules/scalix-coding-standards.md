---
id: scalix-coding-standards
name: Scalix Coding Standards
summary: "House engineering standards for agent-written code in Scalix repositories: verify against real code, no em dashes, no fabricated metrics, and client-side security parity."
description: House engineering standards from Scalix World for coding agents working in any repository. Enforces verification over assumption, clear technical house style, and the safety posture external-facing changes must meet.
author: Scalix World
trust: official
version: 1.0.0
categories:
  - development
tags:
  - scalix
  - standards
  - house-style
  - security
surfaces:
  - coder
  - ide
  - editor
---

# Scalix Coding Standards

Apply these when writing or reviewing code in any Scalix repository.

## Verify, never assume

1. Read the real code before claiming what it does. Grep and open the file, then quote it with `path:line`.
2. Never invent numbers, benchmarks, quotes or "official" claims. Mark estimates as estimates.
3. Tests are the proof: a change is done when the checks it touches pass, not when it looks done.
4. If a task depends on prior decisions, ask for the sourced note instead of reconstructing it from memory.

## House style

1. No em dashes in prose (UI copy, docs, blog). Use commas, colons or parentheses.
2. Specific numbers over adjectives. "14 modules, 420 passing tests" beats "a large codebase".
3. Cite sources: file paths, vendor docs, URLs. Uncited claims get flagged, not laundered.
4. Follow the file you are editing: match its naming, error handling and comment density.

## Security parity

1. Everything a catalog, config or server returns is untrusted input. Re-validate paths, hosts and payload shapes on the client side even when the server already checked.
2. Credentials live in a secret manager or local uncommitted env files only. Never paste, commit or log a credential; the catalog stores env-var NAMES, never values.
3. New third-party code carries an OSI-approved license (permissive preferred); Valkey over Redis-lineage servers.
4. Prefer additive, minimal diffs on shared entrypoints (route files, registries, index files).

## Git workflow

1. Small, focused commits with a message that explains the why.
2. Keep main releasable: use short-lived feature branches and require passing CI checks before merging.
3. Push early. Concurrent branch switches have clobbered local work before.