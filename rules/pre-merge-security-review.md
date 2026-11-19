---
id: pre-merge-security-review
name: Pre-Merge Security Review
summary: Pre-PR security checklist covering credentials, untrusted input, SSRF, path traversal, supply-chain licenses, and production deploy gates.
description: A structured security review checklist for pull requests. Covers credential handling, input validation, SSRF and traversal guards, dependency licensing, and safe production deployment practices.
author: Scalix World
trust: official
version: 1.0.0
categories:
  - development
  - security
tags:
  - scalix
  - security
  - review
  - checklist
surfaces:
  - coder
  - ide
  - editor
---

# Pre-Merge Security Review

Run this checklist on any PR that touches network-facing code, auth, installers, build config or dependencies.

## Secrets and credentials

- No credential material in source, fixtures, tests, docs or CI logs. Env-var NAMES are fine; values are not.
- Local secret files stay outside the repository (e.g. a dedicated uncommitted secrets directory or secret manager), referenced by path or env var only.
- Error messages and logs never echo a credential value or a full request URL with userinfo.

## Untrusted input

- Server-returned payloads are validated again on the client: paths (no leading `/`, no `\`, no `..`, bounded segments), hostnames (https only, no loopback or RFC1918/link-local/metadata targets), payload shape and size caps.
- New file-writing paths resolve the target and assert containment under the intended directory.
- Shell execution: reject bare paths and metacharacters; require an explicit user confirmation for locally spawned processes.

## Supply chain

- New server/runtime dependencies carry an OSI-approved license (permissive preferred); no RSALv2/SSPL-only Redis-lineage images, no floating `latest` pins.
- Dependency bumps state why; check the upstream changelog for behavior changes, not just version drift.

## Deploy posture

- Never hand-build on a production host. If CI is down, fix CI.
- Deploy only through the repository's scripted release pipeline, never by hand-editing files on production hosts.
- Database migrations and host-level changes stay reversible: forward-only SQL with a documented rollback path and explicit rollout verification.

## Reporting

- Every finding cites file and line. Anything you could not verify is labelled unverified instead of softened.