---
name: project-readiness-test
description: Use when the user asks to check, test or rate a finished project's readiness and security ("тест готового проекта", "насколько проект готов"), run an audit or health check, or get a security score for one or several repos.
---

# Project Readiness Test

Read-only audit that ends in one weighted score. Report in the user's language. Fix nothing unless asked; end with one line offering fixes. `<skill-dir>` below is the "Base directory for this skill" shown when this skill loads.

## Ground rules
- Audit what is pushed: `git fetch`, compare `main` with `origin/main`. If local is behind or dirty, test an export (`git archive origin/main | tar -x -C <dir>`). Never checkout, pull, stash or delete the user's WIP.
- An export lacks gitignored build output: Laravel+Vite view tests need `public/build` (copy it from a clean checkout at the same commit), Nuxt needs `npx nuxt prepare`. Mass failures right after an export are an export artifact, not code.
- Never point tests at a real DB. Laravel: phpunit's sqlite `:memory:`. Go/Postgres: throwaway container with its own name and port, removed at the end (some suites drop the `public` schema).
- Prod: GET/HEAD/OPTIONS on public URLs only. No POST, no logins, no fuzzing.
- Containers get code read-only, nothing is uploaded, secrets stay redacted. Docker may mount only under `$HOME`: exports go to `~/.cache/readiness-test/<repo>`, delete them at the end.
- Absolute paths; no parallel calls that `cd`; never `pkill -f <text in your own command>`. Slow runs go to the background, output to the scratchpad.

## Steps
1. **State:** branch, dirty files, ahead/behind, last commits. Explain dirty files, don't ignore them.
2. **Stack checks** (absent tool = gap, say so):

| Stack | Commands |
|---|---|
| Laravel | `php artisan test --compact`, `vendor/bin/pint --test`, `vendor/bin/phpstan analyse` (if installed), `composer audit --locked` |
| Node/Next/Nuxt | `npm audit --omit=dev` (`pnpm audit --prod`), `npx eslint .`, `npx tsc --noEmit` or `nuxt typecheck`, `npx vitest run` |
| Go | `go vet ./...`, `golangci-lint run ./...`, `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`, `go test -p 1 -count=1 ./...` |

3. **Coverage of the whole source** (a pass rate alone proves little):
   - Go: `go test -p 1 -coverprofile=c.out ./...` then `go tool cover -func=c.out`; count hand-written code only (drop generated `internal/api`, `internal/db`, `cmd`).
   - Vitest: `--coverage --coverage.include='src/**/*.{ts,tsx}'` with `@vitest/coverage-v8` at the vitest version. Without `include` only files that tests load are counted (66% vs a real 3%).
   - PHP: `bash <skill-dir>/scripts/php-coverage.sh <export-dir>` (pcov and GD in a throwaway image; the host has neither). It also runs tests that need GD.
4. **Scanners:** `bash <skill-dir>/scripts/scan.sh <repo>` runs gitleaks (full history), Semgrep, Trivy and zizmor in throwaway containers and prints a summary. The first run pulls about 2 GB of images. Read every hit before dismissing it. Usual false positives: generated code, docs and skill examples, i18n keys, test fixtures, lockfile hashes, nginx `$host` and constant `proxy_pass`, lines already `nolint`ed, `USER` missing in a build stage. `workflow_run` and `head_sha` findings are low risk when the repo is private and the trigger has `branches: [main]`.
5. **Code security** (grep, then read every hit): secrets in tracked files; `.env` ignored; raw SQL, exec, eval, unserialize; `v-html`, `innerHTML`, `dangerouslySetInnerHTML`; mass assignment; upload type/size/storage; webhook signature; CORS origins; rate limits on login and forms; password hashing; cookie flags. Authorization (OWASP A01): `php artisan route:list --json --except-vendor`, list state-changing routes guarded by `auth` alone, then check role/policy in the controller; every admin/staff guard needs a test asserting 403 for a non-admin (a guard at 0% coverage is a gap).
6. **Live hardening:** `curl -sI` for HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, `X-Powered-By`; cookie flags; `/.env` returns 403; a foreign `Origin` is not reflected.
7. **CI/ops:** runs on PRs, gates deploy, actions pinned by SHA, `permissions:` set, no secrets echoed into shell, dependency updates automated. `main` protected: `gh api repos/<o>/<r>/branches/main/protection` and `gh api repos/<o>/<r>/rules/branches/main` (both empty = unprotected).

## Score
Each 0-10, weighted: tests 20 · static analysis 10 · dependencies 10 · code security 25 · live hardening 15 · CI/ops 10 · GDPR/privacy 5 · maintainability 5. Drop an unaudited criterion and renormalize. Tests = pass rate AND whole-source coverage; a security-critical package (auth, payments, admin) under 50% caps it at 6.

## Report
Table (criterion, weight, fact, score) → total → findings, worst first, each with file:line or URL → "Not checked" list.

## Common mistakes
- A crashed or missing tool counted as a pass: read the real exit code, not the pipe's.
- A host-only failure (missing PHP extension) reported as a code bug: label it environment, or rerun in the image.
- Advisory exploitability taken from a summary: mark it second-hand and check the config (Windows-only, AVIF off, MFA unused).
- One new linter finding right after switching directories: re-run with an isolated cache before believing it.
