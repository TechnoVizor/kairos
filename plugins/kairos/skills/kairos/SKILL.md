---
name: kairos
description: Use when the user asks to check, test or rate a finished project's readiness and security ("тест готового проекта", "насколько проект готов"), run an audit or health check, get a security score for one or several repos, or mentions Kairos.
---

# Kairos

*Kairos (καιρός): the opportune moment to ship.*

Read-only audit that ends in one score and a fix list. Scripts measure; you read the code, judge and explain. Report in the language of the user's request. Fix nothing unless asked. `<skill-dir>` is the "Base directory for this skill" shown when this skill loads.

## Ground rules
- Audit what is pushed: `git fetch`, compare `main` with `origin/main`. No remote: audit `HEAD` and say so. If local is behind or dirty, test an export: `git archive origin/main | tar -x -C ~/.cache/kairos/export-<repo>`. Never checkout, pull, stash or delete the user's WIP.
- An export lacks gitignored files, so mass failures right after it are an export artifact, not code. Restore what the project's own setup restores: Laravel+Vite `public/build` (copy from a clean checkout of the same commit), `composer install --no-scripts`, `npm ci`, generators (`nuxt prepare`, `php artisan wayfinder:generate --with-form`; read the `composer.json` and `package.json` scripts). Type errors like "Property X does not exist" mean a generator did not run.
- Never point tests at a real DB. Laravel: phpunit's sqlite `:memory:`. Go/Postgres: throwaway container with its own name and port, removed at the end (some suites drop the `public` schema).
- Prod: GET/HEAD/OPTIONS on public URLs only. No POST, no logins, no fuzzing. You may run the project from an export on `127.0.0.1` to confirm a finding with a harmless payload (`echo`, `id`); stop it afterwards, never against production.
- Containers get code read-only, nothing is uploaded, secrets stay redacted. Docker may mount only under `$HOME`, so exports live under `~/.cache/kairos/`; delete them at the end.
- Absolute paths; no parallel calls that `cd`; never `pkill -f <text in your own command>`. Run slow commands with the tool's background mode, not `nohup` or `&`; output goes to the scratchpad.
- Agent-aware tools (`laravel/pao`) print JSON when `CLAUDECODE` or `AI_AGENT` is set. For normal output run `env -u CLAUDECODE -u AI_AGENT <cmd>` (phpstan: `--error-format=raw`).
- A clean scanner run is not a clean audit. Scanners miss missing role checks, shell injection, a tracked `.env`, hardcoded secrets. Step 5 is always required.

## Steps
1. **State:** branch, dirty files, ahead/behind, last commits. Explain dirty files, don't ignore them.
2. **Stack checks** (absent tool = gap, say so):

| Stack | Commands |
|---|---|
| Laravel | `php artisan test --compact`, `vendor/bin/pint --test`, `vendor/bin/phpstan analyse` (if installed), `composer audit --locked` |
| Node/Next/Nuxt | `npm audit --omit=dev` (`pnpm audit --prod`), `npx eslint .`, `npx tsc --noEmit` or `nuxt typecheck`, `npm test` |
| Go | `go vet ./...`, `golangci-lint run ./...`, `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`, `go test -p 1 -count=1 ./...` |
| Other | The project's documented test, lint and audit commands. The scanners in step 4 work for any language. |

   Read the real exit code. `eslint` exiting 2 with "couldn't find a config" means not configured (a gap), not a crash.
3. **Coverage** (a pass rate alone proves little). Measure logic-bearing code: backend, API clients, stores, guards. Exclude generated code and purely presentational templates, and say so. Name the packages you treat as critical (auth, payments, admin/staff guards, erasure/export, secret handling) and record the lowest coverage among them.
   - Go: `go test -p 1 -coverprofile=c.out ./...`, `go tool cover -func=c.out`; drop generated `internal/api`, `internal/db`, `cmd`.
   - Node, any runner: `npx --yes c8 --all npm test`. A runner's own coverage counts only files the tests load (vitest without `--coverage.include='src/**/*.{ts,tsx}'` says 66% where the real figure is 3%).
   - PHP: `bash <skill-dir>/scripts/php-coverage.sh <export-dir>` (pcov and GD in a throwaway image; the host has neither). The totals count files no test loads, but the per-file table hides them; for a critical package use `--coverage-clover`. It mounts only that directory: tests that read sibling folders of a monorepo need the export root mounted.
   - Vue/Nuxt: vitest cannot parse `.vue` files without `@vitejs/plugin-vue` and still exits 0, silently understating the untested share. If it prints parse failures, estimate from lines of code and say so.
4. **Scanners:** `bash <skill-dir>/scripts/scan.sh <repo>` runs gitleaks (full history), Semgrep, Trivy and zizmor in throwaway containers and prints a summary. The first run pulls about 2 GB of images. A committed `.kairos-baseline.json` lists findings the team already accepted; they are counted, not hidden. Read every hit before dismissing it. Usual false positives: generated code, docs and skill examples, i18n keys, test fixtures, lockfile hashes, nginx `$host` and constant `proxy_pass`, lines already `nolint`ed, `USER` missing in a build stage. `workflow_run` and `head_sha` findings are low risk when the repo is private and the trigger has `branches: [main]`.
5. **Code security** (grep, then read every hit): secrets in tracked files (`git ls-files | grep -i env`); raw SQL, exec/shell, eval, unserialize; `v-html`, `innerHTML`, `dangerouslySetInnerHTML`; mass assignment; upload type/size/storage; webhook signature; CORS origins; rate limits on login, register and forms; password hashing; cookie flags. Authorization (OWASP A01): list state-changing routes guarded by login alone (`php artisan route:list --json --except-vendor`, or read the router), check the role or policy in each controller, and look for a test asserting 403 for a non-admin. A guard at 0% coverage is a gap.
6. **Live hardening:** first confirm the live site runs this code (compare a fingerprint: asset manifest, a route that exists only in the repo, `/robots.txt`); if not, report that as a finding and label the live results "of the running build". Then `python3 <skill-dir>/scripts/live.py <url> [--cors-url <api-url>]`. No URL: set `hardening` to null and list it under Not checked; do not guess from a local run.
7. **CI/ops:** runs on PRs, gates deploy, actions pinned by SHA, `permissions:` set (`gh api repos/<o>/<r>/actions/permissions/workflow`), no secrets echoed into shell, dependency updates automated, backup before migrations. Who can trigger a deploy and from which ref; environment protection (`gh api repos/<o>/<r>/environments`). `main` protected: `gh api repos/<o>/<r>/branches/main/protection` and `.../rules/branches/main` (both empty = unprotected).
8. **Score:** `python3 <skill-dir>/scripts/score.py --example > facts.json`, fill it in, `python3 <skill-dir>/scripts/score.py facts.json`. It validates the file, applies the anchors, caps and renormalization; do the arithmetic nowhere else. Judged criteria (security, privacy, maintain) need a written reason. Use `null` only for a criterion that cannot apply (GDPR when nothing personal is stored) or cannot be measured (no live URL), never to skip work.

## Report
1. **Fix first:** at most five items, ordered by risk, then effort.
2. The table and total that `score.py` printed.
3. Findings, worst first. Each: severity, evidence (`file:line` or URL), fix, effort S/M/L. Recipes for common ones are in `<skill-dir>/fixes.md`.
4. Accepted-by-baseline counts. Suggest `.kairos-baseline.json` entries for confirmed false positives; never write that file yourself.
5. **Not checked:** what you could not or did not verify.
End with one line offering to apply fixes.

## Common mistakes
- A crashed or missing tool counted as a pass: read the real exit code, not the pipe's.
- A host-only failure (missing PHP extension) reported as a code bug: label it environment, or rerun in the image.
- Advisory exploitability taken from a summary: mark it second-hand and check the config (Windows-only, AVIF off, MFA unused).
- One new linter finding right after switching directories: re-run with an isolated cache before believing it.
- Live results credited to code the live site does not run.
