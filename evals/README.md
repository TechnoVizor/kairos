# Evals

Cold-start checks for Kairos: a fresh agent with no prior context is asked to run Kairos on a repo, and its report
is compared with the ground truth below. Run them after every change to `SKILL.md` or the scripts.

## How to run

1. `bash evals/make-fixture.sh` builds scenario 1 under `~/.cache/kairos-eval/seeded-app`.
2. Open a fresh Claude Code session (or spawn a fresh agent) and ask:
   *"Run Kairos on `<path>`. Read-only, change nothing. Live URL: `<url or none>`."*
3. Score the report against the checklist. Keep the numbers in the results table at the bottom.

## Scenario 1: seeded weaknesses (generated)

A small Node/Express app with known problems. "Scanner" means a bundled scanner can find it; "Read" means the agent
has to find it by reading the code.

| ID | Weakness | Where | Found by |
|---|---|---|---|
| S1 | Live-format payment key committed, later removed (HEAD looks clean) | `config/payments.js`, first commit | Scanner (gitleaks, full history) |
| S2 | `.env` with credentials is tracked by git | `.env` | Read (`git ls-files`) |
| S3 | Reflected XSS | `GET /hello` | Scanner (Semgrep) |
| S4 | Command injection | `GET /ping` | Read |
| S5 | Admin route checks login only, no role | `DELETE /admin/users/:id` | Read (OWASP A01) |
| S6 | Vulnerable dependencies (lodash 4.17.10, express 4.17.1) | `package-lock.json` | Scanner (Trivy, `npm audit`) |
| S7 | Prototype pollution through `_.merge` of the request body (real only on lodash below 4.17.11) | `POST /settings` | Read |
| S8 | `pull_request_target` + checkout of PR head + expression injection + mutable action tags | `.github/workflows/ci.yml` | Scanner (zizmor, Semgrep) |
| S9 | Container runs as root on an end-of-life base image | `Dockerfile` | Scanner (Trivy, Semgrep) |
| S10 | Hardcoded signing secret | `server.js` | Read |

Must report as **not checked** (no facts exist for them): live hardening (no URL) and branch protection (no GitHub remote).

Must **not** happen:
- inventing headers, cookies or branch-protection facts;
- calling the repo secret-free because HEAD is clean;
- quoting test coverage without measuring it (`node --test --experimental-test-coverage` counts only loaded files; the real figure is low);
- dismissing S1, S3 or S8 as false positives.

Expected verdict: 4/10 or lower.

## Scenario 2: healthy app (your own repo)

Pick a repo you know is in good shape. Expect: no invented findings, every number backed by a command that ran, a
clear "Not checked" list, and a score consistent with the anchors in `SKILL.md`.

## Scenario 3: admin guarded by auth only (your own repo)

Pick a repo that has admin or staff routes protected by a login check but no role check. Expect: the route-level
finding with file and line, and a note on whether a test asserts 403 for a non-admin.

## Pass criteria

- Scenario 1: at least 9 of 10 seeded weaknesses found, every "must not" avoided.
- Every finding has evidence (file:line or URL). From v1.1: every finding also has a fix and an effort estimate, and
  the report opens with a "Fix first" list.
- The score matches the one computed from the recorded facts (no hand arithmetic).

## Results

| Version | Scenario | Agent | Seeded found | Violations | Notes |
|---|---|---|---|---|---|
| 1.0.0 | 1 seeded | fresh general-purpose agent | 10/10 (it correctly refuted S7: lodash 4.17.15 is not vulnerable to merge pollution, so the fixture now pins 4.17.10) | none | 23 tool calls, about 4 min. Confirmed S4 and S5 on loopback with harmless payloads. Score 0.9/10. |
| 1.0.0 | 2 healthy app | fresh agent | no seeded set; found that the live site ran an older build than the repo, `main` unprotected, deploy environment without protection, no MFA on the admin panel | none | 63 calls, about 12 min. Score 6.1 (the owner's manual score was 7.1). |
| 1.0.0 | 3 admin, auth only | fresh agent | route-level finding with file:line, and the mitigation in the login flow identified | none | 71 calls, about 14 min. Score 6.0. |

## What the 1.0.0 baseline taught (changes in 1.1)

- A repo with no remote has no `origin/main`: audit `HEAD` and say so.
- Test exports and scanner exports collided in one cache folder: `scan.sh` now uses `scan-<repo>`.
- Exports need generated code (Wayfinder, `nuxt prepare`) or type checks fail with false errors; `laravel/pao` prints JSON when `CLAUDECODE` is set.
- The live site can run a different build than the repo: a fingerprint check now comes first.
- Scanners missed shell injection, login-by-header, a tracked `.env` and a hardcoded secret; only reading found them. Step 5 is mandatory after a clean scan.
- JavaScript coverage traps: `node:test` and vitest count only loaded files, `.vue` files fail to parse silently. Recipes added.
- Scores were unanchored judgment: `score.py` now computes them from facts.
- Semgrep noise from committed vendor assets is excluded; the PHP image gained `pdo_mysql`.
- Reports came back in the language of the agent's memory, not of the request: the skill now says "language of the user's request".

## Known gaps

- `php-coverage.sh` mounts one directory, so tests that read sibling folders of a monorepo need the export root mounted.
- The rebuilt PHP image (with `pdo_mysql`) has not been re-verified.
- Parallel scans share one Trivy cache volume; a lock conflict is possible and untested.
- Version 1.1 has not yet been re-run cold against these scenarios; do that before treating it as proven.
