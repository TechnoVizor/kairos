# Kairos

*Kairos (καιρός) is the Greek word for the opportune moment. The right moment to ship is when the project is ready and safe.*

A [Claude Code](https://code.claude.com) skill that audits a finished project and answers one question:
**how ready and how secure is it, in numbers?**

It runs the project's own tests, measures *real* test coverage, scans the git history and dependencies,
reads the security-critical code, checks the live site's hardening and CI setup, and ends with one weighted
score, a "Fix first" list and, for every finding, evidence, a fix and an effort estimate. Everything is read-only: it never changes your repo and never uploads your code.

```
| Criterion       | Weight | Score | Basis                                            |
| Tests           |   20   |  9.5  | 304/305 pass, 91.5% coverage                     |
| Code security   |   25   |  7.5  | no injection sinks, admin guards read            |
| Live hardening  |   15   |  2.5  | missing/weak: hsts, csp, frame, nosniff, ...     |
| ...             |        |       |                                                  |
                                                    Total: 7.3 / 10
```

See a full [sample report](examples/sample-report.md).

## What it checks

| Criterion | Weight | How |
|---|---:|---|
| Tests | 20 | The stack's test suite **and** whole-source coverage (Go `-cover`, Vitest `--coverage.include`, PHP `pcov`). A security-critical package under 50% caps the score at 6. |
| Static analysis | 10 | Pint / PHPStan, ESLint, `tsc`, `go vet`, `golangci-lint`, `govulncheck` |
| Dependencies | 10 | `composer audit`, `npm/pnpm audit`, Trivy over lockfiles, staleness |
| Code security | 25 | Semgrep (OWASP Top 10), route audit for missing role checks, grep for injection sinks, uploads, CORS, cookies, password hashing |
| Live hardening | 15 | `curl -I` on the live site: HSTS, CSP, X-Frame-Options, cookie flags, `/.env`, CORS reflection |
| CI / ops | 10 | Actions pinned by SHA, permissions, zizmor, branch protection on `main` |
| GDPR / privacy | 5 | Consent, retention, erasure |
| Maintainability | 5 | Docs, structure, TODO debt |

Secrets are hunted in the **whole git history** with gitleaks (values redacted), not just the working tree.
A criterion that cannot be audited is dropped and the weights are renormalized.
Scores are computed by `scripts/score.py` from measured facts with fixed anchors (80% whole-source coverage is a 10;
a critical package under 50% caps the tests score at 6), so two people get the same number for the same repo.

## Install

The repository is a Claude Code plugin marketplace. Two commands:

```bash
claude plugin marketplace add TechnoVizor/kairos
claude plugin install kairos@kairos
```

While the repository is private, the owner must add you as a collaborator first, and you need to be signed in
with `gh auth login` (or have git credentials for GitHub).

No marketplace? Copy the skill folder instead:

```bash
cp -r plugins/kairos/skills/kairos ~/.claude/skills/
```

Restart Claude Code (or run `/reload-plugins`) after installing.

### Requirements

- **Docker**, running. Scanners run as throwaway containers; the first scan pulls about 2 GB of images.
- **git** and **python3**.
- The project's own toolchain for its stack checks (PHP + Composer, Node, Go).
- **gh** (optional) for the branch-protection check.

## Use

Ask in plain language:

> Run Kairos on `~/repos/my-app`

> Rate how ready and secure these three repos are and compare them.

The trigger phrases also work in Russian (`тест готового проекта`). The report comes back in the language you write in.

The two helper scripts also work on their own:

```bash
# gitleaks (full history) + Semgrep + Trivy + zizmor, summarized
bash plugins/kairos/skills/kairos/scripts/scan.sh ~/repos/my-app

# PHP coverage inside a throwaway image with pcov and GD (pass an export, not a working checkout)
bash plugins/kairos/skills/kairos/scripts/php-coverage.sh ~/.cache/kairos/my-app

# hardening facts of the live site (GET/HEAD only); prints JSON for the score
python3 plugins/kairos/skills/kairos/scripts/live.py https://your-site --cors-url https://your-site/api/health

# score from a facts file (start from: score.py --example)
python3 plugins/kairos/skills/kairos/scripts/score.py facts.json
```

### Accepting known findings

Scanners repeat the same false positives. Commit a `.kairos-baseline.json` to the audited repo and they are counted
separately instead of reappearing as new (a reason is required for every entry):

```json
{"accepted": [
  {"tool": "semgrep", "rule": "missing-user", "path": "Dockerfile", "reason": "final stage sets USER"},
  {"tool": "gitleaks", "path": "docs/*", "reason": "example keys in documentation"}
]}
```

Kairos suggests entries but never writes the file itself.

## Safety model

- **Read-only.** It audits `origin/main` from a `git archive` export, so uncommitted work and local files are never touched.
- **No code is uploaded.** Scanners download rule packs and vulnerability databases, but get your code mounted read-only; Semgrep telemetry is off, zizmor runs offline, secrets are redacted in output.
- **Never a real database.** Tests use sqlite in memory or a throwaway container with its own name and port.
- **Production is looked at, not poked:** `GET`/`HEAD`/`OPTIONS` on public URLs only. No logins, no `POST`, no fuzzing.
- Temporary exports live in `~/.cache/kairos/` and are deleted after each scan.

## Repository layout

```
.claude-plugin/marketplace.json                     makes the repo installable
plugins/kairos/
  .claude-plugin/plugin.json                        plugin manifest (version lives here)
  skills/kairos/
    SKILL.md                                        the instructions Claude follows + the scoring rubric
    fixes.md                                        ready-made fix recipes for the common findings
    scripts/scan.sh                                 gitleaks, Semgrep, Trivy, zizmor in Docker
    scripts/summarize.py                            scanner JSON to short markdown, honors the baseline
    scripts/live.py                                 hardening facts of a live site (GET/HEAD only)
    scripts/score.py                                facts to score: validation, anchors, caps, arithmetic
    scripts/php-coverage.sh, php-coverage.Dockerfile
evals/                                              cold-start checks and the generated vulnerable fixture
examples/sample-report.md                           what the output looks like
```

## Limits

- It is an audit, not a penetration test: no dynamic scanning, no exploit attempts.
- Authorization is checked by reading routes and controllers; a passing audit does not prove there is no IDOR.
- Advisory exploitability is judged from the advisory text and your config, and is marked second-hand.
- Semgrep may skip files it cannot parse; the summary shows how many.

## Contributing

Edit `SKILL.md` for behavior and the scripts for tooling. Keep the skill short, since it is loaded into context.
Before pushing, run `claude plugin validate .` and `python3 .../scripts/score.py --selftest`, then run the
cold-start checks in [`evals/`](evals/README.md) with a fresh agent and compare with the ground truth.
Bump `version` in `plugin.json` so installed copies update.

## License

[MIT](LICENSE)
