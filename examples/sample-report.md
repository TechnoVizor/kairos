# Sample report

Illustrative output, anonymized from a real run on a Laravel 13 + Filament 5 + Inertia/Vue marketing site with a lead-capture form.

**Example Shop**, audited from `origin/main`.

## Verdict: 7.3 / 10

Ready for production as a marketing site. No blocking vulnerabilities found. The biggest gaps are cheap: security headers, admin MFA, unprotected `main`.

## Fix first

1. Set security headers (finding 1): about 15 minutes, the biggest score gain.
2. Protect `main` and make CI a required check (finding 2).
3. Turn on MFA for the admin panel (finding 3).
4. `composer update league/commonmark` (finding 4).
5. Fix the failing test and the PHPStan backlog so the project's own gate is green (findings 6 and 7).

Printed by `scripts/score.py` from the recorded facts:

| Criterion | Weight | Score | Basis |
|---|---:|---:|---|
| Tests | 20 | 9.5 | 304/305 pass, 91.5% coverage |
| Static analysis | 10 | 7.5 | 3/4 tools clean |
| Dependencies | 10 | 8.8 | 1 advisories, 9 minors behind |
| Code security | 25 | 7.5 | No injection sinks; admin guards read; gitleaks and Semgrep clean |
| Live hardening | 15 | 2.5 | missing/weak: hsts, csp, frame, nosniff, referrer, permissions, powered_by_hidden |
| CI / ops | 10 | 6.7 | failing: pr_ci, main_protected |
| GDPR / privacy | 5 | 9 | Erasure and retention purge exist and are tested |
| Maintainability | 5 | 8 | Documented, one TODO in the codebase |

**Total: 7.3 / 10** (weights renormalized over 100% audited)

## Findings, worst first

1. **No security headers on the live site** (medium). `curl -sI https://example.test/` shows no `Strict-Transport-Security`, `Content-Security-Policy` or `X-Frame-Options`; `X-Powered-By: PHP/8.4.19` is exposed. *Fix:* set them in `.htaccess` or a middleware, CSP as report-only first (recipe in `fixes.md`). *Effort:* S.
2. **`main` has no branch protection and CI only runs manually** (medium). Anyone with write access can push straight to the branch that deploys. Evidence: `gh api repos/<o>/<r>/branches/main/protection` returns "Branch not protected"; `rules/branches/main` is empty. *Fix:* require a PR and the CI check; run CI on `pull_request`. *Effort:* S.
3. **Admin panel has no MFA** (medium). Two-factor exists for the public accounts, not for the Filament panel (`AdminPanelProvider.php`). *Fix:* enable the panel's multi-factor authentication. *Effort:* M.
4. **`league/commonmark` 2.9.1 advisory** (high on paper, low in practice). The affected Attributes extension is not used in `app/`, Filament or the framework, so it is not reachable. *Fix:* `composer update league/commonmark`. *Effort:* S.
5. **Legal pages render admin HTML with `v-html` and no sanitizer** (low), while the blog goes through one. Only admins can write it. *Fix:* run it through the same renderer. *Effort:* S.
6. **PHPStan level 7 reports 75 errors** (low), mostly missing array value types and `resource|false`; the project's own gate would fail on them. *Fix:* fix or baseline them. *Effort:* M.
7. **One failing test** (low): a feature test expects one image path and receives another, so the test or the code has drifted. *Fix:* update the expectation. *Effort:* S.

## Scanner summary

- **gitleaks** (full history, 156 commits): 2 findings, both example keys in documentation.
- **Semgrep** (`owasp-top-ten`, `secrets`, `php`, `javascript`, `typescript`): 5 findings, all supply-chain hygiene (`minimum-release-age`, `trust-policy`); 18 files not fully parsed.
- **Trivy** (HIGH/CRITICAL): 1 package (`composer.lock`), 0 secrets, 0 misconfigurations.
- **zizmor**: 2 `artipacked`, 2 `excessive-permissions`, 1 `dependabot-cooldown`, all warnings.

## Not checked

Production `.env` (`APP_DEBUG`, keys), mutation testing, dynamic scanning, load behavior, anything behind a login on the live site.
