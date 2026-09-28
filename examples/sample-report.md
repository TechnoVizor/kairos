# Sample report

Illustrative output, anonymized from a real run on a Laravel 13 + Filament 5 + Inertia/Vue marketing site with a lead-capture form.

**Example Shop**, audited from `origin/main`.

## Verdict: 7.1 / 10

Ready for production as a marketing site. No blocking vulnerabilities found. The biggest gaps are cheap: security headers, admin MFA, unprotected `main`.

| Criterion | Weight | Fact | Score |
|---|---:|---|---:|
| Tests | 20 | 304/305 pass, 3331 assertions; 91.5% line coverage (pcov) | 9.5 |
| Static analysis | 10 | Pint clean, ESLint clean, `vue-tsc` clean; PHPStan level 7: 75 errors | 6 |
| Dependencies | 10 | `npm audit`: 0; `composer audit`: 1 high (unused feature); framework several minors behind | 7 |
| Code security | 25 | No raw SQL with user input, no exec/eval; Semgrep: 0 code findings; gitleaks: 2 hits, both doc examples | 7.5 |
| Live hardening | 15 | No HSTS, CSP or X-Frame-Options; `X-Powered-By` leaks the PHP version; cookies are `secure; httponly; samesite` | 4 |
| CI / ops | 10 | Actions pinned by SHA, `permissions:` set; CI is manual-only; `main` unprotected | 5.5 |
| GDPR / privacy | 5 | Erasure and retention purge commands, both tested | 9 |
| Maintainability | 5 | Documented, 1 TODO in the codebase | 8 |
| **Total** | 100 | | **7.1** |

## Findings, worst first

1. **No security headers on the live site.** `curl -sI https://example.test/` shows no `Strict-Transport-Security`, `Content-Security-Policy` or `X-Frame-Options`; `X-Powered-By: PHP/8.4.19` is exposed. Fix: set them in `.htaccess` or a middleware.
2. **`main` has no branch protection and CI only runs manually.** Anyone with write access can push straight to the branch that deploys. `gh api repos/<o>/<r>/branches/main/protection` returns "Branch not protected"; `rules/branches/main` is empty.
3. **Admin panel has no MFA.** Two-factor exists for the public accounts but not for the Filament panel.
4. **`league/commonmark` 2.9.1 advisory (high).** The affected Attributes extension is not used anywhere in `app/`, Filament or the framework, so it is not reachable. `composer update league/commonmark` clears it.
5. **Legal pages render admin HTML with `v-html` and no sanitizer**, while the blog goes through one. Only admins can write it, so the risk is low; sanitize anyway.
6. **PHPStan level 7 reports 75 errors** (mostly missing array value types and `resource|false`), and the manual CI would fail on them.
7. **One failing test:** a feature test that expects one image path and receives another, so the test or the code has drifted.

## Scanner summary

- **gitleaks** (full history, 156 commits): 2 findings, both example keys in documentation.
- **Semgrep** (`owasp-top-ten`, `secrets`, `php`, `javascript`, `typescript`): 5 findings, all supply-chain hygiene (`minimum-release-age`, `trust-policy`); 18 files not fully parsed.
- **Trivy** (HIGH/CRITICAL): 1 package (`composer.lock`), 0 secrets, 0 misconfigurations.
- **zizmor**: 2 `artipacked`, 2 `excessive-permissions`, 1 `dependabot-cooldown`, all warnings.

## Not checked

Production `.env` (`APP_DEBUG`, keys), mutation testing, dynamic scanning, load behavior, anything behind a login on the live site.
