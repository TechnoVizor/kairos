# Fix recipes

One recipe per common finding: what to change, then how to verify. Adapt names to the project. Load the section you
need, not the whole file. Every recipe ends with a check the developer can run.

## Contents
- Security headers · X-Powered-By leak
- `main` is not protected
- GitHub Actions: pin, permissions, injection
- Admin route guarded by login only
- Open redirect
- Secret in git history · `.env` tracked by git
- Vulnerable dependency
- Command injection · reflected XSS
- Docker runs as root
- Go server timeouts
- Swagger UI from a CDN
- Missing authorization tests

## Security headers · X-Powered-By leak
Start CSP as report-only, watch for breakage, then enforce.

Apache (`public/.htaccess`):
```apache
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  Header always set Content-Security-Policy-Report-Only "default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"
  Header unset X-Powered-By
</IfModule>
```
nginx: the same `add_header <Name> "<value>" always;` lines, plus `server_tokens off;` and `fastcgi_hide_header X-Powered-By;`.
Laravel: a middleware that sets the same headers on `$response->headers`, registered with `$middleware->web(append: [SecurityHeaders::class]);` in `bootstrap/app.php`.
Next.js: `poweredByHeader: false` and an `async headers()` returning the same key/value pairs for `source: '/(.*)'`. Express: `app.disable('x-powered-by')` or `helmet()`.
Verify: `python3 <skill-dir>/scripts/live.py https://your-site` shows every header true.

## `main` is not protected
Classic protection with required PRs and a green CI check (all four keys are required by the API):
```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input - <<'EOF'
{"required_status_checks":{"strict":true,"contexts":["CI"]},"enforce_admins":false,
 "required_pull_request_reviews":{"required_approving_review_count":1},"restrictions":null}
EOF
```
Use the real name of the CI job in `contexts`. On GitHub Free, private repositories cannot use branch protection.
Verify: `gh api repos/OWNER/REPO/branches/main/protection` returns the settings instead of "Branch not protected".

## GitHub Actions: pin, permissions, injection
- Pin by commit SHA: `gh api repos/actions/checkout/commits/v4 --jq .sha`, then `uses: actions/checkout@<sha> # v4`.
  Keep pins fresh with Dependabot:
  ```yaml
  version: 2
  updates:
    - package-ecosystem: github-actions
      directory: /
      schedule: { interval: weekly }
      cooldown: { default-days: 7 }
  ```
- Least privilege: top-level `permissions: contents: read`; grant `packages: write` only on the job that pushes images.
- Expression injection: pass untrusted values through `env`, never inline in `run:`:
  ```yaml
  - env:
      PR_TITLE: ${{ github.event.pull_request.title }}
    run: echo "Testing PR $PR_TITLE"
  ```
- `pull_request_target` must not check out or run PR code; use `pull_request`.
Verify: `docker run --rm -v "$PWD":/w:ro -w /w ghcr.io/zizmorcore/zizmor --offline .`

## Admin route guarded by login only
Laravel: add a policy and put it on the route, so a logged-in non-admin gets 403:
```php
Route::delete('/admin/products/{product}', [ProductController::class, 'destroy'])
    ->middleware(['auth', 'can:delete,product']);
```
Or `$this->authorize('delete', $product);` in the controller. Express: a `requireRole('admin')` middleware after `requireLogin`.
Then pin it with a test:
```php
public function test_employee_cannot_delete_a_product(): void
{
    $employee = User::factory()->create(['role' => 'employee']);
    $this->actingAs($employee)->delete("/admin/products/{$this->product->id}")->assertForbidden();
}
```
Verify: the test fails without the guard and passes with it.

## Open redirect
Accept only same-site relative paths:
```php
$back = $request->query('back');
$safe = is_string($back) && str_starts_with($back, '/') && ! str_starts_with($back, '//') ? $back : url('/admin');
return redirect()->to($safe);
```
Verify: `?back=https://evil.example` and `?back=//evil.example` both land on `/admin`.

## Secret in git history · `.env` tracked by git
1. **Rotate or revoke the secret first.** Clones and forks keep the history; a removed line is not a removed leak.
2. Tracked `.env`: `git rm --cached .env`, add `.env` to `.gitignore`, commit a `.env.example` with placeholders.
3. Optional history rewrite: `git filter-repo --replace-text expressions.txt`, force-push, everyone re-clones.
Verify: `gitleaks detect --redact` over the full history shows no live secret, and the provider shows the old key revoked.

## Vulnerable dependency
- Read the advisory: is the vulnerable feature used (Windows-only, AVIF disabled, extension never loaded)? That decides urgency, not the label.
- Fix inside the major: `composer update vendor/pkg --with-dependencies`, `npm i pkg@<fixed>`, `go get pkg@<fixed>` then `go mod tidy`.
- Framework bumps (Next.js, Laravel, Filament): run the full tests and click the admin panel afterwards.
Verify: `composer audit --locked`, `npm audit --omit=dev`, `govulncheck ./...` no longer list it.

## Command injection · reflected XSS
- No shell with user input: `execFile('ping', ['-c1', host])` (validate `host` against a hostname pattern) instead of `exec()` with the host concatenated into the command string. PHP: `escapeshellarg`, or avoid the shell.
- Escape on output: templates that auto-escape (Blade `{{ }}`, Vue `{{ }}`); never build HTML with string concatenation or `v-html` on user data; sanitize rich text on the server.
Verify: `?host=127.0.0.1;id` and `?name=<script>` are inert.

## Docker runs as root
```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY --chown=node:node . .
RUN npm ci --omit=dev
USER node
CMD ["node", "server.js"]
```
Pin a supported base image tag; use a multi-stage build so build tools stay out of the final image.
Verify: `docker run --rm image id -u` is not `0`; Trivy's `DS-0002` disappears.

## Go server timeouts
```go
srv := &http.Server{
    Addr: addr, Handler: h,
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      60 * time.Second, // raise or use http.ResponseController for streaming endpoints
    IdleTimeout:       120 * time.Second,
}
```
Verify: a client that opens a connection and sends nothing is dropped after the timeout.

## Swagger UI from a CDN
Serve it from the project, or pin an exact version with a subresource-integrity hash:
`curl -s <url> | openssl dgst -sha384 -binary | openssl base64 -A`, then `<script src="<url>" integrity="sha384-<hash>" crossorigin="anonymous">`.
A floating tag (`@5`) on the same origin as an admin panel lets a compromised CDN act as the admin.

## Missing authorization tests
A table-driven test per role beats coverage chasing. Go:
```go
for _, tc := range []struct{ role string; want int }{{"client", 403}, {"mentor", 403}, {"staff", 200}} {
    t.Run(tc.role, func(t *testing.T) { /* call the admin endpoint as tc.role */ })
}
```
Cover the guard functions themselves (`requireStaff`-style helpers) and every admin route once per role.
Verify: coverage of the guard is above 0% and removing the guard breaks a test.
