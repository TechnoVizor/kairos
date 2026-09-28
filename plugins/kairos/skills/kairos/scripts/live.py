#!/usr/bin/env python3
"""Read-only hardening facts for a live site. GET/HEAD only, no logins, no POST.

Usage: python3 live.py <url> [--cors-url <url>]
  <url>       the site (redirects are followed; headers of the final response are judged)
  --cors-url  also test CORS reflection on this URL (e.g. a JSON endpoint of the API)

Prints JSON that fits the `hardening` block of the facts file for score.py.
A value of null means "could not be determined". On a network error: {"checked": false, ...}.
"""
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = {"User-Agent": "kairos-live-check/1.0"}
ALIEN_ORIGIN = "https://kairos-check.invalid"


def fetch(url, method="HEAD", headers=None, body_bytes=0):
    """Returns (status, headers, body_prefix, final_url). HEAD falls back to GET when refused."""
    for m in ([method, "GET"] if method == "HEAD" else [method]):
        req = urllib.request.Request(url, method=m, headers={**UA, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.headers, (r.read(body_bytes) if body_bytes else b""), r.geturl()
        except urllib.error.HTTPError as e:
            if m == "HEAD" and e.code in (403, 405, 501):
                continue
            return e.code, e.headers, (e.read(body_bytes) if body_bytes else b""), url
    raise RuntimeError("no response")


def cookie_facts(headers):
    out = []
    for raw in headers.get_all("Set-Cookie") or []:
        flags = raw.lower()
        name = raw.split("=", 1)[0].strip()
        out.append({"name": name, "secure": "; secure" in flags, "httponly": "; httponly" in flags,
                    "samesite": "samesite=" in flags,
                    # only session/auth cookies must carry all flags; locale or CSRF cookies legitimately do not
                    "session_like": bool(re.search(r"(?i)sess|sid|auth|jwt|login|remember|token", name))
                                    and not re.match(r"(?i)(x?csrf|xsrf)", name)})
    return out


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 2
    url = argv[0]
    cors_url = argv[argv.index("--cors-url") + 1] if "--cors-url" in argv else url
    try:
        status, h, _, final = fetch(url)
    except Exception as e:  # network, TLS, DNS
        print(json.dumps({"checked": False, "error": str(e)}))
        return 0
    g = lambda k: (h.get(k) or "").strip()
    csp, csp_ro = g("content-security-policy"), g("content-security-policy-report-only")
    real = lambda p: bool(re.search(r"(?i)\b(default-src|script-src)\b", p))
    hsts_age = re.search(r"max-age=(\d+)", g("strict-transport-security"))
    cookies = cookie_facts(h)
    sess = [c for c in cookies if c["session_like"]]

    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(final))
    try:
        st, _, body, _ = fetch(origin + "/.env", "GET", body_bytes=2048)
        env_blocked = not (st == 200 and re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=", body))
    except Exception:
        env_blocked = None
    try:
        _, ch, _, _ = fetch(cors_url, "GET", {"Origin": ALIEN_ORIGIN})
        acao, cred = (ch.get("access-control-allow-origin") or ""), (ch.get("access-control-allow-credentials") or "").lower()
        cors_ok = not (acao == ALIEN_ORIGIN or (acao == "*" and cred == "true"))
    except Exception:
        cors_ok = None

    print(json.dumps({
        "checked": True,
        "hsts": bool(hsts_age and int(hsts_age.group(1)) >= 15552000),
        "csp": "enforced" if real(csp) else "report-only" if real(csp_ro) else "missing",
        "frame": bool(g("x-frame-options") or re.search(r"(?i)frame-ancestors", csp)),
        "nosniff": g("x-content-type-options").lower() == "nosniff",
        "referrer": bool(g("referrer-policy")),
        "permissions": bool(g("permissions-policy")),
        "cookies_ok": None if not sess else all(c["secure"] and c["httponly"] and c["samesite"] for c in sess),
        "powered_by_hidden": not g("x-powered-by") and not re.search(r"\d+\.\d+", g("server")),
        "env_blocked": env_blocked,
        "cors_ok": cors_ok,
        "details": {"url": final, "status": status, "server": g("server") or None, "x_powered_by": g("x-powered-by") or None,
                    "csp_present": bool(csp or csp_ro), "cookies": cookies},
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
