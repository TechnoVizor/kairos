#!/usr/bin/env python3
"""Turn audit facts into the Kairos score, with the arithmetic and the anchors in one place.

Usage:
  python3 score.py --example > facts.json     start from a filled-in example
  python3 score.py facts.json [--json out.json]
  python3 score.py --selftest

Measurable criteria (tests, static, deps, hardening, ci) are scored from numbers by fixed anchors.
Judged criteria (security, privacy, maintain) take the auditor's 0-10 score and REQUIRE a reason.
Set a criterion to null when it was not audited: it is dropped and the weights are renormalized.
"""
import json
import sys

WEIGHTS = {"tests": 20, "static": 10, "deps": 10, "security": 25, "hardening": 15, "ci": 10, "privacy": 5, "maintain": 5}
LABELS = {"tests": "Tests", "static": "Static analysis", "deps": "Dependencies", "security": "Code security",
          "hardening": "Live hardening", "ci": "CI / ops", "privacy": "GDPR / privacy", "maintain": "Maintainability"}

EXAMPLE = {
    "project": "Example Shop",
    "_help": {
        "tests": "passed/failed = test counts; coverage_pct = WHOLE-source line coverage or null if not measured; critical_min_pct = lowest coverage among auth/payments/admin packages or null",
        "static": "clean = tools that passed, total = tools that exist (lint, types, static analyzer, vet...)",
        "deps": "one entry per advisory; severity critical|high|medium|low; reachable true|false|\"unknown\" (unknown counts as reachable); behind_minor = minor releases behind on the main framework or null",
        "hardening": "headers from live.py; csp = enforced|report-only|missing; null for a check you could not make; checked=false when there is no live URL",
        "ci": "true/false/null per check",
        "security, privacy, maintain": "judged 0-10 with a reason of at least 15 characters",
    },
    "tests": {"passed": 304, "failed": 1, "coverage_pct": 91.5, "critical_min_pct": None},
    "static": {"clean": 3, "total": 4},
    "deps": {"advisories": [{"severity": "high", "reachable": False}], "behind_minor": 9},
    "security": {"score": 7.5, "why": "No injection sinks; admin guards read; gitleaks and Semgrep clean"},
    "hardening": {"checked": True, "hsts": False, "csp": "missing", "frame": False, "nosniff": False, "referrer": False,
                  "permissions": False, "cookies_ok": True, "powered_by_hidden": False, "env_blocked": True, "cors_ok": True},
    "ci": {"pr_ci": False, "gates_deploy": None, "actions_pinned": True, "permissions_set": True, "no_secret_echo": True,
           "deps_automation": True, "main_protected": False},
    "privacy": {"score": 9, "why": "Erasure and retention purge exist and are tested"},
    "maintain": {"score": 8, "why": "Documented, one TODO in the codebase"},
}


def s_tests(f):
    p, fl, cov, crit = f["passed"], f["failed"], f.get("coverage_pct"), f.get("critical_min_pct")
    if p + fl == 0:
        return 2.0, "no tests"
    notes = []
    if cov is None:
        base = 6.0
        notes.append("coverage not measured, capped at 6")
    else:
        base = next(s for t, s in [(80, 10), (60, 8), (40, 6.5), (25, 5), (10, 3.5), (0, 2.5)] if cov >= t)
        notes.append(f"{cov:g}% coverage")
    rate = p / (p + fl)
    base -= 0 if fl == 0 else 0.5 if rate >= 0.95 else 1.5 if rate >= 0.8 else 3
    notes.insert(0, f"{p}/{p + fl} pass")
    if crit is not None and crit < 50:
        base = min(base, 6.0)
        notes.append(f"critical package at {crit:g}% caps at 6")
    return max(base, 0.0), ", ".join(notes)


def s_static(f):
    if f["total"] == 0:
        return 3.0, "no linters or analyzers configured"
    return 10.0 * f["clean"] / f["total"], f"{f['clean']}/{f['total']} tools clean"


PENALTY = {("critical", True): 3, ("critical", False): 0.75, ("high", True): 1.5, ("high", False): 0.25,
           ("medium", True): 0.5, ("medium", False): 0.1, ("low", True): 0.1, ("low", False): 0.0}


def s_deps(f):
    pen = sum(PENALTY[(a["severity"], a.get("reachable", "unknown") is not False)] for a in f["advisories"])
    pen = min(pen, 8)
    b = f.get("behind_minor")
    stale = 0 if b is None else 1.5 if b >= 20 else 1 if b >= 8 else 0.5 if b >= 3 else 0
    return max(10 - pen - stale, 0.0), f"{len(f['advisories'])} advisories, {b if b is not None else '?'} minors behind"


HARD = [("hsts", 2), ("csp", 2), ("frame", 1), ("nosniff", 1), ("referrer", 0.5), ("permissions", 0.5),
        ("cookies_ok", 1.5), ("powered_by_hidden", 0.5), ("env_blocked", 0.5), ("cors_ok", 0.5)]


def s_hardening(f):
    if not f.get("checked", True):
        return None
    got = total = 0.0
    missing = []
    for key, w in HARD:
        v = f.get(key)
        if v is None:
            continue
        ok = {"enforced": 1, "report-only": 0.5, "missing": 0}[v] if key == "csp" else (1 if v else 0)
        got += w * ok
        total += w
        if ok < 1:
            missing.append(key)
    if total == 0:
        return None
    return 10 * got / total, "missing/weak: " + (", ".join(missing) or "none")


CI = ["pr_ci", "gates_deploy", "actions_pinned", "permissions_set", "no_secret_echo", "deps_automation", "main_protected"]


def s_ci(f):
    known = [k for k in CI if f.get(k) is not None]
    if not known:
        return None
    bad = [k for k in known if not f[k]]
    return 10.0 * (len(known) - len(bad)) / len(known), "failing: " + (", ".join(bad) or "none")


def judged(f):
    return float(f["score"]), f["why"]


SCORERS = {"tests": s_tests, "static": s_static, "deps": s_deps, "hardening": s_hardening, "ci": s_ci,
           "security": judged, "privacy": judged, "maintain": judged}


def validate(facts):
    errs = []
    num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
    for k in WEIGHTS:
        if k not in facts:
            errs.append(f"{k}: missing (use null if it was not audited)")
    t = facts.get("tests")
    if t is not None:
        for k in ("passed", "failed"):
            if not (isinstance(t.get(k), int) and t[k] >= 0):
                errs.append(f"tests.{k}: must be a non-negative integer, got {t.get(k)!r}")
        for k in ("coverage_pct", "critical_min_pct"):
            v = t.get(k)
            if v is not None and not (num(v) and 0 <= v <= 100):
                errs.append(f"tests.{k}: must be 0-100 or null, got {v!r}")
    s = facts.get("static")
    if s is not None and not (isinstance(s.get("clean"), int) and isinstance(s.get("total"), int) and 0 <= s["clean"] <= s["total"]):
        errs.append("static: needs integers with 0 <= clean <= total")
    d = facts.get("deps")
    if d is not None:
        for i, a in enumerate(d.get("advisories") or []):
            if a.get("severity") not in ("critical", "high", "medium", "low"):
                errs.append(f"deps.advisories[{i}].severity: critical|high|medium|low, got {a.get('severity')!r}")
            if a.get("reachable", "unknown") not in (True, False, "unknown"):
                errs.append(f"deps.advisories[{i}].reachable: true|false|\"unknown\", got {a.get('reachable')!r}")
        if "advisories" not in d:
            errs.append("deps.advisories: missing (use [] for none)")
    h = facts.get("hardening")
    if h is not None and h.get("csp") not in (None, "enforced", "report-only", "missing"):
        errs.append(f"hardening.csp: enforced|report-only|missing|null, got {h.get('csp')!r}")
    for k in ("security", "privacy", "maintain"):
        j = facts.get(k)
        if j is None:
            continue
        if not (num(j.get("score")) and 0 <= j["score"] <= 10):
            errs.append(f"{k}.score: must be 0-10, got {j.get('score')!r}")
        if len(str(j.get("why", "")).strip()) < 15:
            errs.append(f"{k}.why: a judged score needs a reason of at least 15 characters")
    return errs


def compute(facts):
    rows = {}
    for k, fn in SCORERS.items():
        if facts.get(k) is None:
            continue
        r = fn(facts[k])
        if r is not None:
            rows[k] = {"score": round(r[0], 1), "weight": WEIGHTS[k], "note": r[1]}
    wsum = sum(v["weight"] for v in rows.values())
    total = round(sum(v["score"] * v["weight"] for v in rows.values()) / wsum, 1) if wsum else None
    return rows, total, wsum


def render(facts, rows, total, wsum):
    out = [f"| Criterion | Weight | Score | Basis |", "|---|---:|---:|---|"]
    for k in WEIGHTS:
        if k in rows:
            r = rows[k]
            out.append(f"| {LABELS[k]} | {r['weight']} | {r['score']:g} | {r['note']} |")
        else:
            out.append(f"| {LABELS[k]} | {WEIGHTS[k]} | n/a | not audited, dropped |")
    out.append(f"\n**Total: {total:g} / 10** (weights renormalized over {wsum}% audited)" if total is not None else "\nNo criterion audited.")
    return "\n".join(out)


def selftest():
    assert s_tests({"passed": 10, "failed": 0, "coverage_pct": 85}) == (10, "10/10 pass, 85% coverage")
    assert s_tests({"passed": 10, "failed": 0, "coverage_pct": 85, "critical_min_pct": 30})[0] == 6.0
    assert s_tests({"passed": 304, "failed": 1, "coverage_pct": 91.5})[0] == 9.5
    assert s_tests({"passed": 5, "failed": 0, "coverage_pct": None})[0] == 6.0
    assert s_tests({"passed": 0, "failed": 0})[0] == 2.0
    assert s_static({"clean": 3, "total": 4})[0] == 7.5
    assert s_deps({"advisories": [], "behind_minor": 0})[0] == 10
    assert s_deps({"advisories": [{"severity": "critical"}], "behind_minor": None})[0] == 7  # unknown counts as reachable
    assert s_hardening({"checked": False}) is None
    assert s_hardening({"hsts": True, "csp": "report-only"})[0] == 7.5  # (2 + 1) / 4
    assert s_ci({"pr_ci": True, "main_protected": False})[0] == 5.0
    assert s_ci({}) is None
    assert validate(EXAMPLE) == [], validate(EXAMPLE)
    assert any("reason" in e for e in validate({**EXAMPLE, "security": {"score": 5, "why": "ok"}}))
    assert any("tests.coverage_pct" in e for e in validate({**EXAMPLE, "tests": {"passed": 1, "failed": 0, "coverage_pct": "high"}}))
    rows, total, wsum = compute({**{k: None for k in WEIGHTS}, "tests": {"passed": 9, "failed": 0, "coverage_pct": 90}})
    assert (total, wsum) == (10.0, 20), (total, wsum)  # a single audited criterion renormalizes to itself
    rows, total, wsum = compute(EXAMPLE)
    assert wsum == 100 and 5 < total < 9, (total, wsum)
    print("selftest ok")


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if "--example" in argv:
        print(json.dumps(EXAMPLE, indent=2))
        return 0
    paths = [a for a in argv if not a.startswith("--") and a != (argv[argv.index("--json") + 1] if "--json" in argv else None)]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    facts = json.load(open(paths[0]))
    errs = validate(facts)
    if errs:
        print("facts file is invalid:\n  - " + "\n  - ".join(errs), file=sys.stderr)
        return 2
    rows, total, wsum = compute(facts)
    print(render(facts, rows, total, wsum))
    if "--json" in argv:
        json.dump({"project": facts.get("project"), "total": total, "criteria": rows}, open(argv[argv.index("--json") + 1], "w"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
