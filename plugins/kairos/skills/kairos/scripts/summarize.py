#!/usr/bin/env python3
"""Summarize scan.sh output (gitleaks, Semgrep, Trivy, zizmor) as short markdown.

Usage: python3 summarize.py <out-dir> [baseline.json]
Counts and locations only; secret values never appear (gitleaks ran with --redact).

Baseline (optional, committed by the project as .kairos-baseline.json):
  {"accepted": [{"tool": "semgrep", "rule": "missing-user", "path": "Dockerfile", "reason": "final stage sets USER"}]}
  tool: gitleaks|semgrep|trivy|zizmor   rule: name or glob, default "*"   path: glob   reason: required
Accepted findings are not hidden: they are counted next to the open ones.
"""
import fnmatch
import json
import re
import sys
from collections import Counter
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
TOP = 8


def load(name):
    try:
        return json.loads((OUT / name).read_text())
    except (OSError, ValueError):
        return None


def rel(path):
    return path.removeprefix("/src/")


ACCEPTED = []
if len(sys.argv) > 2:
    try:
        entries = json.loads(Path(sys.argv[2]).read_text()).get("accepted", [])
    except (OSError, ValueError) as e:
        entries = []
        print(f"note: baseline not readable ({e}); ignoring it\n")
    for e in entries:
        if e.get("tool") and e.get("path") and str(e.get("reason", "")).strip():
            ACCEPTED.append(e)
        else:
            print(f"note: baseline entry ignored, tool, path and reason are required: {e}\n")


def split(tool, items, rule_of, path_of):
    """(open, accepted) for one tool's findings."""
    def hit(x):
        return any(e["tool"] == tool and fnmatch.fnmatch(rule_of(x), e.get("rule", "*"))
                   and fnmatch.fnmatch(path_of(x), e["path"]) for e in ACCEPTED)
    open_, acc = [], []
    for x in items:
        (acc if hit(x) else open_).append(x)
    return open_, acc


def head(n_open, n_acc, extra=""):
    return f"{n_open} findings{extra}" + (f" (+{n_acc} accepted in baseline)" if n_acc else "")


d = load("gitleaks.json")
print("## gitleaks (full git history)")
if d is None:
    print("no result, see gitleaks.log")
else:
    op, acc = split("gitleaks", d, lambda x: x["RuleID"], lambda x: x["File"])
    print(head(len(op), len(acc)))
    for (rule, f), n in Counter((x["RuleID"], x["File"]) for x in op).most_common(TOP):
        print(f"- {n}x `{rule}` in `{f}`")

d = load("semgrep.json")
print("\n## Semgrep")
if d is None:
    print("no result, see semgrep.log")
else:
    op, acc = split("semgrep", d.get("results", []), lambda r: r["check_id"].split(".")[-1], lambda r: rel(r["path"]))
    sev = Counter(r["extra"]["severity"] for r in op)
    print(head(len(op), len(acc), f" {dict(sev)}; {len(d.get('errors', []))} files not fully parsed"))
    seen = {}
    for r in op:
        seen.setdefault((r["check_id"].split(".")[-1], r["extra"]["severity"]), []).append(r)
    for (rule, s), rs in sorted(seen.items(), key=lambda kv: -len(kv[1]))[:TOP]:
        first = rs[0]
        print(f"- {len(rs)}x [{s}] `{rule}` e.g. `{rel(first['path'])}:{first['start']['line']}`")

d = load("trivy.json")
print("\n## Trivy (HIGH/CRITICAL)")
if d is None:
    print("no result, see trivy.log")
else:
    vulns, mis, secrets, n_acc = Counter(), Counter(), 0, 0
    for r in d.get("Results", []):
        target = rel(r["Target"])
        v_open, v_acc = split("trivy", r.get("Vulnerabilities") or [], lambda v: v["VulnerabilityID"], lambda v: target)
        m_open, m_acc = split("trivy", r.get("Misconfigurations") or [], lambda m: m["ID"], lambda m: target)
        n_acc += len(v_acc) + len(m_acc)
        for v in v_open:
            vulns[(target, v["Severity"])] += 1
        for m in m_open:
            mis[(target, m["ID"], m["Severity"])] += 1
        secrets += len(r.get("Secrets") or [])
    print(f"{sum(vulns.values())} vulnerable packages, {sum(mis.values())} misconfigurations, {secrets} secrets"
          + (f" (+{n_acc} accepted in baseline)" if n_acc else ""))
    for (target, s), n in vulns.most_common(TOP):
        print(f"- {n}x {s} in `{target}`")
    for (target, mid, s), n in mis.most_common(TOP):
        print(f"- {n}x {s} `{mid}` in `{target}`")

print("\n## zizmor (GitHub Actions)")
try:
    text = re.sub(r"\x1b\[[0-9;]*m", "", (OUT / "zizmor.txt").read_text())
except OSError:
    print("no .github directory or no result")
else:
    found = [{"rule": m.group(1) + ":" + m.group(2), "name": m.group(2), "path": (m.group(3) or "").strip()}
             for m in re.finditer(r"^(error|warning|note|info)\[([a-z0-9-]+)\].*\n\s*--> ([^:\n]+)", text, re.M)]
    op, acc = split("zizmor", found, lambda x: x["name"], lambda x: x["path"].removeprefix("./"))
    rules = Counter(x["rule"] for x in op)
    print((", ".join(f"{n}x {r}" for r, n in rules.most_common()) or "no findings")
          + (f" (+{len(acc)} accepted in baseline)" if acc else ""))

if ACCEPTED:
    print(f"\nBaseline: {len(ACCEPTED)} accepted entries applied; reasons: " + "; ".join(sorted({e['reason'] for e in ACCEPTED})[:5]))
print("\nRead every hit before dismissing it; generated code, docs examples and test fixtures are the usual false positives.")
