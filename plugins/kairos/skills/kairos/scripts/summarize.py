#!/usr/bin/env python3
"""Summarize scan.sh output (gitleaks, Semgrep, Trivy, zizmor) as short markdown.

Usage: python3 summarize.py <out-dir>
Counts and locations only; secret values never appear (gitleaks ran with --redact).
"""
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


d = load("gitleaks.json")
print("## gitleaks (full git history)")
if d is None:
    print("no result, see gitleaks.log")
else:
    print(f"{len(d)} findings")
    for (rule, f), n in Counter((x["RuleID"], x["File"]) for x in d).most_common(TOP):
        print(f"- {n}x `{rule}` in `{f}`")

d = load("semgrep.json")
print("\n## Semgrep")
if d is None:
    print("no result, see semgrep.log")
else:
    res = d.get("results", [])
    sev = Counter(r["extra"]["severity"] for r in res)
    print(f"{len(res)} findings {dict(sev)}; {len(d.get('errors', []))} files not fully parsed")
    seen = {}
    for r in res:
        seen.setdefault((r["check_id"].split(".")[-1], r["extra"]["severity"]), []).append(r)
    for (rule, s), rs in sorted(seen.items(), key=lambda kv: -len(kv[1]))[:TOP]:
        first = rs[0]
        print(f"- {len(rs)}x [{s}] `{rule}` e.g. `{rel(first['path'])}:{first['start']['line']}`")

d = load("trivy.json")
print("\n## Trivy (HIGH/CRITICAL)")
if d is None:
    print("no result, see trivy.log")
else:
    vulns, mis, secrets = Counter(), Counter(), 0
    for r in d.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            vulns[(rel(r["Target"]), v["Severity"])] += 1
        for m in r.get("Misconfigurations") or []:
            mis[(rel(r["Target"]), m["ID"], m["Severity"])] += 1
        secrets += len(r.get("Secrets") or [])
    print(f"{sum(vulns.values())} vulnerable packages, {sum(mis.values())} misconfigurations, {secrets} secrets")
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
    rules = Counter(m.group(1) + ":" + m.group(2) for m in re.finditer(r"^(error|warning|note|info)\[([a-z0-9-]+)\]", text, re.M))
    print(", ".join(f"{n}x {r}" for r, n in rules.most_common()) or "no findings")

print("\nRead every hit before dismissing it; generated code, docs examples and test fixtures are the usual false positives.")
