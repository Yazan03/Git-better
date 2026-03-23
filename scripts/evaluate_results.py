#!/usr/bin/env python3
"""
Evaluate scan outputs and decide whether CI should fail.
"""

import argparse
import json
import sys
from pathlib import Path


def read_json(path: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def bandit_counts(data):
    if not isinstance(data, dict):
        return {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    results = data.get("results", [])
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in results:
        sev = str(item.get("issue_severity", "")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def safety_count(data):
    if data is None:
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("issues", "vulnerabilities", "results"):
            if isinstance(data.get(key), list):
                return len(data.get(key))
    return 0


def custom_counts(data):
    if not isinstance(data, dict):
        return {"high": 0, "medium": 0, "low": 0}
    return {
        "high": int(data.get("high", 0)),
        "medium": int(data.get("medium", 0)),
        "low": int(data.get("low", 0)),
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate security scan results")
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--safety", required=True)
    parser.add_argument("--custom", required=True)
    args = parser.parse_args()

    bandit = read_json(args.bandit)
    safety = read_json(args.safety)
    custom = read_json(args.custom)

    bandit_sev = bandit_counts(bandit)
    safety_issues = safety_count(safety)
    custom_sev = custom_counts(custom)

    print("Scan summary")
    print(f"Bandit: HIGH={bandit_sev['HIGH']} MEDIUM={bandit_sev['MEDIUM']} LOW={bandit_sev['LOW']}")
    print(f"Safety: issues={safety_issues}")
    print(f"Custom: HIGH={custom_sev['high']} MEDIUM={custom_sev['medium']} LOW={custom_sev['low']}")

    fail = False
    if bandit_sev["HIGH"] > 0 or custom_sev["high"] > 0:
        fail = True
    if safety_issues > 0:
        fail = True

    if fail:
        print("Failing build due to high severity issues or vulnerable dependencies.")
        sys.exit(1)

    print("No blocking issues found.")
    sys.exit(0)


if __name__ == "__main__":
    main()
