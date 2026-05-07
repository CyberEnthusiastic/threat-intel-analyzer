#!/usr/bin/env python3
"""
Threat Intel Analyzer — IOC enrichment, MITRE ATT&CK mapping, threat-actor
TTP correlation, and SIEM detection-rule generation in one CLI.

  $ python analyzer.py --observation samples/observation.json \
                       --intel samples/threat_intel.json \
                       --rules-out rules/

Pipeline:
  1. Enrich each observed IOC against the local intel DB.
  2. Map IOCs + observed process to MITRE ATT&CK techniques.
  3. Correlate the technique set against curated threat-actor profiles.
  4. Generate Sigma detection rules — one per matched actor (or one
     generic rule if no actor crossed threshold).

Zero deps — Python 3.8+ stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter

# UTF-8 stdout for Windows hosts.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, ValueError):
    pass

from ioc_enricher import IOCEnricher  # local module
from mitre_mapper import map_observation
from sigma_generator import make_rule_pack
from ttp_correlator import correlate


_RESET = "\033[0m"
_COL = {
    "CRIT":  "\033[1;91m", "HIGH": "\033[1;33m", "MED": "\033[1;36m",
    "DIM":   "\033[2m",    "OK":   "\033[1;92m", "TITLE": "\033[1;94m",
}


def _c(key: str, s: str) -> str:
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return s
    return f"{_COL.get(key, '')}{s}{_RESET}"


# ─── Pipeline ───────────────────────────────────────────────────────────────
def analyze(observation_path: str, intel_path: str | None = None) -> dict:
    with open(observation_path, "r", encoding="utf-8") as fh:
        obs = json.load(fh)

    enricher = IOCEnricher(intel_path=intel_path)
    enriched = [enricher.enrich(v).as_dict() for v in (obs.get("iocs") or [])]
    obs_for_mapping = dict(obs)
    obs_for_mapping["iocs"] = enriched

    mappings = [m.as_dict() for m in map_observation(obs_for_mapping)]
    technique_ids = [m["technique_id"] for m in mappings]
    correlations = [c.as_dict() for c in correlate(technique_ids)]

    return {
        "observation": obs,
        "enriched_iocs": enriched,
        "techniques": mappings,
        "actors": correlations,
        "ts": int(time.time()),
    }


# ─── Output ─────────────────────────────────────────────────────────────────
def print_report(report: dict) -> None:
    obs = report["observation"]
    enriched = report["enriched_iocs"]
    techs = report["techniques"]
    actors = report["actors"]

    print(_c("TITLE", "=" * 70))
    print(_c("TITLE", "  Threat Intel Analyzer"))
    print(_c("TITLE", "=" * 70))
    print(f"[*] Source: {obs.get('source', 'observation')}  Host: {obs.get('host', '?')}")
    print(f"[*] IOCs   : {len(enriched)}    "
          f"(scored >0: {sum(1 for e in enriched if e['score'] > 0)})")
    print(f"[*] ATT&CK : {len(techs)} techniques mapped")
    print(f"[*] Actors : {len(actors)} correlated profiles\n")

    # Enrichments
    print(_c("HIGH", "── Enriched IOCs " + "─" * 50))
    for e in sorted(enriched, key=lambda x: -x["score"]):
        tag = ",".join(e.get("tags") or []) or "no-tags"
        print(f"   {e['kind']:7} {e['ioc']:50}  score={e['score']:3}  [{tag}]")

    # MITRE
    if techs:
        print()
        print(_c("HIGH", "── MITRE ATT&CK techniques " + "─" * 40))
        for t in techs:
            print(f"   {t['technique_id']:11} {t['technique_name']:35} "
                  f"[{t['tactic_name']}]  conf={t['confidence']}")
            for ev in t["evidence"]:
                print(f"      {_c('DIM', '↳ ' + ev)}")

    # Actors
    if actors:
        print()
        print(_c("HIGH", "── Threat-actor correlations " + "─" * 38))
        for a in actors:
            sig = " ⭐" if a["signature_full"] else ""
            print(f"   {a['actor_name']:40} score={a['score']:3}  "
                  f"({len(a['matched'])}/{a['profile_size']}){sig}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Enrich IOCs, map to ATT&CK, correlate actors, generate Sigma.")
    p.add_argument("--observation", required=True,
                   help="Path to observation JSON (IOCs + process + host)")
    p.add_argument("--intel", help="Path to local threat-intel JSON")
    p.add_argument("--json", help="Write full report JSON to this path")
    p.add_argument("--rules-out", help="Directory to write generated Sigma rules into")
    p.add_argument("--actor-threshold", type=int, default=50,
                   help="Minimum actor score to include in rule generation (default 50)")
    args = p.parse_args(argv)

    report = analyze(args.observation, args.intel)
    print_report(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(_c("DIM", f"\n   -> wrote report JSON to {args.json}"))

    if args.rules_out:
        os.makedirs(args.rules_out, exist_ok=True)
        actors = [a for a in report["actors"] if a["score"] >= args.actor_threshold]
        rules = make_rule_pack(actors, report["enriched_iocs"],
                               [t["technique_id"] for t in report["techniques"]])
        for filename, content in rules:
            path = os.path.join(args.rules_out, filename)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(_c("OK", f"   -> wrote {path}"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
