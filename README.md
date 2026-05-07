# Threat Intel Analyzer

> **IOC enrichment, MITRE ATT&CK mapping, threat-actor TTP correlation, and SIEM rule generation in one CLI.**
> Turns a raw incident observation into a triage report and a Sigma rule pack — feed straight back into Splunk / Elastic / Sentinel.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-1F4E79)](https://attack.mitre.org/)
[![Sigma](https://img.shields.io/badge/output-Sigma%20YAML-7B42BC)](https://github.com/SigmaHQ/sigma)

---

## What it does

Takes one observation (a host + process + list of IOCs from an incident),
runs four steps:

1. **Enrich** every IOC against a local threat-intel JSON (and optional
   public OSINT) — IPs, domains, URLs, MD5/SHA1/SHA256 all supported.
2. **Map** the enriched IOCs + observed process to MITRE ATT&CK
   techniques. Ships with a curated 30+ technique corpus covering the most
   common SOC observations (PowerShell, encoded scripts, ransomware,
   Tor, MFA fatigue, etc.).
3. **Correlate** the resulting technique set against curated threat-actor
   profiles (LockBit 3.0, BlackCat, FIN7, Lazarus, SmokeLoader,
   Scattered Spider, MFA-fatigue kits, Tor-exfil) — outputs a ranked
   list with confidence scores.
4. **Generate Sigma rules** — one YAML rule per matched actor (or one
   generic rule when nothing crosses threshold). Convert with
   `sigmac` to your SIEM dialect.

```
======================================================================
  Threat Intel Analyzer
======================================================================
[*] Source: soc-tier-1-incident-2025-04-18  Host: WIN-FIN-014
[*] IOCs   : 5    (scored >0: 5)
[*] ATT&CK : 9 techniques mapped
[*] Actors : 8 correlated profiles

── MITRE ATT&CK techniques ─────────────────────
   T1090.003   Multi-hop Proxy (Tor)         [Command and Control]  conf=85
   T1486       Data Encrypted for Impact     [Impact]  conf=85
   T1490       Inhibit System Recovery       [Impact]  conf=85
   T1105       Ingress Tool Transfer         [Command and Control]  conf=85
   T1059.001   PowerShell                    [Execution]  conf=75
   ...

── Threat-actor correlations ──────────────────
   Tor-based exfiltration            score=73  (2/3) ⭐
   SmokeLoader broker                score=60  (3/6) ⭐
   BlackCat / ALPHV                  score=50  (5/8)
   ...
   -> wrote rules/blackcat_alphv.yml
   -> wrote rules/smokeloader_broker.yml
   -> wrote rules/tor_based_exfiltration.yml
```

---

## Why you want this

- **Triage → detection in one tool.** Most incident workflows stop at "we have IOCs." This tool keeps going: maps them, attributes them, *and* writes the detection rule that catches the next one.
- **Sigma output is portable.** YAML rules convert to Splunk SPL, Elastic EQL, Sentinel KQL, Chronicle YARA-L via `sigmac`. One source of truth, every SIEM.
- **Threat-actor attribution that's honest.** Scores are derived from how many of the actor's signature techniques you saw — no AI hallucinations, no opaque embeddings. You can read the table in `ttp_correlator.py` and disagree.
- **Local-first.** The IOC database, ATT&CK corpus, and actor profiles all live in this repo. Works in air-gapped environments where you can't hit external threat-intel APIs.
- **Zero dependencies.** Python 3.8+ stdlib only.

---

## Quickstart

```bash
git clone https://github.com/CyberEnthusiastic/threat-intel-analyzer.git
cd threat-intel-analyzer

# Run on the bundled observation (5 IOCs → 9 techniques → 3 Sigma rules):
python analyzer.py --observation samples/observation.json \
                   --intel samples/threat_intel.json \
                   --rules-out rules/

# Real run from a SOAR or runbook:
python analyzer.py --observation /tmp/incident-2025-04.json \
                   --intel ./intel/local.json --json out.json \
                   --rules-out detection_rules/
```

---

## Observation format

Minimal observation shape:

```json
{
  "source": "soc-tier-1-incident-2025-04-18",
  "host": "WIN-FIN-014",
  "user": "fin\\jdoe",
  "process": "powershell.exe",
  "iocs": [
    "45.155.205.233",
    "44d8...02f",
    "evil-update.click",
    "185.220.101.42"
  ]
}
```

Anything you don't have, omit. The pipeline degrades gracefully — fewer
inputs → fewer mappings → fewer rules, never an error.

---

## ATT&CK corpus

The technique corpus in `mitre_mapper.py` covers 30+ techniques across all
12 ATT&CK tactics. Examples:

| Technique | Tactic | Trigger |
|---|---|---|
| `T1059.001` PowerShell | Execution | process = `powershell.exe` / `pwsh.exe` |
| `T1059.005` Visual Basic | Execution | process = `wscript.exe` / `cscript.exe` / `mshta.exe` |
| `T1486` Data Encrypted for Impact | Impact | tag = `ransomware` |
| `T1490` Inhibit System Recovery | Impact | tag = `ransomware` |
| `T1071.001` Web Protocols | C&C | URL / domain IOC |
| `T1090.003` Multi-hop Proxy (Tor) | C&C | tag = `tor-exit` |
| `T1105` Ingress Tool Transfer | C&C | tag = `loader` |
| `T1621` MFA Request Generation | Credential Access | tag = `mfa-fatigue` |

Adding a mapping = one entry in `_TAG_TO_TECH` or `_PROCESS_TECHNIQUES`.

---

## Threat-actor profiles

| Actor | Category | Signature techniques |
|---|---|---|
| **LockBit 3.0** | ransomware | T1486, T1490, T1562.001 |
| **BlackCat / ALPHV** | ransomware | T1486, T1078.004 |
| **FIN7 / Carbon Spider** | apt | T1059.005, T1078 |
| **Lazarus / APT38** | apt | T1567.002, T1041 |
| **SmokeLoader broker** | loader | T1105, T1027 |
| **Scattered Spider / 0ktapus** | apt | T1621, T1078.004 |
| **MFA fatigue kit** | broker | T1621 |
| **Tor exfiltration** | broker | T1090.003 |

A correlation gets a base score from `(matched / profile_size) * 80`,
plus 20 if all signature techniques are present (the ⭐ in output).

---

## Sigma output

Each generated rule is valid Sigma YAML 1.0:

```yaml
title: Activity matching SmokeLoader broker
id: a3f1...
description: Auto-generated from 3 of 6 signature techniques.
status: experimental
author: threat-intel-analyzer
date: 2025/04/18
tags:
    - attack.t1105
    - attack.t1027
    - attack.t1071.001
references:
    - actor:smokeloader_broker
logsource:
    category: network_connection
detection:
    sel_ip:
        DestinationIp:
            - '45.155.205.233'
    sel_dom:
        DestinationHostname|contains:
            - 'evil-update.click'
    sel_hash:
        Hashes|contains:
            - '44d8...02f'
    condition: sel_ip or sel_dom or sel_hash
falsepositives:
    - Legitimate use of public services with overlapping indicators
level: high
```

Convert to your SIEM:

```bash
sigmac -t splunk rules/smokeloader_broker.yml > smokeloader.spl
sigmac -t es-qs rules/smokeloader_broker.yml > smokeloader.eql
```

---

## CLI

```
usage: analyzer.py [-h] --observation PATH [--intel PATH] [--json PATH]
                   [--rules-out DIR] [--actor-threshold N]
```

| Flag | Purpose |
|---|---|
| `--observation PATH` | Observation JSON (host + process + iocs) |
| `--intel PATH` | Local threat-intel JSON (same shape as MDR triage bot) |
| `--json PATH` | Write full report JSON for downstream tools |
| `--rules-out DIR` | Directory to write generated Sigma rule files into |
| `--actor-threshold N` | Minimum actor score to include in rule generation (default 50) |

---

## Architecture

```
analyzer.py        ── CLI orchestrator: enrich → map → correlate → emit
ioc_enricher.py    ── shared with mdr-triage-bot
mitre_mapper.py    ── ATT&CK corpus + heuristic mappers
ttp_correlator.py  ── threat-actor profiles + scoring
sigma_generator.py ── Sigma YAML emitter (stdlib-only YAML output)
samples/
  observation.json  ── one realistic incident fixture
  threat_intel.json ── small but populated IOC database
tests/
  test_analyzer.py  ── 10 unit tests, runs in <100ms
```

---

## Running the tests

```bash
python -m unittest discover tests
```

10 tests covering: ATT&CK mapper (process → technique, corpus size,
multi-IOC observation), TTP correlator (signature-full bonus, no-match,
profile count), Sigma generator (YAML structure, generic-fallback when no
actors), and end-to-end on the sample observation.

---

## License

MIT — see [LICENSE](./LICENSE).
