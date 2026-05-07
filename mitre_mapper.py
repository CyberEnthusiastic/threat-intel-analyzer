"""
MITRE ATT&CK mapping.

Maps IOCs and observed behavior to MITRE ATT&CK tactics, techniques, and
sub-techniques. The mapping is rule-based — heuristics over indicator
type + observed context — and ships with a baseline corpus of 30+
techniques covering the most common SOC observations.

Output is suitable for direct ingestion by Sigma / Splunk / Elastic
detection pipelines.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ─── ATT&CK reference data (snapshot) ───────────────────────────────────────
# Tactic IDs are TA0001..TA0040. We carry the human-readable label.
TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

# (technique_id, name, tactic) — the corpus we map TO.
TECHNIQUES = [
    ("T1059.001", "PowerShell",                          "TA0002"),
    ("T1059.003", "Windows Command Shell",               "TA0002"),
    ("T1059.005", "Visual Basic",                        "TA0002"),
    ("T1059.007", "JavaScript",                          "TA0002"),
    ("T1071.001", "Web Protocols (HTTP/S)",              "TA0011"),
    ("T1071.004", "DNS",                                 "TA0011"),
    ("T1090.003", "Multi-hop Proxy (Tor)",               "TA0011"),
    ("T1105",     "Ingress Tool Transfer",               "TA0011"),
    ("T1078",     "Valid Accounts",                      "TA0001"),
    ("T1078.004", "Cloud Accounts",                      "TA0001"),
    ("T1110.003", "Password Spraying",                   "TA0006"),
    ("T1003.001", "LSASS Memory",                        "TA0006"),
    ("T1003.003", "NTDS",                                "TA0006"),
    ("T1486",     "Data Encrypted for Impact",           "TA0040"),
    ("T1490",     "Inhibit System Recovery",             "TA0040"),
    ("T1041",     "Exfil over C2 Channel",               "TA0010"),
    ("T1567.002", "Exfil to Cloud Storage",              "TA0010"),
    ("T1537",     "Transfer Data to Cloud Account",      "TA0010"),
    ("T1027",     "Obfuscated Files or Information",     "TA0005"),
    ("T1140",     "Deobfuscate/Decode Files",            "TA0005"),
    ("T1112",     "Modify Registry",                     "TA0005"),
    ("T1562.001", "Disable or Modify Tools",             "TA0005"),
    ("T1547.001", "Registry Run Keys",                   "TA0003"),
    ("T1136.001", "Local Account Created",               "TA0003"),
    ("T1543.003", "Windows Service",                     "TA0003"),
    ("T1068",     "Exploitation for Priv Esc",           "TA0004"),
    ("T1134.001", "Token Impersonation",                 "TA0004"),
    ("T1018",     "Remote System Discovery",             "TA0007"),
    ("T1046",     "Network Service Scanning",            "TA0007"),
    ("T1021.001", "Remote Desktop Protocol",             "TA0008"),
    ("T1021.006", "Windows Remote Management",           "TA0008"),
    ("T1621",     "MFA Request Generation (push bombing)", "TA0006"),
]


# ─── Heuristic mappers ──────────────────────────────────────────────────────
@dataclass
class Mapping:
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: int = 70  # 0-100
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


_TECH_LOOKUP = {tid: (name, tac) for tid, name, tac in TECHNIQUES}


def _make(tid: str, evidence: str, confidence: int = 80) -> Mapping:
    name, tac = _TECH_LOOKUP[tid]
    return Mapping(
        technique_id=tid, technique_name=name,
        tactic_id=tac, tactic_name=TACTICS[tac],
        confidence=confidence, evidence=[evidence],
    )


_PROCESS_TECHNIQUES = {
    "powershell.exe": "T1059.001",
    "pwsh.exe":       "T1059.001",
    "cmd.exe":        "T1059.003",
    "wscript.exe":    "T1059.005",
    "cscript.exe":    "T1059.005",
    "mshta.exe":      "T1059.005",
    "node.exe":       "T1059.007",
    "rundll32.exe":   "T1140",
    "regsvr32.exe":   "T1140",
    "lsass.exe":      "T1003.001",  # observation context
}

_TAG_TO_TECH = {
    "ransomware":   ["T1486", "T1490"],
    "smokeloader":  ["T1105", "T1027"],
    "loader":       ["T1105"],
    "c2":           ["T1071.001", "T1090.003"],
    "cobalt-strike":["T1071.001", "T1078"],
    "tor-exit":     ["T1090.003"],
    "fakeupdate":   ["T1071.001", "T1027"],
    "malware-distribution": ["T1071.001"],
    "ldap-bind":    ["T1110.003"],
}


def map_ioc(ioc: dict) -> list[Mapping]:
    """Map a single enriched IOC dict to one or more ATT&CK techniques."""
    mappings: list[Mapping] = []
    tags = ioc.get("tags") or []
    seen: set[str] = set()
    for tag in tags:
        for tid in _TAG_TO_TECH.get(tag, []):
            if tid in seen or tid not in _TECH_LOOKUP:
                continue
            mappings.append(_make(tid, evidence=f"tag:{tag}", confidence=85))
            seen.add(tid)
    return mappings


def map_process(process_name: str) -> Optional[Mapping]:
    if not process_name:
        return None
    name = process_name.lower().split("\\")[-1].split("/")[-1]
    tid = _PROCESS_TECHNIQUES.get(name)
    if tid:
        return _make(tid, evidence=f"process:{name}", confidence=75)
    return None


_DNS_RE = re.compile(r"\.")
_HTTP_RE = re.compile(r"^https?://", re.I)


def map_network(ioc: dict) -> Optional[Mapping]:
    kind = ioc.get("kind") or ""
    val = ioc.get("ioc") or ""
    if kind == "domain":
        return _make("T1071.001", evidence=f"domain:{val}", confidence=70)
    if kind == "url" or _HTTP_RE.match(val):
        return _make("T1071.001", evidence=f"url:{val}", confidence=80)
    if kind in ("ipv4", "ipv6"):
        # If the IOC tag suggests Tor, prefer T1090.003 — handled by map_ioc.
        return _make("T1071.001", evidence=f"ip:{val}", confidence=60)
    return None


def map_observation(observation: dict) -> list[Mapping]:
    """
    `observation` shape:
        { "iocs": [{...}, ...], "process": "powershell.exe", ... }
    Returns deduped Mapping list ranked by confidence desc.
    """
    out: list[Mapping] = []
    seen: set[str] = set()

    for ioc in observation.get("iocs") or []:
        for m in map_ioc(ioc):
            key = m.technique_id + ":" + (m.evidence[0] if m.evidence else "")
            if key in seen:
                continue
            seen.add(key)
            out.append(m)
        nm = map_network(ioc)
        if nm:
            key = nm.technique_id + ":" + (nm.evidence[0] if nm.evidence else "")
            if key not in seen:
                seen.add(key)
                out.append(nm)

    pm = map_process(observation.get("process") or "")
    if pm:
        key = pm.technique_id + ":" + (pm.evidence[0] if pm.evidence else "")
        if key not in seen:
            seen.add(key)
            out.append(pm)

    # Deduplicate by technique_id, keeping highest-confidence and merging evidence.
    by_id: dict[str, Mapping] = {}
    for m in out:
        cur = by_id.get(m.technique_id)
        if cur is None or m.confidence > cur.confidence:
            by_id[m.technique_id] = Mapping(
                technique_id=m.technique_id, technique_name=m.technique_name,
                tactic_id=m.tactic_id, tactic_name=m.tactic_name,
                confidence=m.confidence,
                evidence=list(set(((cur.evidence if cur else []) + m.evidence))),
            )
        else:
            cur.evidence = sorted(set(cur.evidence + m.evidence))

    return sorted(by_id.values(), key=lambda x: -x.confidence)
