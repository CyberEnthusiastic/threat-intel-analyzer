"""
TTP correlator — given a set of mapped MITRE techniques, score the
likelihood that the observed activity belongs to a known threat actor /
ransomware family / APT campaign.

The correlation table is a small, hand-curated subset that reflects what
SOC analysts care about day-to-day. It is NOT a research-grade threat
graph; it is a triage aid that says "this looks 80% like Lazarus" so the
Tier-2 analyst opens the right runbook first.

Match score = (techniques in profile that we observed) / (techniques in profile)
              with a small bonus when ALL of the actor's "signature" techniques fire.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


# Each entry:
#   id           short code
#   name         display name
#   category     ransomware|apt|loader|broker|insider
#   techniques   set of MITRE technique IDs canonical to this actor
#   signature    optional subset whose presence boosts confidence
ACTOR_PROFILES = [
    {
        "id": "lockbit_3",
        "name": "LockBit 3.0 ransomware",
        "category": "ransomware",
        "techniques": {"T1486", "T1490", "T1059.001", "T1027", "T1003.001",
                       "T1543.003", "T1112", "T1562.001", "T1071.001"},
        "signature": {"T1486", "T1490", "T1562.001"},
    },
    {
        "id": "blackcat",
        "name": "BlackCat / ALPHV",
        "category": "ransomware",
        "techniques": {"T1486", "T1490", "T1059.001", "T1078",
                       "T1003.001", "T1547.001", "T1071.001", "T1078.004"},
        "signature": {"T1486", "T1078.004"},
    },
    {
        "id": "fin7",
        "name": "FIN7 / Carbon Spider",
        "category": "apt",
        "techniques": {"T1059.005", "T1059.001", "T1027", "T1547.001",
                       "T1078", "T1071.001", "T1140"},
        "signature": {"T1059.005", "T1078"},
    },
    {
        "id": "lazarus",
        "name": "Lazarus / APT38",
        "category": "apt",
        "techniques": {"T1059.001", "T1027", "T1071.001", "T1078",
                       "T1041", "T1567.002", "T1547.001"},
        "signature": {"T1567.002", "T1041"},
    },
    {
        "id": "smokeloader",
        "name": "SmokeLoader broker",
        "category": "loader",
        "techniques": {"T1105", "T1027", "T1140", "T1071.001",
                       "T1547.001", "T1112"},
        "signature": {"T1105", "T1027"},
    },
    {
        "id": "scattered_spider",
        "name": "Scattered Spider / 0ktapus",
        "category": "apt",
        "techniques": {"T1078", "T1078.004", "T1621", "T1110.003",
                       "T1071.001", "T1003.001"},
        "signature": {"T1621", "T1078.004"},
    },
    {
        "id": "mfa_fatigue",
        "name": "MFA fatigue / push-bombing kit",
        "category": "broker",
        "techniques": {"T1621", "T1110.003", "T1078"},
        "signature": {"T1621"},
    },
    {
        "id": "tor_exfil",
        "name": "Tor-based exfiltration",
        "category": "broker",
        "techniques": {"T1090.003", "T1071.001", "T1041"},
        "signature": {"T1090.003"},
    },
]


@dataclass
class Correlation:
    actor_id: str
    actor_name: str
    category: str
    score: int  # 0-100
    matched: list[str]
    profile_size: int
    signature_full: bool

    def as_dict(self) -> dict:
        return self.__dict__


def correlate(observed_techniques: Iterable[str]) -> list[Correlation]:
    obs = set(observed_techniques)
    out: list[Correlation] = []
    for profile in ACTOR_PROFILES:
        techs = profile["techniques"]
        sig = profile["signature"]
        matched = sorted(obs & techs)
        if not matched:
            continue
        ratio = len(matched) / max(1, len(techs))
        signature_full = bool(sig and sig.issubset(obs))
        score = int(round(ratio * 80))
        if signature_full:
            score = min(100, score + 20)
        out.append(Correlation(
            actor_id=profile["id"],
            actor_name=profile["name"],
            category=profile["category"],
            score=score,
            matched=matched,
            profile_size=len(techs),
            signature_full=signature_full,
        ))
    return sorted(out, key=lambda x: -x.score)
