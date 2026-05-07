"""
Generate Sigma detection rules from observed IOCs + ATT&CK mappings.

Sigma is YAML — we emit it without a YAML library by hand-formatting
(stdlib-only constraint). The output is valid for sigmac → splunk /
elastic / sentinel converters.

Reference: https://github.com/SigmaHQ/sigma-specification
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Iterable, Optional


def _slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    return s[:60] or "rule"


def _yaml_str(s: str) -> str:
    """YAML-quote a string. Single quotes + escape inner singles."""
    return "'" + str(s).replace("'", "''") + "'"


def _yaml_list(items: Iterable[str], indent: str = "    ") -> str:
    return "\n".join(f"{indent}- {_yaml_str(i)}" for i in items)


def make_rule(
    title: str,
    iocs: list[dict],
    techniques: list[str],
    actor: Optional[str] = None,
    description: Optional[str] = None,
    level: str = "high",
) -> str:
    """Render a single Sigma rule covering the given IOCs."""
    rid = hashlib.sha1((title + str(time.time_ns())).encode()).hexdigest()[:16]

    ips: list[str] = []
    domains: list[str] = []
    hashes: list[str] = []
    urls: list[str] = []
    for i in iocs:
        kind = i.get("kind") or i.get("type") or ""
        v = i.get("ioc") or i.get("value") or ""
        if not v:
            continue
        if kind in ("ipv4", "ipv6"):
            ips.append(v)
        elif kind == "domain":
            domains.append(v)
        elif kind == "url":
            urls.append(v)
        elif kind in ("md5", "sha1", "sha256"):
            hashes.append(v)

    desc = description or f"Auto-generated from threat intel matching {actor or 'observed activity'}."
    lines = [
        f"title: {title}",
        f"id: {rid}",
        f"description: {desc}",
        "status: experimental",
        f"author: threat-intel-analyzer",
        f"date: {time.strftime('%Y/%m/%d')}",
    ]
    if techniques:
        lines.append("tags:")
        for t in techniques:
            lines.append(f"    - attack.{t.lower().replace('.', '.')}")
    if actor:
        lines.append(f"references:")
        lines.append(f"    - actor:{_slug(actor)}")

    lines.append("logsource:")
    lines.append("    category: network_connection")

    lines.append("detection:")
    cond_blocks = []
    if ips:
        lines.append("    sel_ip:")
        lines.append("        DestinationIp:")
        lines.append(_yaml_list(ips, indent="            "))
        cond_blocks.append("sel_ip")
    if domains:
        lines.append("    sel_dom:")
        lines.append("        DestinationHostname|contains:")
        lines.append(_yaml_list(domains, indent="            "))
        cond_blocks.append("sel_dom")
    if urls:
        lines.append("    sel_url:")
        lines.append("        Url|contains:")
        lines.append(_yaml_list(urls, indent="            "))
        cond_blocks.append("sel_url")
    if hashes:
        lines.append("    sel_hash:")
        lines.append("        Hashes|contains:")
        lines.append(_yaml_list(hashes, indent="            "))
        cond_blocks.append("sel_hash")

    if not cond_blocks:
        lines.append("    sel_dummy:")
        lines.append("        EventID: 1")
        cond_blocks.append("sel_dummy")

    lines.append(f"    condition: {' or '.join(cond_blocks)}")
    lines.append("falsepositives:")
    lines.append("    - Legitimate use of public services with overlapping indicators")
    lines.append(f"level: {level}")

    return "\n".join(lines) + "\n"


def make_rule_pack(actor_correlations: list[dict],
                   iocs: list[dict],
                   technique_ids: list[str]) -> list[tuple[str, str]]:
    """Yield (filename, sigma_yaml) for each correlated actor.

    If no actors match, emit one generic rule covering all IOCs.
    """
    out: list[tuple[str, str]] = []
    if not actor_correlations:
        title = "Generic threat-intel match"
        out.append((f"{_slug(title)}.yml",
                    make_rule(title, iocs, technique_ids, actor=None,
                              description="Generic detection from threat-intel-analyzer.",
                              level="medium")))
        return out

    for c in actor_correlations:
        actor = c.get("actor_name") or c.get("actor_id") or "actor"
        title = f"Activity matching {actor}"
        level = "high" if c.get("score", 0) >= 80 else "medium"
        out.append((f"{_slug(actor)}.yml",
                    make_rule(title, iocs, c.get("matched") or technique_ids,
                              actor=actor,
                              description=f"Auto-generated from {len(c.get('matched') or [])} of "
                                          f"{c.get('profile_size', 0)} signature techniques.",
                              level=level)))
    return out
