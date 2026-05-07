"""Smoke + correctness tests. Run: python -m unittest discover tests"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer import analyze  # noqa: E402
from mitre_mapper import (TACTICS, TECHNIQUES, map_observation, map_process)  # noqa: E402
from sigma_generator import make_rule, make_rule_pack  # noqa: E402
from ttp_correlator import ACTOR_PROFILES, correlate  # noqa: E402


class TestMitreMapper(unittest.TestCase):
    def test_powershell_maps_to_T1059_001(self):
        m = map_process("powershell.exe")
        self.assertIsNotNone(m)
        self.assertEqual(m.technique_id, "T1059.001")
        self.assertEqual(m.tactic_id, "TA0002")

    def test_unknown_process_returns_none(self):
        self.assertIsNone(map_process("cool_program.exe"))

    def test_corpus_has_30_plus(self):
        self.assertGreaterEqual(len(TECHNIQUES), 30)

    def test_obs_yields_multi_techniques(self):
        obs = {
            "process": "powershell.exe",
            "iocs": [
                {"ioc": "45.155.205.233", "kind": "ipv4", "tags": ["c2", "cobalt-strike"]},
                {"ioc": "evil-update.click", "kind": "domain", "tags": ["fakeupdate"]},
            ],
        }
        ms = map_observation(obs)
        self.assertGreaterEqual(len(ms), 2)


class TestTtpCorrelator(unittest.TestCase):
    def test_lockbit_signature_full(self):
        techs = ["T1486", "T1490", "T1562.001", "T1059.001", "T1027"]
        cs = correlate(techs)
        top = cs[0]
        self.assertEqual(top.actor_id, "lockbit_3")
        self.assertTrue(top.signature_full)
        self.assertGreaterEqual(top.score, 60)

    def test_no_match_when_unrelated(self):
        cs = correlate(["T9999"])
        self.assertEqual(cs, [])

    def test_corpus_size(self):
        self.assertGreaterEqual(len(ACTOR_PROFILES), 6)


class TestSigmaGenerator(unittest.TestCase):
    def test_basic_rule_yaml(self):
        y = make_rule(
            "Test rule",
            iocs=[{"ioc": "1.2.3.4", "kind": "ipv4"},
                  {"ioc": "evil.com", "kind": "domain"}],
            techniques=["T1071.001"],
            actor="LockBit 3.0 ransomware",
        )
        self.assertIn("title: Test rule", y)
        self.assertIn("DestinationIp:", y)
        self.assertIn("DestinationHostname|contains:", y)
        self.assertIn("attack.t1071.001", y)
        self.assertIn("level:", y)

    def test_pack_generic_when_no_actors(self):
        rules = make_rule_pack([], [{"ioc": "1.2.3.4", "kind": "ipv4"}], ["T1071.001"])
        self.assertEqual(len(rules), 1)
        self.assertIn(".yml", rules[0][0])


class TestEndToEnd(unittest.TestCase):
    def test_e2e_runs(self):
        report = analyze(
            os.path.join(ROOT, "samples", "observation.json"),
            os.path.join(ROOT, "samples", "threat_intel.json"),
        )
        self.assertGreater(len(report["enriched_iocs"]), 4)
        self.assertGreater(len(report["techniques"]), 3)
        self.assertGreater(len(report["actors"]), 0)
        # PowerShell + ransomware tags + tor + c2 should fire LockBit/SmokeLoader.
        actor_ids = [a["actor_id"] for a in report["actors"]]
        self.assertTrue(any(x in actor_ids for x in ("smokeloader", "lockbit_3", "blackcat")))


if __name__ == "__main__":
    unittest.main()
