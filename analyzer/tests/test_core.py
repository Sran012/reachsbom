from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reachsbom import osv, reachability, report, scoring, stage2
from reachsbom import cli
from reachsbom.models import (
    Advisory,
    Component,
    Finding,
    ProjectBuild,
    SymbolRef,
    SymbolResult,
)


class CvssTests(unittest.TestCase):
    def test_known_base_scores(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
            "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H": 5.9,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(osv.cvss3_base_score(vector), expected)

    def test_temporal_metrics_are_ignored(self):
        base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        with_temporal = base + "/E:H/RL:O/RC:C"
        self.assertEqual(osv.cvss3_base_score(base), 10.0)
        self.assertEqual(osv.cvss3_base_score(with_temporal), 10.0)

    def test_parse_returns_metrics(self):
        metrics = osv.parse_cvss3_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        )
        self.assertEqual(metrics["AV"], "N")
        self.assertEqual(metrics["S"], "C")
        self.assertEqual(metrics["UI"], "R")

    def test_invalid_vectors_raise(self):
        with self.assertRaises(ValueError):
            osv.cvss3_base_score("CVSS:3.1/AV:N/AC:L")
        with self.assertRaises(ValueError):
            osv.cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N")


class OsvTests(unittest.TestCase):
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    def component(self) -> Component:
        return Component(
            name="log4j-core",
            version="2.14.1",
            purl=self.purl,
            group="org.apache.logging.log4j",
        )

    def record_a(self) -> dict:
        return {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Log4Shell",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                }
            ],
            "database_specific": {"severity": "CRITICAL"},
            "affected": [
                {
                    "package": {
                        "name": "org.apache.logging.log4j:log4j-core",
                        "ecosystem": "Maven",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.4"},
                                {"fixed": "2.12.2"},
                                {"fixed": "2.15.0"},
                            ],
                        }
                    ],
                }
            ],
        }

    def record_b(self) -> dict:
        return {
            "id": "OSV-2021-1234",
            "aliases": ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
            "summary": "Duplicate advisory",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [
                {
                    "package": {
                        "name": "org.apache.logging.log4j:log4j-core",
                        "ecosystem": "Maven",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.3.1"}],
                        }
                    ],
                }
            ],
        }

    def test_merge_by_cve_alias(self):
        merged = osv.merge_records([self.record_a(), self.record_b()])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "CVE-2021-44228")
        self.assertIn("GHSA-jfh8-c2jp-5v3q", merged[0]["aliases"])
        self.assertIn("OSV-2021-1234", merged[0]["aliases"])

    def test_advisory_from_merged_record(self):
        advisories = osv.advisories_from_response(
            {"vulns": [self.record_a(), self.record_b()]},
            self.component(),
        )
        self.assertEqual(len(advisories), 1)
        advisory = advisories[0]
        self.assertEqual(advisory.advisory_id, "CVE-2021-44228")
        self.assertEqual(advisory.cvss, 10.0)
        self.assertEqual(advisory.severity, "CRITICAL")
        self.assertEqual(advisory.fixed_version, "2.15.0")
        self.assertIn("GHSA-jfh8-c2jp-5v3q", advisory.aliases)

    def test_severity_fallback_without_vector(self):
        record = {
            "id": "GHSA-test",
            "aliases": ["CVE-2022-0001"],
            "summary": "No vector",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {
                        "name": "org.example:lib",
                        "ecosystem": "Maven",
                        "purl": "pkg:maven/org.example/lib",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                        }
                    ],
                }
            ],
        }
        component = Component(
            name="lib",
            version="1.0.0",
            purl="pkg:maven/org.example/lib@1.0.0",
        )
        advisory = osv.advisories_from_response({"vulns": [record]}, component)[0]
        self.assertEqual(advisory.cvss, 8.0)
        self.assertEqual(advisory.fixed_version, "1.2.3")

    def test_v4_only_falls_back_to_severity(self):
        record = {
            "id": "GHSA-v4",
            "aliases": ["CVE-2025-0001"],
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                }
            ],
            "database_specific": {"severity": "MODERATE"},
        }
        advisory = osv.advisories_from_response({"vulns": [record]}, self.component())[0]
        self.assertEqual(advisory.cvss, 5.5)
        self.assertEqual(advisory.severity, "MODERATE")

    def test_query_cache(self):
        self_record = {"id": "GHSA-cache", "aliases": ["CVE-2024-0001"]}

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"vulns": [self_record]}

        class FakeSession:
            def __init__(self):
                self.calls = 0

            def post(self, *args, **kwargs):
                self.calls += 1
                return FakeResponse()

        session = FakeSession()
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "cache"
            first = osv.query_osv(self.purl, cache, session=session)
            second = osv.query_osv(self.purl, cache, session=session)
            self.assertEqual(first, second)
            self.assertEqual(session.calls, 1)
            files = list(cache.glob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(len(files[0].stem), 64)


class ScoringTests(unittest.TestCase):
    def advisory(self, advisory_id: str = "CVE-2021-44228", cvss: float = 10.0) -> Advisory:
        return Advisory(
            advisory_id=advisory_id,
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            component="log4j-core",
            cvss=cvss,
            fixed_version="2.15.0",
            aliases=["GHSA-jfh8-c2jp-5v3q"],
        )

    def test_weights(self):
        expected = {
            "Present": 0.2,
            "ClassPresent": 0.4,
            "PossiblyReachable": 0.6,
            "Reachable": 0.8,
            "Taint": 1.0,
        }
        self.assertEqual(scoring.WEIGHTS, expected)
        for status, weight in expected.items():
            self.assertEqual(scoring.weight_for(status), weight)
            self.assertEqual(scoring.risk_score(10.0, status), weight)

    def test_risk_formula(self):
        self.assertEqual(scoring.risk_score(9.8, "Reachable"), 0.784)
        self.assertEqual(scoring.risk_score(5.0, "Present"), 0.1)
        self.assertEqual(scoring.risk_score(0.0, "Taint"), 0.0)

    def test_build_finding_uses_strongest_result(self):
        advisory = self.advisory()
        results = [
            SymbolResult(
                advisory_id=advisory.advisory_id,
                class_name="org.example.A",
                method="<A: void a()>",
                status="ClassPresent",
                purl=advisory.purl,
            ),
            SymbolResult(
                advisory_id=advisory.advisory_id,
                class_name="org.example.B",
                method="<B: void b()>",
                status="Reachable",
                path=["<App: void main()>", "<B: void b()>"],
                purl=advisory.purl,
            ),
        ]
        finding = scoring.build_finding(advisory, results)
        self.assertEqual(finding.status, "Reachable")
        self.assertEqual(finding.symbol, "<B: void b()>")
        self.assertEqual(finding.path, ["<App: void main()>", "<B: void b()>"])
        self.assertEqual(finding.risk, 0.8)
        self.assertEqual(finding.advisory_ids, ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"])

    def test_findings_are_sorted_by_risk(self):
        low = self.advisory("CVE-2022-0001", cvss=9.0)
        high = self.advisory("CVE-2021-44228", cvss=10.0)
        findings = scoring.build_findings(
            [low, high],
            [
                SymbolResult(
                    advisory_id=high.advisory_id,
                    class_name="A",
                    status="Reachable",
                    purl=high.purl,
                ),
                SymbolResult(
                    advisory_id=low.advisory_id,
                    class_name="B",
                    status="Present",
                    purl=low.purl,
                ),
            ],
        )
        self.assertEqual(findings[0].advisory_id, high.advisory_id)
        self.assertEqual(findings[0].risk, 0.8)
        self.assertEqual(findings[1].risk, 0.18)


class Stage2Tests(unittest.TestCase):
    def test_runtime_index_and_component_fallback(self):
        purl = "pkg:maven/org.example/lib@1.0.0"
        component = Component("lib", "1.0.0", purl, "org.example")
        with tempfile.TemporaryDirectory() as temp:
            jar = Path(temp) / "lib-1.0.0.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("org/example/Lib.class", b"")
                archive.writestr("org/example/Other.class", b"")
                archive.writestr(
                    "META-INF/maven/org.example/lib/pom.properties",
                    "groupId=org.example\nartifactId=lib\nversion=1.0.0\n",
                )
            index = stage2.RuntimeIndex.from_jars([jar], [component])
            self.assertTrue(index.has_class("org.example.Lib"))
            self.assertEqual(index.component_for_class("org.example.Lib"), purl)
            self.assertEqual(index.classes_for_component(purl), {"org.example.Lib", "org.example.Other"})

            results = [
                SymbolResult(
                    advisory_id="CVE-2020-0001",
                    class_name="org.example.Other",
                    status="Reachable",
                    path=["<org.example.Other: void run()>"],
                    class_present=True,
                    purl=purl,
                ),
                SymbolResult(
                    advisory_id="CVE-2020-0001",
                    class_name="org.example.Lib",
                    status="ClassPresent",
                    class_present=True,
                    purl=purl,
                ),
            ]
            stage2.apply_component_fallback(results, index)
            self.assertEqual(results[1].status, "PossiblyReachable")
            self.assertTrue(results[1].fallback)


class ReachabilityTests(unittest.TestCase):
    def build(self, root: Path) -> ProjectBuild:
        classes = root / "target" / "classes"
        sbom_jars = root / "target" / "sbom-jars"
        runtime_jars = root / "target" / "runtime-jars"
        classes.mkdir(parents=True)
        sbom_jars.mkdir(parents=True)
        runtime_jars.mkdir(parents=True)
        return ProjectBuild(
            project_dir=root,
            group_id="com.example",
            artifact_id="demo",
            version="1.0",
            main_class="com.example.App",
            classes_dir=classes,
            sbom_jars_dir=sbom_jars,
            runtime_jars_dir=runtime_jars,
        )

    def test_static_symbols_attach(self):
        static = reachability.load_static_advisories(ROOT / "data" / "advisories.json")
        advisory = Advisory(
            advisory_id="CVE-2021-44228",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            component="log4j-core",
            cvss=10.0,
        )
        reachability.attach_static_symbols([advisory], static)
        self.assertEqual(len(advisory.symbols), 2)
        classes = {symbol.class_name for symbol in advisory.symbols}
        self.assertIn("org.apache.logging.log4j.core.net.JndiManager", classes)

    def test_request_matches_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            build = self.build(Path(temp))
            source = Advisory(
                advisory_id="CVE-2021-44228",
                purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                component="log4j-core",
                cvss=10.0,
                symbols=[
                    SymbolRef(
                        "CVE-2021-44228",
                        "org.apache.logging.log4j.core.net.JndiManager",
                        ("<org.apache.logging.log4j.core.net.JndiManager: java.lang.Object lookup(java.lang.String)>",),
                    )
                ],
            )
            request = reachability.build_request(
                build,
                [source],
                None,
                algorithm="rta",
                use_edge_rules=True,
                edge_rules_path=ROOT / "data" / "edge_rules.json",
                repo_root=ROOT,
            )
            self.assertEqual(request["algorithm"], "rta")
            self.assertTrue(request["use_edge_rules"])
            app = request["apps"][0]
            self.assertEqual(app["main_class"], "com.example.App")
            self.assertEqual(app["app_dirs"], [str(build.classes_dir.resolve())])
            self.assertEqual(app["symbols"][0]["key"], "CVE-2021-44228")
            self.assertEqual(app["edge_rules"][0]["type"], "method_map")
            self.assertTrue(app["reflection"])

    def test_absent_symbol_skips_java(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build = self.build(root)
            advisory = Advisory(
                advisory_id="CVE-2022-0001",
                purl="pkg:maven/org.example/lib@1.0.0",
                component="lib",
                cvss=5.0,
                symbols=[
                    SymbolRef(
                        "CVE-2022-0001",
                        "org.example.Missing",
                        ("<org.example.Missing: void run()>",),
                    )
                ],
            )
            index = stage2.RuntimeIndex.from_jars([], [])
            results = reachability.analyze(
                build,
                [advisory],
                index,
                root / "out",
                edge_rules_path=ROOT / "data" / "edge_rules.json",
                repo_root=ROOT,
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, "Present")
            self.assertEqual(results[0].source, "stage2")
            self.assertFalse(results[0].class_present)
            self.assertFalse((root / "out" / "response.json").exists())

    def test_parse_analyzer_response(self):
        signature = "<org.example.Lib: void run()>"
        response = {
            "apps": {
                "demo-1.0": {
                    "symbols": {
                        signature: {
                            "class_present": True,
                            "method_present": True,
                            "status": "Reachable",
                            "path": ["<org.example.App: void main()>", signature],
                        }
                    },
                    "dynamic": False,
                }
            }
        }
        parsed = reachability.parse_analyzer_response(response)
        self.assertEqual(parsed[signature]["status"], "Reachable")
        self.assertEqual(parsed[signature]["path"][1], signature)


class ReportTests(unittest.TestCase):
    def test_outputs_include_required_fields(self):
        finding = Finding(
            component="log4j-core",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            advisory_ids=["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
            cvss=10.0,
            fixed_version="2.15.0",
            status="Reachable",
            path=["<App: void main()>", "<JndiManager: Object lookup(String)>"],
            risk=0.8,
            symbol="<JndiManager: Object lookup(String)>",
        )
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            report.write_outputs(out, [finding], "com.example:demo:1.0", 3, 1)
            records = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(records), 1)
            for key in (
                "component",
                "purl",
                "advisory_ids",
                "cvss",
                "fixed_version",
                "status",
                "path",
                "risk",
                "symbol",
            ):
                self.assertIn(key, records[0])
            text = (out / "report.txt").read_text(encoding="utf-8")
            self.assertIn("CVE-2021-44228", text)
            self.assertIn("Reachable", text)
            self.assertIn("2.15.0", text)


class CliTests(unittest.TestCase):
    def test_build_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code = cli.main(
                [
                    "scan",
                    str(root / "missing-project"),
                    "--out",
                    str(root / "out"),
                ]
            )
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
