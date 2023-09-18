from typing import Any
import io
import json
import sys
import pytest
import shutil
import os


sys.path.append("..")
import filescan_sandbox_result
from assemblyline_v4_service.common.result import (
    Result,
    ResultSection,
    Classification,
    BODY_FORMAT,
)


def util_load_json(path: str) -> Any:
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


class TestFilescanSandboxResult:
    @classmethod
    def setup_class(cls):
        # copy yml
        path = os.getcwd()
        filename = "service_manifest.yml"
        parent_dir = os.path.abspath(os.path.join(path, os.pardir))
        origin_path = f"{parent_dir}/{filename}"
        target_path = f"{parent_dir}/tests/{filename}"
        if not os.path.exists(target_path):
            shutil.copyfile(origin_path, target_path)

    @classmethod
    def teardown_class(cls):
        # delete yml
        path = os.getcwd()
        filename = "service_manifest.yml"
        parent_dir = os.path.abspath(os.path.join(path, os.pardir))
        target_path = f"{parent_dir}/tests/{filename}"
        if os.path.exists(target_path):
            os.remove(target_path)

    @staticmethod
    def test_parse_compact_result_bad():
        raw_response = (
            (util_load_json("badfile.json"))
            .get("reports", {})
            .get("93a90ffb-1aac-43f6-abdd-c579d6ae14df", {})
        )
        compact_result = filescan_sandbox_result.parse_compact_result(
            raw_response,
            "93a90ffb-1aac-43f6-abdd-c579d6ae14df",
            "64d1fb9c2a1db2a88ac17017",
        )
        target = {
            "Verdict": "MALICIOUS",
            "Name": "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc",
            "File Magic": "application/x-msdownload",
            "SHA-256": "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc",
            "Report ID": "93a90ffb-1aac-43f6-abdd-c579d6ae14df",
            "Submission ID": "64d1fb9c2a1db2a88ac17017",
            "Submission Date": "08/08/2023, 08:23:57",
            "Tags": ["peexe", "html", "emotet", "pup", "packed"],
            "MITRE Techniques": ["Defense Evasion: Software Packing"],
        }
        assert target == compact_result

    @staticmethod
    def test_parse_compact_result_informational():
        raw_response = (
            (util_load_json("informational.json"))
            .get("reports", {})
            .get("21815d5f-3653-466e-a421-187423ca7b93", {})
        )
        compact_result = filescan_sandbox_result.parse_compact_result(
            raw_response,
            "21815d5f-3653-466e-a421-187423ca7b93",
            "64de1abb9489ac1ead366732",
        )
        target = {
            "Verdict": "INFORMATIONAL",
            "Name": "test.jpg",
            "File Magic": "image/jpeg",
            "SHA-256": "02595a43f63a1ed021c2d6ea1fd7086565caa1088ca06f46df3bc2f56308f999",
            "Report ID": "21815d5f-3653-466e-a421-187423ca7b93",
            "Submission ID": "64de1abb9489ac1ead366732",
            "Submission Date": "08/17/2023, 13:03:57",
            "Tags": ["jpg"],
            "MITRE Techniques": [],
        }
        assert target == compact_result

    @staticmethod
    def test_parse_compact_result_badfile2():
        raw_response = (
            (util_load_json("badfile2.json"))
            .get("reports", {})
            .get("d389e943-dc72-4070-aade-1d11f0457ea3", {})
        )
        compact_result = filescan_sandbox_result.parse_compact_result(
            raw_response,
            "d389e943-dc72-4070-aade-1d11f0457ea3",
            "64de19f4a29d57e20384dac6",
        )
        target = {
            "Verdict": "LIKELY_MALICIOUS",
            "Name": "aa79391c7db478fbb969875da39ce09e3e8124b869acc3178f5b6a3b4e10d5ce.bin",
            "File Magic": "application/x-msdownload",
            "SHA-256": "aa79391c7db478fbb969875da39ce09e3e8124b869acc3178f5b6a3b4e10d5ce",
            "Report ID": "d389e943-dc72-4070-aade-1d11f0457ea3",
            "Submission ID": "64de19f4a29d57e20384dac6",
            "Submission Date": "08/17/2023, 13:00:39",
            "Tags": [
                "peexe",
                "html",
                "vbs",
                "evasive",
                "keylogger",
                "cmd",
                "dllhost",
                "fingerprint",
                "greyware",
                "overlay",
                "packed",
                "shell32",
                "expand",
                "explorer",
                "lolbin",
                "tracker",
                "crypto",
            ],
            "MITRE Techniques": [
                "Discovery: Query Registry, System Information Discovery, System Owner/User Discovery, Query Registry, File and Directory Discovery",
                "Defense Evasion: Process Injection, Software Packing, Software Packing, Access Token Manipulation, Process Injection, Software Packing, System Checks, Windows File and Directory Permissions Modification, Obfuscated Files or Information, Obfuscated Files or Information, Virtualization/Sandbox Evasion, System Checks, Process Hollowing, Obfuscated Files or Information, Trusted Developer Utilities Proxy Execution, Indirect Command Execution, Rundll32, NTFS File Attributes",
                "Collection: Keylogging, Screen Capture",
                ": Encrypted Channel, Software Discovery, Security Software Discovery, Component Object Model Hijacking",
                "Execution: Windows Command Shell, Windows Command Shell, Windows Command Shell",
            ],
        }
        assert target == compact_result

    @staticmethod
    def test_parse_compact_result_empty():
        raw_response = {}
        compact_result = filescan_sandbox_result.parse_compact_result(
            raw_response,
            "93a90ffb-1aac-43f6-abdd-c579d6ae14df",
            "64d1fb9c2a1db2a88ac17017",
        )
        target = {
            "Verdict": "UNKNOWN",
            "Name": None,
            "File Magic": None,
            "SHA-256": None,
            "Report ID": "93a90ffb-1aac-43f6-abdd-c579d6ae14df",
            "Submission ID": "64d1fb9c2a1db2a88ac17017",
            "Submission Date": None,
            "Tags": [],
            "MITRE Techniques": [],
        }
        assert target == compact_result

    @staticmethod
    def test_process_allSignalGroups():
        raw_response = (
            (util_load_json("badfile.json"))
            .get("reports", {})
            .get("93a90ffb-1aac-43f6-abdd-c579d6ae14df", {})
            .get("allSignalGroups")
        )

        rs = ResultSection("Test", body_format=BODY_FORMAT.TEXT, body="test")

        compact_result = filescan_sandbox_result.process_allSignalGroups(
            rs, raw_response
        )

        tags = {"file.rule.yara": ["PUP_InstallRex_AntiFWb"]}
        assert rs.tags == tags

    @staticmethod
    def test_process_iocs():
        raw_response = (
            (util_load_json("badfile.json"))
            .get("reports", {})
            .get("93a90ffb-1aac-43f6-abdd-c579d6ae14df", {})
            .get("iocs")
        )

        rs = ResultSection("Test", body_format=BODY_FORMAT.TEXT, body="test")

        compact_result = filescan_sandbox_result.process_iocs(rs, raw_response)
        tags = {
            "network.email.address": ["ActivationDepartment@FedRetireSoftware.com"],
            "network.static.uri": [
                "https://FedRetireSoftware.com/",
                "http://www.FedRetireSoftware.com",
                "http://FedRetireSoftware.com",
            ],
            "network.static.ip": ["209.182.199.110"],
            "network.static.domain": ["FedRetireSoftware.com"],
            "network.dynamic.domain": ["FedRetireSoftware.com"],
        }
        assert rs.tags == tags

    @staticmethod
    def test_process_allOsintTags():
        raw_response = (
            (util_load_json("badfile.json"))
            .get("reports", {})
            .get("93a90ffb-1aac-43f6-abdd-c579d6ae14df", {})
            .get("allOsintTags")
        )

        rs = ResultSection("Test", body_format=BODY_FORMAT.TEXT, body="test")

        compact_result = filescan_sandbox_result.process_allOsintTags(rs, raw_response)
        tags = {"av.virus_name": ["emotet", "geodo"]}
        assert rs.tags == tags

    @staticmethod
    def test_process_resources():
        raw_response = (
            (util_load_json("badfile.json"))
            .get("reports", {})
            .get("93a90ffb-1aac-43f6-abdd-c579d6ae14df", {})
            .get("resources")
        )

        rs = ResultSection("Test", body_format=BODY_FORMAT.TEXT, body="test")

        compact_result = filescan_sandbox_result.process_resources(rs, raw_response)
        tags = {
            "av.virus_name": ["Trojan/Riskware!my0NYEEN"],
            "attribution.family": ["riskware"],
            "attribution.category": ["trojan", "agent"],
            "file.pe.imports.imphash": ["05ea7b0d93fd49dca73c49b148424e88"],
            "file.pe.resources.language": ["NEUTRAL"],
            "file.pe.rich_header.hash": ["0xd07c1cfb"],
            "file.pe.versions.filename": ["TSULoader.exe"],
            "file.pe.imports.suspicious": ["kernel32.dll", "user32.dll"],
        }
        assert rs.tags == tags
