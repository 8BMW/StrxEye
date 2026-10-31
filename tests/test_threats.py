from strxeye.analytics import threats


def obs(kind, value, entity="198.51.100.7", type_="ip", source="x", confidence=1.0):
    return {"kind": kind, "value": value, "entity_type": type_, "entity_value": entity,
            "entity_id": 1, "source": source, "confidence": confidence,
            "collected_at": "2026-10-31T00:00:00+00:00", "evidence_id": "e"}


def test_threat_rules_and_ordering():
    rows = threats([
        obs("scan.possible_vulnerability", "CVE-2023-48795", source="internetdb"),
        obs("threat.listed", {"feed": "abuse.ch Feodo Tracker", "severity": "high",
                              "malware": "Emotet"}, source="threatfeeds"),
        obs("threat.listed", {"feed": "Tor exit nodes", "severity": "info"}),
        obs("vt.analysis_stats", {"malicious": 2, "harmless": 60, "undetected": 8},
            entity="bad.example", type_="domain"),
        obs("vt.analysis_stats", {"malicious": 0, "harmless": 70}, entity="ok.example",
            type_="domain"),
        obs("otx.pulse_count", 12, entity="popular.example", type_="domain"),
        obs("otx.allowlisted", ["Whitelisted domain"], entity="popular.example", type_="domain"),
        obs("otx.pulse_count", 0, entity="quiet.example", type_="domain"),
        # Same fact from a second run is reported once.
        obs("scan.possible_vulnerability", "CVE-2023-48795", source="internetdb"),
    ])
    summary = [(r["severity"], r["entity"], r["summary"]) for r in rows]
    assert summary[0] == ("high", "198.51.100.7", "abuse.ch Feodo Tracker (Emotet)")
    assert ("medium", "bad.example", "2/70 VirusTotal engines flag it as malicious") in summary
    assert any(s[1] == "popular.example" and s[0] == "info" and "allow-lists" in s[2]
               for s in summary)
    assert not any(s[1] in ("ok.example", "quiet.example") for s in summary)
    cve_rows = [s for s in summary if "CVE" in s[2]]
    assert len(cve_rows) == 1 and cve_rows[0][2].startswith("1 possible CVE(s)")
    assert [s[0] for s in summary] == sorted((s[0] for s in summary),
                                             key=["high", "medium", "low", "info"].index)


def test_many_cves_collapse_to_one_row():
    rows = threats([obs("scan.possible_vulnerability", f"CVE-2015-{n:04d}") for n in range(40)])
    assert len(rows) == 1
    assert rows[0]["summary"].startswith("40 possible CVE(s)")
    assert rows[0]["summary"].endswith("and 35 more")
