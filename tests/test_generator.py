"""Synthetic company determinism and the required security stories."""

from pathlib import Path

from security_investigator.generator import generate_company, manifest_json, write_company_files


def _by_key(items: list[dict], key: str) -> dict:
    return next(item for item in items if item["key"] == key)


def test_same_seed_produces_identical_rows_and_manifest() -> None:
    first = generate_company()
    second = generate_company()
    assert first.tables == second.tables
    assert manifest_json(first.manifest) == manifest_json(second.manifest)


def test_different_seed_changes_operational_logs() -> None:
    first = generate_company(seed=42)
    second = generate_company(seed=43)
    assert first.tables["logs"] != second.tables["logs"]
    assert [row[1] for row in first.tables["incidents"]] == [
        row[1] for row in second.tables["incidents"]
    ]


def test_required_stories_and_chronology() -> None:
    company = generate_company()
    incidents = {item["key"]: item for item in company.manifest["incidents"]}
    alerts = {item["key"]: item for item in company.manifest["alerts"]}

    sqli = incidents["billing_sqli_resolved"]
    assert sqli["status"] == "resolved"
    assert sqli["current_fix_verified"] is True
    assert sqli["cwe_id"] == "CWE-89"
    assert len(sqli["alert_ids"]) == 3

    assert incidents["user_idor_open"]["status"] == "open"
    assert incidents["user_idor_open"]["severity"] == "critical"
    assert len(incidents["user_idor_open"]["alert_ids"]) == 4

    assert incidents["billing_bac_resolved"]["resolved"] is True
    lookalike = alerts["billing_bac_lookalike"]
    assert lookalike["incident_id"] is None
    assert lookalike["status"] == "new"
    assert lookalike["family"] == "billing_bac_resolved"

    blocked = alerts["billing_sqli_blocked"]
    assert blocked["blocked_attempt"] is True
    assert blocked["incident_id"] is None
    assert blocked["noise"] is True

    assert alerts["auth_login_drill_fp"]["status"] == "closed_false_positive"
    assert alerts["auth_login_drill_fp"]["incident_id"] is None

    reopened = incidents["auth_regression_reopened"]
    assert reopened["reopened"] is True
    assert reopened["was_resolved"] is True
    assert reopened["resolved"] is False
    assert "reopened" in reopened["expected_status_at"].values()
    assert "resolved" in reopened["expected_status_at"].values()

    pending = incidents["file_misconfig_unverified"]
    assert pending["status"] == "mitigated"
    assert pending["verification_status"] == "pending"
    assert pending["current_fix_verified"] is False

    sparse = incidents["admin_integrity_sparse"]
    assert sparse["sparse_logs"] is True
    assert sparse["confirmed"] is True
    sparse_logs = [row for row in company.tables["alert_logs"] if row[0] in sparse["alert_ids"]]
    assert len(sparse_logs) == 1

    assert (
        company.manifest["prompt_injection_log_id"] in company.manifest["benign_suspicious_log_ids"]
    )
    assert company.manifest["statistics"]["http_success_ratio"] > 0.85
    assert company.manifest["counts"] == {
        "alerts": 250,
        "incidents": 30,
        "logs": 15_000,
        "services": 6,
    }


def test_files_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "security.db"
    manifest_path = tmp_path / "manifest.json"
    first = write_company_files(database_path, manifest_path)
    text = manifest_path.read_text(encoding="utf-8")
    second = write_company_files(tmp_path / "other.db", tmp_path / "other.json")
    assert text == manifest_json(first.manifest)
    assert text == manifest_json(second.manifest)
    assert "Do not pass this document to the runtime agent." in text
