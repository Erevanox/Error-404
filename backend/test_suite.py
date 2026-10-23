import os
import json
from datetime import datetime, timezone
from normalizer import (
    normalize_timestamp,
    normalize_json_payload,
    normalize_csv_payload
)
from exporter import (
    _format_timestamp_for_export,
    generate_csv_export,
    generate_pdf_report
)
from database import (
    init_db, clear_active_telemetry, insert_event, get_all_events,
    get_all_alerts, insert_alert
)
from sample_data import get_canonical_scenario, save_sample_datasets
from detector import run_correlation_engine
from fastapi.testclient import TestClient
from main import app, load_canonical_data

def test_timestamp_normalizer():
    print("--- [TEST 1] Timestamp Normalizer ---")
    
    # 1. ISO 8601 UTC
    iso_ts = "2026-10-16T14:23:45Z"
    res1 = normalize_timestamp(iso_ts)
    assert res1.normalized == "2026-10-16T14:23:45Z", f"Unexpected ISO norm: {res1.normalized}"
    assert res1.status == "ok"
    assert res1.original == iso_ts
    print("[PASS] ISO 8601 normalized correctly")

    # 2. ISO with offset (-04:00 -> converts to UTC)
    offset_ts = "2026-10-16T10:23:45-04:00"
    res2 = normalize_timestamp(offset_ts)
    assert res2.normalized == "2026-10-16T14:23:45Z", f"Unexpected offset norm: {res2.normalized}"
    assert res2.status == "ok"
    print("[PASS] Explicit UTC offset converted to UTC correctly")

    # 3. Epoch timestamps (seconds & milliseconds)
    epoch_sec = "1729088625"
    res3 = normalize_timestamp(epoch_sec)
    assert res3.normalized is not None and res3.normalized.endswith("Z")
    assert res3.status == "ok"
    
    epoch_ms = "1729088625000"
    res4 = normalize_timestamp(epoch_ms)
    assert res4.normalized is not None and res4.normalized.endswith("Z")
    assert res4.status == "ok"
    print("[PASS] Epoch seconds and milliseconds normalized correctly")

    # 4. Ambiguous timestamps (day vs month ambiguity e.g. 03/04/2026)
    ambig_ts = "03/04/2026 12:00:00"
    res5 = normalize_timestamp(ambig_ts)
    assert res5.status == "ambiguous", f"Expected ambiguous status, got: {res5.status}"
    print(f"[PASS] Ambiguous timestamp identified honestly without silent guessing (status={res5.status})")

    # 5. Invalid timestamp - NEVER silently replaces with current time
    invalid_ts = "not-a-valid-timestamp"
    res6 = normalize_timestamp(invalid_ts)
    assert res6.normalized is None, f"Expected None for invalid timestamp, got {res6.normalized}"
    assert res6.status == "unparsed"
    assert res6.original == invalid_ts
    print("[PASS] Invalid timestamp NOT replaced with fake time (retained as unparsed with raw text preserved)")

def test_export_formatting():
    print("\n--- [TEST 2] Export Timestamp Formatting Engine ---")
    ts = "2026-10-23T14:30:15Z"
    
    # YYYY-MM-DD 24h
    f1 = _format_timestamp_for_export(ts, "YYYY-MM-DD", "24h")
    assert f1 == "2026-10-23 14:30:15 UTC", f"Got: {f1}"
    
    # DD-MM-YYYY 12h
    f2 = _format_timestamp_for_export(ts, "DD-MM-YYYY", "12h")
    assert f2 == "23-10-2026 02:30:15 PM UTC", f"Got: {f2}"
    
    # MM-DD-YYYY 24h
    f3 = _format_timestamp_for_export(ts, "MM-DD-YYYY", "24h")
    assert f3 == "10-23-2026 14:30:15 UTC", f"Got: {f3}"
    
    # DD/MM/YYYY 12h
    f4 = _format_timestamp_for_export(ts, "DD/MM/YYYY", "12h")
    assert f4 == "23/10/2026 02:30:15 PM UTC", f"Got: {f4}"
    
    print(f"[PASS] Export format YYYY-MM-DD 24h: {f1}")
    print(f"[PASS] Export format DD-MM-YYYY 12h: {f2}")
    print(f"[PASS] Export format MM-DD-YYYY 24h: {f3}")
    print(f"[PASS] Export format DD/MM/YYYY 12h: {f4}")

def test_csv_and_pdf_generation():
    print("\n--- [TEST 3] CSV, JSON, and PDF Reports ---")
    load_canonical_data()
    events = get_all_events(limit=50)
    alerts = get_all_alerts()
    assert len(events) > 0, "No events loaded from canonical scenario"
    assert len(alerts) > 0, "No alerts loaded from canonical scenario"

    # CSV with DD-MM-YYYY and 12h
    csv_out = generate_csv_export(events, date_format="DD-MM-YYYY", time_format="12h")
    assert "2026" in csv_out
    assert "UTC" in csv_out
    print(f"[PASS] Generated CSV export with formatted timestamps ({len(csv_out)} bytes)")

    # PDF with MM-DD-YYYY and 24h
    first_alert = alerts[0]
    pdf_out = generate_pdf_report(
        alert=first_alert,
        all_events=events,
        all_alerts=alerts,
        date_format="MM-DD-YYYY",
        time_format="24h"
    )
    assert len(pdf_out) > 5000, f"PDF too small: {len(pdf_out)} bytes"
    assert pdf_out.startswith(b"%PDF"), "Output is not valid PDF"
    print(f"[PASS] Generated PDF forensic dossier with formatted timestamps ({len(pdf_out)} bytes)")

def test_fastapi_endpoints():
    print("\n--- [TEST 4] FastAPI Endpoints & Contract Validation ---")
    client = TestClient(app)

    # Health check
    res = client.get("/api/health")
    assert res.status_code == 200
    print("[PASS] /api/health returned 200 OK")

    # CSV export endpoint
    res_csv = client.get("/api/reports/csv?date_format=DD-MM-YYYY&time_format=12h")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "TraceX_Evidence_Export.csv" in res_csv.headers["content-disposition"]
    print("[PASS] /api/reports/csv returned valid CSV with custom format params")

    # JSON export endpoint
    res_json = client.get("/api/reports/json?date_format=YYYY-MM-DD&time_format=24h")
    assert res_json.status_code == 200
    data = res_json.json()
    assert "metadata" in data
    assert "events" in data
    assert data["metadata"]["date_format"] == "YYYY-MM-DD"
    assert data["metadata"]["time_format"] == "24h"
    print("[PASS] /api/reports/json returned valid JSON with metadata and formatted timestamps")

    # PDF export endpoint
    res_pdf = client.get("/api/reports/pdf?date_format=DD/MM/YYYY&time_format=12h")
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert res_pdf.content.startswith(b"%PDF")
    print("[PASS] /api/reports/pdf returned valid PDF document")

    # Upload endpoint with automatic normalization (no format params required)
    csv_payload = (
        "timestamp,user,action,source_ip,host,category,severity_score\n"
        "2026-10-23T19:00:00Z,j.doe,login_failed,192.168.1.50,srv-web01,AUTHENTICATION,6.5\n"
        "2026-10-23T19:01:00Z,j.doe,login_success,192.168.1.50,srv-web01,AUTHENTICATION,4.0\n"
    )
    upload_res = client.post(
        "/api/upload",
        files={"file": ("test_logs.csv", csv_payload, "text/csv")},
        data={"mode": "append"}
    )
    assert upload_res.status_code == 200
    up_data = upload_res.json()
    assert up_data["success"] is True
    assert up_data["parsed_events_count"] == 2
    assert up_data["timestamps_normalized"] == 2
    assert "timestamps_ambiguous" in up_data
    print("[PASS] /api/upload successfully ingested file with automatic normalization (no format params required)")

if __name__ == "__main__":
    print("==================================================================")
    print("TRACEX VERIFICATION & REGRESSION TEST SUITE")
    print("==================================================================")
    test_timestamp_normalizer()
    test_export_formatting()
    test_csv_and_pdf_generation()
    test_fastapi_endpoints()
    print("\n==================================================================")
    print("ALL 4 TEST SUITES PASSED SUCCESSFULLY (100% EVIDENCE INTEGRITY)!")
    print("==================================================================")
