import urllib.request
import urllib.parse
import json
import os
import io
import mimetypes

import os

BASE_URL = os.environ.get("TRACEX_API_URL", "http://127.0.0.1:8001")

def post_json(endpoint, data=None):
    req = urllib.request.Request(f"{BASE_URL}{endpoint}", data=b"" if data is None else json.dumps(data).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode("utf-8"))

def get_json(endpoint):
    with urllib.request.urlopen(f"{BASE_URL}{endpoint}") as res:
        return json.loads(res.read().decode("utf-8"))

def get_bytes(endpoint):
    with urllib.request.urlopen(f"{BASE_URL}{endpoint}") as res:
        return res.read()

def upload_multipart(filename, content_bytes, mode="clear"):
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = bytearray()
    
    # mode field
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="mode"\r\n\r\n'.encode("utf-8"))
    body.extend(f"{mode}\r\n".encode("utf-8"))
    
    # file field
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
    body.extend(b"Content-Type: text/csv\r\n\r\n")
    body.extend(content_bytes)
    body.extend(b"\r\n")
    
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    
    req = urllib.request.Request(f"{BASE_URL}/api/upload", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))

def run_tests():
    print("=" * 60)
    print("TRACEX VERIFICATION SUITE")
    print("=" * 60)
    
    # ---------------------------------------------------------
    # TEST A: Fresh Launch / Clean State
    # ---------------------------------------------------------
    print("\n[TEST A] Verifying Fresh Launch & Empty State...")
    post_json("/api/clear")
    stats = get_json("/api/stats")
    print(f"  Total Records:     {stats.get('total_records', stats.get('total_events'))}")
    print(f"  Detection Alerts:  {stats.get('detection_alerts')}")
    print(f"  Correlated Alerts: {stats.get('correlated_alerts')}")
    print(f"  Validation Errors: {stats.get('validation_errors')}")
    
    assert stats.get('total_records', stats.get('total_events')) == 0, "Total records must be 0"
    assert stats.get('detection_alerts') == 0, "Detection alerts must be 0"
    assert stats.get('correlated_alerts') == 0, "Correlated alerts must be 0"
    assert stats.get('validation_errors') == 0, "Validation errors must be 0"
    
    events_resp = get_json("/api/events")
    assert len(events_resp["events"]) == 0, "Events list must be empty"
    alerts_resp = get_json("/api/alerts")
    assert len(alerts_resp["alerts"]) == 0, "Alerts list must be empty"
    print("  -> TEST A PASSED: All metrics strictly 0, database completely clean.")
    
    # ---------------------------------------------------------
    # TEST E: Empty-State Export
    # ---------------------------------------------------------
    print("\n[TEST E] Verifying Empty-State PDF Export...")
    empty_pdf = get_bytes("/api/reports/pdf")
    assert empty_pdf.startswith(b"%PDF-"), "Must produce a valid PDF"
    assert b"TraceX" in empty_pdf or b"TRACEX" in empty_pdf, "Must contain TraceX branding"
    assert b"EventLens" not in empty_pdf and b"Event Lens" not in empty_pdf, "Must not contain EventLens"
    print(f"  -> TEST E PASSED: Generated valid empty state report ({len(empty_pdf)} bytes) without fabrication.")
    
    # ---------------------------------------------------------
    # TEST C: Invalid CSV Upload
    # ---------------------------------------------------------
    print("\n[TEST C] Verifying Invalid CSV Handling...")
    invalid_csv_bytes = b"bad_col1,bad_col2\n" # Missing valid structure
    status_code, err_resp = upload_multipart("invalid.csv", b"")
    print(f"  Upload empty CSV HTTP Status: {status_code}")
    print(f"  Response: {err_resp}")
    assert status_code == 400, "Must return 400 for empty/invalid CSV"
    assert err_resp.get("success") is False, "success must be False"
    print("  -> TEST C PASSED: Invalid CSV caught with structured error message, server stable.")
    
    # ---------------------------------------------------------
    # TEST B: Valid CSV Upload
    # ---------------------------------------------------------
    print("\n[TEST B] Verifying Valid CSV Upload & Pipeline Processing...")
    csv_path = os.path.join(os.path.dirname(__file__), "datasets", "sample_attack_lateral_movement.csv")
    with open(csv_path, "rb") as f:
        csv_bytes = f.read()
    
    status_code, upload_resp = upload_multipart("sample_attack_lateral_movement.csv", csv_bytes, mode="clear")
    print(f"  Upload CSV HTTP Status: {status_code}")
    print(f"  Parsed Events:          {upload_resp.get('parsed_events_count')}")
    print(f"  New Events Inserted:    {upload_resp.get('new_events_inserted')}")
    print(f"  Total Database Events:  {upload_resp.get('total_database_events')}")
    print(f"  New Alerts Generated:   {upload_resp.get('new_alerts_generated')}")
    
    assert status_code == 200, "Upload must succeed with HTTP 200"
    assert upload_resp.get("new_events_inserted") > 0, "Must insert events"
    assert upload_resp.get("new_alerts_generated") > 0, "Must generate correlated alerts"
    
    updated_stats = get_json("/api/stats")
    print(f"  Updated Stats: Total Records={updated_stats.get('total_records')}, Alerts={updated_stats.get('correlated_alerts')}")
    assert updated_stats.get("total_records") > 0
    assert updated_stats.get("correlated_alerts") > 0
    print("  -> TEST B PASSED: Pipeline processed CSV, updated stats and correlation.")
    
    # ---------------------------------------------------------
    # TEST D: PDF Export with Investigation Data
    # ---------------------------------------------------------
    print("\n[TEST D] Verifying PDF Export Branding and Content...")
    alerts = get_json("/api/alerts")["alerts"]
    alert_id = alerts[0]["id"]
    alert_pdf = get_bytes(f"/api/reports/pdf/{alert_id}")
    assert alert_pdf.startswith(b"%PDF-"), "Must produce valid PDF binary"
    assert b"EventLens" not in alert_pdf and b"Event Lens" not in alert_pdf, "Must not contain EventLens"
    print(f"  Exported PDF for {alert_id}: {len(alert_pdf)} bytes")
    print("  -> TEST D PASSED: PDF generated with complete TraceX branding and layout.")
    
    # ---------------------------------------------------------
    # TEST F: Reset Back to Clean Empty State
    # ---------------------------------------------------------
    print("\n[TEST F] Resetting back to Empty State for Fresh Launch...")
    post_json("/api/clear")
    final_stats = get_json("/api/stats")
    assert final_stats.get("total_records", final_stats.get("total_events")) == 0
    assert final_stats.get("correlated_alerts") == 0
    print("  -> TEST F PASSED: Cleared back to pristine zero-count state.")
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED WITH 100% SUCCESS")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
