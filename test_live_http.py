import urllib.request
import json

print("1. Checking Frontend (http://localhost:5173/)...")
with urllib.request.urlopen("http://localhost:5173/") as res:
    html = res.read().decode('utf-8')
    print(f"   Frontend Response: HTTP {res.status}, length: {len(html)} bytes")
    print(f"   Has root div: {'id=\"root\"' in html}")

print("\n2. Checking Backend Health (http://127.0.0.1:8000/api/health)...")
with urllib.request.urlopen("http://127.0.0.1:8000/api/health") as res:
    data = json.loads(res.read().decode('utf-8'))
    print(f"   Health response: {data}")

print("\n3. Checking Backend Stats (http://127.0.0.1:8000/api/stats)...")
with urllib.request.urlopen("http://127.0.0.1:8000/api/stats") as res:
    data = json.loads(res.read().decode('utf-8'))
    print(f"   Total events: {data['total_events']}")
    print(f"   Total alerts: {data['total_alerts']}")
    print(f"   Alerts requiring review: {data['alerts_requiring_review']}")
    print(f"   High concern patterns: {data['high_concern_patterns']}")

print("\n4. Checking Correlated Alerts (http://127.0.0.1:8000/api/alerts)...")
with urllib.request.urlopen("http://127.0.0.1:8000/api/alerts") as res:
    data = json.loads(res.read().decode('utf-8'))
    print(f"   Alert count: {data['count']}")
    for a in data['alerts']:
        print(f"   - [{a['severity']}] {a['id']}: {a['title']} (Risk: {a['risk_score']}/100)")

print("\n5. Checking Scatter Events (http://127.0.0.1:8000/api/events/scatter)...")
with urllib.request.urlopen("http://127.0.0.1:8000/api/events/scatter") as res:
    data = json.loads(res.read().decode('utf-8'))
    print(f"   Scatter plot points count: {len(data)}")

print("\n6. Checking Detailed Alert Supporting Events (/api/alerts/{id})...")
with urllib.request.urlopen("http://127.0.0.1:8000/api/alerts") as res:
    alerts_data = json.loads(res.read().decode('utf-8'))['alerts']
    for a in alerts_data:
        aid = a['id']
        with urllib.request.urlopen(f"http://127.0.0.1:8000/api/alerts/{aid}") as a_res:
            detail = json.loads(a_res.read().decode('utf-8'))
            sup = detail.get('supporting_events', [])
            print(f"   - Alert {aid}: {len(sup)} supporting events, user: {detail.get('primary_user')}, ip: {detail.get('primary_ip')}")
            for i, ev in enumerate(sup[:2]):
                print(f"       Node {i+1}: [{ev.get('timestamp')}] {ev.get('event_type')} (action={ev.get('action')}, score={ev.get('severity_score')})")

print("\nAll live HTTP endpoint tests passed successfully!")
