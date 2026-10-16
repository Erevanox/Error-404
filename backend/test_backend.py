from main import app, on_startup
from database import get_all_events, get_all_alerts
from exporter import generate_pdf_report

print("Testing backend startup...")
on_startup()
events = get_all_events()
alerts = get_all_alerts()
print(f"Events loaded: {len(events)}")
print(f"Alerts generated: {len(alerts)}")

if alerts:
    first_alert = alerts[0]
    print(f"Testing PDF generation for alert {first_alert['id']}...")
    pdf_bytes = generate_pdf_report(first_alert)
    print(f"PDF generated successfully! Size: {len(pdf_bytes)} bytes")

print("All backend checks passed!")
