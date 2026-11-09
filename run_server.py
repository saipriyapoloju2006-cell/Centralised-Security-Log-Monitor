"""
Runner script for Centralized Security Log Monitoring and Alert System.
Starts the ASGI server on http://127.0.0.1:8000
"""
import sys
import uvicorn
from app.config import SERVER_HOST, SERVER_PORT
from app.database import init_db

def main():
    print("=" * 70)
    print("  SENTINEL-LOG SIEM | Centralized Security Log Monitoring System")
    print("  Industrial Cybersecurity Monitoring & Incident Response Platform")
    print("=" * 70)
    print(f"[*] Initializing local database and threat detection rules...")
    init_db()
    print(f"[+] Database ready at data/security_logs.db")
    print(f"[+] Starting HTTP / ASGI server on http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"[+] Web Dashboard URL: http://{SERVER_HOST}:{SERVER_PORT}/index.html")
    print(f"[+] Predefined Rules Loaded: RULE-001 through RULE-006")
    print(f"[+] Simulation Lab Ready: Test scenarios 1 through 6 active")
    print("=" * 70)
    print("Press CTRL+C to stop the server.\n")

    uvicorn.run(
        "app.api:create_app",
        factory=True,
        host=SERVER_HOST,
        port=SERVER_PORT,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    main()
