"""
Demo Seeder Script.
Populates the SIEM database with baseline traffic and a few sample attack scenarios
for immediate interactive demonstration in the Web Dashboard.
"""
from app.database import init_db
from app.api import simulator

def seed():
    print("[*] Initializing database and default rules...")
    init_db()

    print("[*] Generating baseline enterprise traffic...")
    simulator.run_scenario("normal_traffic", intensity=20)

    print("[*] Simulating SSH Brute Force attempt (RULE-001)...")
    simulator.run_scenario("brute_force", intensity=6)

    print("[*] Simulating Server Directory Probing / Access Denied (RULE-003)...")
    simulator.run_scenario("access_denied", intensity=4)

    print("[+] Seeding complete! Dashboard is ready with live alerts and events.")

if __name__ == "__main__":
    seed()
