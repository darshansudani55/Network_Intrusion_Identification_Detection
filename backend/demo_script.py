"""
Auto-Demo Script
--------------------------------
Cycles the traffic simulator through Benign -> Port Scan -> Benign ->
DoS Volumetric -> Benign -> DoS Slowloris automatically, with pauses,
so you can run this once and just talk over the dashboard during your
viva instead of clicking buttons live.

Usage:
  1. Start the backend first (separate terminal):
       cd backend
       uvicorn app.main:app --reload --port 8000

  2. Open frontend/dashboard.html in your browser so you can see it live.

  3. Then run this script (another terminal):
       cd backend
       python demo_script.py

Requires: pip install requests
"""

import time
import requests

API = "http://localhost:8000"

# (mode, human-readable label, seconds to stay in this mode)
SCRIPT = [
    ("benign",         "Benign traffic — establishing a normal baseline",     8),
    ("portscan",       "Port scan attack — attacker probing all ports",       10),
    ("benign",         "Back to benign — system recovers",                    6),
    ("dos_volumetric", "DoS attack (volumetric flood)",                       10),
    ("benign",         "Back to benign again",                                6),
    ("dos_slow",       "DoS attack (Slowloris — slow, low-rate)",             12),
    ("benign",         "Demo complete — back to benign",                      5),
]


def set_mode(mode: str):
    r = requests.post(f"{API}/api/simulate/mode", json={"mode": mode}, timeout=5)
    r.raise_for_status()
    return r.json()


def check_backend():
    try:
        r = requests.get(f"{API}/api/status", timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def main():
    status = check_backend()
    if status is None:
        print(f"[!] Can't reach backend at {API}. Start it first with:")
        print("      uvicorn app.main:app --reload --port 8000")
        return

    print(f"[+] Backend connected. Model loaded: {status.get('ml_model_loaded')}")
    print("[+] Starting auto-demo. Watch the dashboard in your browser.\n")

    for mode, label, duration in SCRIPT:
        print(f"[>] Switching to: {label} ({mode}) — holding for {duration}s")
        try:
            set_mode(mode)
        except Exception as e:
            print(f"[!] Failed to switch mode: {e}")
            return
        time.sleep(duration)

    print("\n[+] Demo sequence finished.")


if __name__ == "__main__":
    main()
