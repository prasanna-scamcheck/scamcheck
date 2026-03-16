"""
ScamCheck — Scheduled Threat Feed Updater
Runs threat feeds every 6 hours to keep the database fresh.

Run:  py -3.12 scheduler.py
Or:   Keep it running in a third terminal for auto-updates.
"""

import time
import threading
from datetime import datetime
from threat_feeds import run_all_feeds


UPDATE_INTERVAL_HOURS = 6


def run_update():
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scheduled feed update...")
    try:
        run_all_feeds()
    except Exception as e:
        print(f"Feed update error: {e}")
    print(f"Next update in {UPDATE_INTERVAL_HOURS} hours.\n")


if __name__ == "__main__":
    print("=" * 60)
    print("ScamCheck — Threat Feed Scheduler")
    print(f"Updates every {UPDATE_INTERVAL_HOURS} hours")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    # Run immediately on start
    run_update()

    # Then schedule periodic updates
    while True:
        time.sleep(UPDATE_INTERVAL_HOURS * 3600)
        run_update()
