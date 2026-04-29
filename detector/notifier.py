"""
notifier.py - Slack alert sender

Sends formatted Slack messages via incoming webhook.
Uses a background queue so HTTP latency doesn't block detection.

Author: Vivian Nduka
"""

import json
import queue
import threading
import time
import logging
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Sends formatted alerts to Slack via webhook."""

    def __init__(self,
                 webhook_url,
                 username="HNG-Detector",
                 icon_emoji=":shield:",
                 async_dispatch=True,
                 timeout=5):
        """
        Args:
            webhook_url: Your Slack incoming webhook URL
            username: Display name for posts
            icon_emoji: Emoji shown beside posts
            async_dispatch: If True, send via background queue (non-blocking)
            timeout: HTTP timeout in seconds
        """
        self.webhook_url = webhook_url
        self.username = username
        self.icon_emoji = icon_emoji
        self.async_dispatch = async_dispatch
        self.timeout = timeout

        # Queue for async dispatch
        self._queue = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._thread = None

        if async_dispatch:
            self._start_worker()

    def _start_worker(self):
        """Start background thread that drains the queue."""
        self._thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="slack-notifier",
        )
        self._thread.start()

    def _worker_loop(self):
        """Pull messages off queue and POST them to Slack."""
        while not self._stop_event.is_set():
            try:
                payload = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            self._send_now(payload)
            self._queue.task_done()

    def _send_now(self, payload):
        """Synchronous POST to Slack."""
        if not self.webhook_url or "REPLACE" in self.webhook_url:
            logger.warning(
                "Slack webhook not configured - skipping alert. "
                f"Payload was: {payload.get('text', '?')[:80]}"
            )
            return

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout,
            )
            if response.status_code != 200:
                logger.error(
                    f"Slack returned {response.status_code}: {response.text}"
                )
            else:
                logger.debug(
                    f"Slack alert sent: {payload.get('text', '?')[:80]}"
                )
        except requests.RequestException as e:
            logger.error(f"Slack POST failed: {e}")

    def stop(self):
        """Drain queue and stop the worker thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ============================================================
    # Public API: high-level alert methods
    # ============================================================

    def send_ban_alert(self, ip, condition, current_rate,
                       baseline_mean, baseline_stddev,
                       duration_seconds, permanent=False, tightened=False):
        """Send a Slack alert when an IP is banned."""
        duration_str = "PERMANENT" if permanent else self._format_duration(duration_seconds)
        ts = datetime.utcnow().isoformat() + "Z"

        attachment = {
            "color": "#ff0000",  # red
            "title": f":no_entry: IP Banned: {ip}",
            "fields": [
                {"title": "Condition", "value": condition, "short": False},
                {"title": "Current Rate", "value": f"{current_rate} req/min", "short": True},
                {"title": "Baseline Mean", "value": f"{baseline_mean:.2f}", "short": True},
                {"title": "Baseline Stddev", "value": f"{baseline_stddev:.2f}", "short": True},
                {"title": "Ban Duration", "value": duration_str, "short": True},
                {"title": "Tightened?", "value": "Yes" if tightened else "No", "short": True},
                {"title": "Timestamp", "value": ts, "short": True},
            ],
            "footer": "HNG Stage 3 Detector",
        }

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": f":rotating_light: *Ban triggered:* `{ip}` ({condition})",
            "attachments": [attachment],
        }

        self._dispatch(payload)

    def send_unban_alert(self, ip, ban_info):
        """Send a Slack alert when an IP is auto-unbanned."""
        ts = datetime.utcnow().isoformat() + "Z"
        age_str = self._format_duration(ban_info.get("age_seconds", 0))

        attachment = {
            "color": "#36a64f",  # green
            "title": f":unlock: IP Unbanned: {ip}",
            "fields": [
                {"title": "Was Banned For", "value": age_str, "short": True},
                {"title": "Offense Count", "value": str(ban_info.get("offense_count", "?")), "short": True},
                {"title": "Original Condition", "value": ban_info.get("condition", "?"), "short": False},
                {"title": "Timestamp", "value": ts, "short": True},
            ],
            "footer": "HNG Stage 3 Detector",
        }

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": f":white_check_mark: *Auto-unbanned:* `{ip}`",
            "attachments": [attachment],
        }

        self._dispatch(payload)

    def send_global_alert(self, current_rate, baseline_mean,
                          baseline_stddev, condition):
        """Send a Slack alert when global rate is anomalous (no per-IP ban)."""
        ts = datetime.utcnow().isoformat() + "Z"

        attachment = {
            "color": "#ff8c00",  # orange
            "title": ":warning: Global Anomaly Detected",
            "fields": [
                {"title": "Condition", "value": condition, "short": False},
                {"title": "Current Rate", "value": f"{current_rate} req/min (global)", "short": True},
                {"title": "Baseline Mean", "value": f"{baseline_mean:.2f}", "short": True},
                {"title": "Baseline Stddev", "value": f"{baseline_stddev:.2f}", "short": True},
                {"title": "Action", "value": "Alert only (no ban)", "short": True},
                {"title": "Timestamp", "value": ts, "short": True},
            ],
            "footer": "HNG Stage 3 Detector",
        }

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": f":zap: *Global anomaly!* {condition}",
            "attachments": [attachment],
        }

        self._dispatch(payload)

    # ============================================================
    # Internal helpers
    # ============================================================

    def _dispatch(self, payload):
        """Send via queue if async, otherwise sync."""
        if self.async_dispatch:
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                logger.warning("Slack queue full - dropping alert")
        else:
            self._send_now(payload)

    def _format_duration(self, seconds):
        """Format seconds as a friendly string."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f} min"
        hours = minutes / 60
        return f"{hours:.1f} hr"


# ============================================================
# Standalone test
# ============================================================
if __name__ == "__main__":
    import sys
    import os
    import yaml

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    # Load webhook from config.yaml
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    webhook = cfg["slack"]["webhook_url"]
    if "REPLACE" in webhook:
        print("ERROR: Slack webhook not set in config.yaml")
        sys.exit(1)

    print(f"\nStandalone notifier test (using webhook from config.yaml)\n")

    notifier = SlackNotifier(
        webhook_url=webhook,
        async_dispatch=False,  # synchronous for testing
    )

    print("1. Sending fake BAN alert...")
    notifier.send_ban_alert(
        ip="192.0.2.42",
        condition="z_score>3.0 (z=8.45)",
        current_rate=120,
        baseline_mean=5.0,
        baseline_stddev=1.2,
        duration_seconds=600,
        permanent=False,
        tightened=False,
    )
    time.sleep(1)

    print("2. Sending fake UNBAN alert...")
    notifier.send_unban_alert(
        ip="192.0.2.42",
        ban_info={
            "age_seconds": 600,
            "offense_count": 1,
            "condition": "z_score>3.0 (z=8.45)",
        },
    )
    time.sleep(1)

    print("3. Sending fake GLOBAL alert...")
    notifier.send_global_alert(
        current_rate=850,
        baseline_mean=50.0,
        baseline_stddev=10.0,
        condition="rate>5x_mean (850 > 250)",
    )
    time.sleep(1)

    print("\n4. Testing async dispatch...")
    async_notifier = SlackNotifier(
        webhook_url=webhook,
        async_dispatch=True,
    )

    print("   Sending 3 alerts in quick succession...")
    for i in range(3):
        async_notifier.send_ban_alert(
            ip=f"192.0.2.{100+i}",
            condition=f"async_test_{i}",
            current_rate=99 + i,
            baseline_mean=5.0,
            baseline_stddev=1.0,
            duration_seconds=600,
        )

    print("   Waiting 5s for async sends to drain...")
    time.sleep(5)
    async_notifier.stop()

    print("\nTest complete! Check your Slack channel - you should see 6 messages:")
    print("  - 1 ban alert (red)")
    print("  - 1 unban alert (green)")
    print("  - 1 global alert (orange)")
    print("  - 3 async ban alerts (red)")
