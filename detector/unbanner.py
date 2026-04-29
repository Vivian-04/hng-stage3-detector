"""
unbanner.py - Automatic unbanner with backoff schedule

Runs as a background thread. Periodically checks the blocker for IPs
whose ban duration has elapsed and unbans them.

Backoff schedule (from config):
  1st ban: 10 min
  2nd ban: 30 min
  3rd ban: 2 hours
  4th+:    permanent

Author: Vivian Nduka
"""

import threading
import time
import logging

logger = logging.getLogger(__name__)


class Unbanner:
    """Background thread that releases bans on a backoff schedule."""

    def __init__(self,
                 blocker,
                 detector,
                 unban_schedule_seconds,
                 permanent_after_offense=4,
                 check_interval=30,
                 on_unban_callback=None):
        """
        Args:
            blocker: An IPBlocker instance
            detector: An AnomalyDetector instance (so we can clear its alert flag)
            unban_schedule_seconds: List like [600, 1800, 7200] for 1st, 2nd, 3rd ban
            permanent_after_offense: Permanent ban after this many offenses (4)
            check_interval: How often to check for expired bans (seconds)
            on_unban_callback: Optional fn called as callback(ip, info) after unban
        """
        self.blocker = blocker
        self.detector = detector
        self.unban_schedule = unban_schedule_seconds
        self.permanent_after_offense = permanent_after_offense
        self.check_interval = check_interval
        self.on_unban_callback = on_unban_callback

        self._stop_event = threading.Event()
        self._thread = None

    def get_ban_duration(self, offense_count):
        """Return the ban duration for the given offense number.

        Returns -1 to signal permanent ban.

        offense_count is 1-based (1 = first offense, 2 = second, etc.)
        """
        if offense_count >= self.permanent_after_offense:
            return -1  # signal permanent

        # Schedule is 0-indexed, offense is 1-indexed
        idx = offense_count - 1
        if idx < len(self.unban_schedule):
            return self.unban_schedule[idx]

        # Fallback: use last entry in schedule (shouldn't happen)
        return self.unban_schedule[-1]

    def calculate_ban_for_ip(self, ip):
        """Determine ban duration for an IP based on its offense history.

        Returns (duration_seconds, is_permanent).
        """
        prev_offenses = self.blocker.get_offense_count(ip)
        new_offense_count = prev_offenses + 1

        duration = self.get_ban_duration(new_offense_count)

        if duration == -1:
            # Permanent ban
            return (365 * 24 * 3600, True)  # 1 year nominally; flag as permanent
        return (duration, False)

    def start(self):
        """Start the background unban-check thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Unbanner already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="unbanner",
        )
        self._thread.start()
        logger.info(
            f"Unbanner started (check every {self.check_interval}s, "
            f"schedule={self.unban_schedule})"
        )

    def stop(self):
        """Stop the background thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Unbanner stopped")

    def _run(self):
        """Main loop: check for expired bans, unban them."""
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:
                logger.exception(f"Unbanner tick failed: {e}")

            # Wait for next check (or stop event)
            self._stop_event.wait(self.check_interval)

    def _tick(self):
        """One iteration of the unban check loop."""
        expired_ips = self.blocker.list_expired()

        if not expired_ips:
            return

        for ip in expired_ips:
            # Get ban info BEFORE unbanning (we'll lose it after)
            ban_info = None
            for b in self.blocker.list_bans():
                if b["ip"] == ip:
                    ban_info = b
                    break

            success = self.blocker.unban(ip)
            if not success:
                logger.warning(f"Failed to unban {ip}")
                continue

            # Clear the detector's alert flag so this IP can re-trigger if needed
            self.detector.clear_alert(ip)

            logger.info(
                f"Auto-unbanned {ip} after {ban_info['age_seconds']:.0f}s"
                if ban_info else f"Auto-unbanned {ip}"
            )

            # Fire callback (will send Slack alert in main.py)
            if self.on_unban_callback and ban_info:
                try:
                    self.on_unban_callback(ip, ban_info)
                except Exception as e:
                    logger.exception(f"Unban callback failed for {ip}: {e}")


# ============================================================
# Standalone test
# ============================================================
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    # We need blocker and a stub detector for the test
    sys.path.insert(0, ".")
    from blocker import IPBlocker

    class StubDetector:
        def __init__(self):
            self.cleared = []
        def clear_alert(self, ip):
            self.cleared.append(ip)
            print(f"  [stub detector] cleared alert for {ip}")

    TEST_IP = "192.0.2.99"
    SHORT_DURATION = 5  # seconds

    print(f"\nStandalone unbanner test (using {TEST_IP}, {SHORT_DURATION}s ban)\n")

    blocker = IPBlocker()
    detector_stub = StubDetector()

    def on_unban(ip, info):
        print(f"  [callback] would send Slack alert: {ip} unbanned "
              f"(was banned for {info['age_seconds']:.1f}s)")

    unbanner = Unbanner(
        blocker=blocker,
        detector=detector_stub,
        unban_schedule_seconds=[SHORT_DURATION, 30, 60],
        permanent_after_offense=4,
        check_interval=2,
        on_unban_callback=on_unban,
    )

    print(f"1. Banning {TEST_IP} for {SHORT_DURATION}s...")
    blocker.ban(TEST_IP, duration_seconds=SHORT_DURATION, condition="test")

    print("2. Starting unbanner thread...")
    unbanner.start()

    print(f"3. Waiting {SHORT_DURATION + 4}s for auto-unban...")
    for i in range(SHORT_DURATION + 4):
        time.sleep(1)
        active = blocker.list_bans()
        print(f"   t={i+1}s: {len(active)} active bans")
        if not active:
            break

    print("\n4. Stopping unbanner...")
    unbanner.stop()

    print(f"\n5. Final state:")
    print(f"   Active bans: {blocker.list_bans()}")
    print(f"   Detector cleared: {detector_stub.cleared}")

    print("\n6. Backoff schedule test (no actual bans, just calculation):")
    for offense in [1, 2, 3, 4, 5]:
        duration = unbanner.get_ban_duration(offense)
        if duration == -1:
            print(f"   Offense #{offense}: PERMANENT")
        else:
            print(f"   Offense #{offense}: {duration}s "
                  f"({duration//60}min if applicable)")

    print("\nTest complete!")
