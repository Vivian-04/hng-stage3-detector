"""
detector.py - Anomaly detection logic

Maintains two sliding windows (per-IP and global) using deques.
On each request, updates windows and checks for anomalies via
z-score and rate-multiplier rules.

When an IP's error rate (4xx/5xx) is 3x the baseline, tightens
detection thresholds for that IP.

Author: Vivian Nduka
"""

import time
import threading
import logging
from collections import deque, defaultdict

logger = logging.getLogger(__name__)


class SlidingWindow:
    """A simple deque-based timestamp window."""

    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self._timestamps = deque()

    def add(self, timestamp=None):
        """Record an event at the given timestamp (or now)."""
        if timestamp is None:
            timestamp = time.time()
        self._timestamps.append(timestamp)
        self._evict(timestamp)

    def _evict(self, now):
        """Remove timestamps older than window_seconds from `now`."""
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def rate(self, now=None):
        """Return current request count in the window."""
        if now is None:
            now = time.time()
        self._evict(now)
        return len(self._timestamps)

    def __len__(self):
        return len(self._timestamps)


class AnomalyDetector:
    """Detects per-IP and global rate anomalies using z-score + rate rules."""

    def __init__(self,
                 baseline,
                 window_seconds=60,
                 z_threshold=3.0,
                 rate_multiplier=5.0,
                 error_surge_multiplier=3.0,
                 tightened_z=2.0,
                 tightened_rate_multiplier=3.0,
                 max_tracked_ips=10000):
        """
        Args:
            baseline: A RollingBaseline instance (provides mean/stddev)
            window_seconds: Sliding window size (60s)
            z_threshold: Normal z-score threshold (3.0)
            rate_multiplier: Normal rate threshold (5x mean)
            error_surge_multiplier: Tighten when IP errors > this x baseline (3x)
            tightened_z: Z-threshold for IPs with error surges (2.0)
            tightened_rate_multiplier: Rate threshold for surging IPs (3x)
            max_tracked_ips: Cap on tracked IPs (memory protection)
        """
        self.baseline = baseline
        self.window_seconds = window_seconds
        self.z_threshold = z_threshold
        self.rate_multiplier = rate_multiplier
        self.error_surge_multiplier = error_surge_multiplier
        self.tightened_z = tightened_z
        self.tightened_rate_multiplier = tightened_rate_multiplier
        self.max_tracked_ips = max_tracked_ips

        # Global sliding window (all requests)
        self._global_window = SlidingWindow(window_seconds)

        # Per-IP sliding window
        self._ip_windows = {}  # ip -> SlidingWindow
        self._ip_error_windows = {}  # ip -> SlidingWindow (only 4xx/5xx)

        # Track which IPs we've already alerted on (avoid spam)
        # Will be cleared by the blocker/unbanner integration
        self._alerted_ips = set()
        self._global_alert_active = False

        self._lock = threading.Lock()

    def _get_or_create_ip_window(self, ip):
        """Lazy-create per-IP windows, capped at max_tracked_ips."""
        if ip in self._ip_windows:
            return self._ip_windows[ip], self._ip_error_windows[ip]

        if len(self._ip_windows) >= self.max_tracked_ips:
            # We've hit the cap. Don't track new IPs (memory protection).
            # In a real system, you'd evict the LRU entry here.
            return None, None

        w = SlidingWindow(self.window_seconds)
        ew = SlidingWindow(self.window_seconds)
        self._ip_windows[ip] = w
        self._ip_error_windows[ip] = ew
        return w, ew

    def process_request(self, ip, is_error, now=None):
        """Record a request and check for anomalies.

        Returns:
            list of dicts describing anomalies fired (empty if none).
            Each dict has: type ('per_ip' or 'global'), ip, rate, baseline_mean,
            baseline_stddev, z_score, condition, timestamp.
        """
        if now is None:
            now = time.time()

        with self._lock:
            anomalies = []

            # ============================================================
            # Update global window
            # ============================================================
            self._global_window.add(now)
            global_rate = self._global_window.rate(now)

            # ============================================================
            # Update per-IP window
            # ============================================================
            ip_window, ip_error_window = self._get_or_create_ip_window(ip)
            if ip_window is None:
                # IP cap reached - skip per-IP tracking but still check global
                pass
            else:
                ip_window.add(now)
                if is_error:
                    ip_error_window.add(now)

                # ============================================================
                # Check per-IP anomaly
                # ============================================================
                ip_rate = ip_window.rate(now)
                ip_error_rate = ip_error_window.rate(now)

                # Decide thresholds: tighten if error surge
                z_thresh = self.z_threshold
                rate_mult = self.rate_multiplier

                if self.baseline.is_ready and self.baseline.error_mean > 0:
                    if ip_error_rate >= self.error_surge_multiplier * self.baseline.error_mean:
                        z_thresh = self.tightened_z
                        rate_mult = self.tightened_rate_multiplier
                        logger.debug(
                            f"IP {ip} has error surge "
                            f"({ip_error_rate} vs baseline {self.baseline.error_mean:.2f}) "
                            f"-> tightened thresholds"
                        )

                # Check anomaly conditions
                anomaly = self._check_anomaly(
                    rate=ip_rate,
                    z_thresh=z_thresh,
                    rate_mult=rate_mult,
                )
                if anomaly and ip not in self._alerted_ips:
                    self._alerted_ips.add(ip)
                    anomalies.append({
                        "type": "per_ip",
                        "ip": ip,
                        "rate": ip_rate,
                        "baseline_mean": self.baseline.mean,
                        "baseline_stddev": self.baseline.stddev,
                        "z_score": anomaly["z_score"],
                        "condition": anomaly["condition"],
                        "tightened": z_thresh != self.z_threshold,
                        "timestamp": now,
                    })

            # ============================================================
            # Check global anomaly
            # ============================================================
            global_anomaly = self._check_anomaly(
                rate=global_rate,
                z_thresh=self.z_threshold,
                rate_mult=self.rate_multiplier,
            )
            if global_anomaly and not self._global_alert_active:
                self._global_alert_active = True
                anomalies.append({
                    "type": "global",
                    "ip": None,
                    "rate": global_rate,
                    "baseline_mean": self.baseline.mean,
                    "baseline_stddev": self.baseline.stddev,
                    "z_score": global_anomaly["z_score"],
                    "condition": global_anomaly["condition"],
                    "tightened": False,
                    "timestamp": now,
                })
            elif not global_anomaly and self._global_alert_active:
                # Global rate normalized
                self._global_alert_active = False

            return anomalies

    def _check_anomaly(self, rate, z_thresh, rate_mult):
        """Apply z-score AND rate-multiplier rules.

        Returns dict with z_score and condition if anomalous, else None.
        """
        if not self.baseline.is_ready:
            return None  # Don't fire alarms before baseline is established

        mean = self.baseline.mean
        stddev = self.baseline.stddev

        # Rule 1: Z-score
        if stddev > 0:
            z = (rate - mean) / stddev
            if z > z_thresh:
                return {
                    "z_score": z,
                    "condition": f"z_score>{z_thresh} (z={z:.2f})",
                }

        # Rule 2: Rate multiplier
        if rate > rate_mult * mean:
            z = (rate - mean) / stddev if stddev > 0 else float("inf")
            return {
                "z_score": z,
                "condition": f"rate>{rate_mult}x_mean ({rate} > {rate_mult * mean:.1f})",
            }

        return None

    def clear_alert(self, ip):
        """Call this when an IP has been unbanned, so it can re-trigger."""
        with self._lock:
            self._alerted_ips.discard(ip)

    def get_stats(self):
        """Return current detector stats (for dashboard)."""
        with self._lock:
            now = time.time()

            # Top 10 IPs by current rate
            ip_rates = [(ip, w.rate(now)) for ip, w in self._ip_windows.items()]
            ip_rates.sort(key=lambda x: x[1], reverse=True)
            top_10 = ip_rates[:10]

            return {
                "global_rate": self._global_window.rate(now),
                "tracked_ips": len(self._ip_windows),
                "top_ips": [{"ip": ip, "rate": rate} for ip, rate in top_10],
                "alerted_ips": list(self._alerted_ips),
                "global_alert_active": self._global_alert_active,
            }


# ============================================================
# Standalone test
# ============================================================
if __name__ == "__main__":
    from baseline import RollingBaseline

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    print("Standalone detector test\n")
    print("Setup: baseline mean=5, stddev=1.5 (manually set)")
    print("Will simulate: normal traffic, then attack from one IP\n")

    # Manually set up a baseline
    bl = RollingBaseline(min_samples=10)
    # Simulate enough data to make it ready
    for sec in range(120):
        for _ in range(5):
            bl.record_request()
    bl.recalculate()
    print(f"Baseline ready: mean={bl.mean:.2f}, stddev={bl.stddev:.2f}\n")

    detector = AnomalyDetector(baseline=bl)

    # Phase 1: Normal traffic from many IPs
    print("Phase 1: Normal traffic (5 req/sec across 10 IPs)")
    for sec in range(10):
        for _ in range(5):
            ip = f"192.168.1.{(sec % 10) + 1}"
            anomalies = detector.process_request(ip, is_error=False)
            if anomalies:
                print(f"  ANOMALY: {anomalies}")
        time.sleep(0.1)
    print(f"  Stats: {detector.get_stats()}\n")

    # Phase 2: Attacker IP hammers us
    print("Phase 2: Attacker 1.2.3.4 sends 100 requests in 1 second")
    print("(Note: anomaly fires ONCE then is suppressed - this is correct!)")
    total_fired = 0
    for i in range(100):
        anomalies = detector.process_request("1.2.3.4", is_error=False)
        if anomalies:
            total_fired += len(anomalies)
            for a in anomalies:
                print(f"  🚨 ANOMALY at request #{i+1}: type={a['type']} "
                      f"ip={a['ip']} rate={a['rate']} z={a['z_score']:.2f} "
                      f"condition={a['condition']}")

    print(f"\nTotal anomalies fired: {total_fired} (expect 2: per_ip + global)")
    print(f"Final stats: {detector.get_stats()}")
    print("\nTest complete!")
