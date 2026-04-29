"""
baseline.py - Rolling baseline calculator

Maintains per-second request counts over a 30-minute rolling window.
Recalculates mean and standard deviation every 60 seconds.

Maintains per-hour slots so the baseline reflects "normal traffic
for THIS hour of day" rather than getting polluted by other periods.

Author: Vivian Nduka
"""

import time
import statistics
import threading
import logging
from collections import deque, defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class RollingBaseline:
    """Computes rolling mean/stddev of per-second request counts."""

    def __init__(self,
                 window_seconds=1800,
                 recalc_interval=60,
                 min_samples=60,
                 floor_mean=1.0,
                 floor_stddev=1.0,
                 use_hourly_slots=True):
        """
        Args:
            window_seconds: Size of rolling window in seconds (1800 = 30 min)
            recalc_interval: How often to recalculate stats (seconds)
            min_samples: Minimum data points before baseline is "ready"
            floor_mean: Minimum mean value (prevents tiny values causing huge z-scores)
            floor_stddev: Minimum stddev value (same reason)
            use_hourly_slots: If True, keep separate baseline per hour-of-day
        """
        self.window_seconds = window_seconds
        self.recalc_interval = recalc_interval
        self.min_samples = min_samples
        self.floor_mean = floor_mean
        self.floor_stddev = floor_stddev
        self.use_hourly_slots = use_hourly_slots

        # Per-second request counts. Each item is (timestamp_int, count).
        # We use a deque with a max size so old data auto-evicts.
        # 1800 seconds = 1800 entries max
        self._counts = deque(maxlen=window_seconds)

        # Per-hour slots: hour (0-23) -> deque of per-second counts
        # Each slot stores up to 3600 entries (one full hour of seconds)
        self._hourly_slots = defaultdict(lambda: deque(maxlen=3600))

        # Per-second error (4xx/5xx) counts for error surge detection
        self._error_counts = deque(maxlen=window_seconds)

        # Current second's counter (we accumulate here, then push to deque each second)
        self._current_second = int(time.time())
        self._current_count = 0
        self._current_errors = 0

        # Computed baseline values (updated by recalculate())
        self.mean = floor_mean
        self.stddev = floor_stddev
        self.error_mean = 0.0
        self.error_stddev = floor_stddev
        self.last_recalc_time = 0
        self.is_ready = False

        # Thread-safe lock since we write from monitor thread, read from detector
        self._lock = threading.Lock()

    def record_request(self, is_error=False):
        """Call this for every request seen. Updates per-second counters."""
        with self._lock:
            now = int(time.time())

            # If we've moved to a new second, push old second's count to deque
            if now != self._current_second:
                self._flush_current_second(now)

            self._current_count += 1
            if is_error:
                self._current_errors += 1

    def _flush_current_second(self, now):
        """Internal: push current second's count to the rolling deque, then reset."""
        # Fill any "skipped" seconds with zeros (no traffic during them)
        while self._current_second < now:
            self._counts.append(self._current_count)
            self._error_counts.append(self._current_errors)

            # Also append to per-hour slot
            if self.use_hourly_slots:
                hour = datetime.fromtimestamp(self._current_second).hour
                self._hourly_slots[hour].append(self._current_count)

            self._current_second += 1
            self._current_count = 0
            self._current_errors = 0

    def recalculate(self):
        """Recalculate mean and stddev from the rolling window.

        Should be called every recalc_interval seconds (60s).
        Prefers per-hour slot data if available and well-populated.
        """
        with self._lock:
            now = int(time.time())
            self._flush_current_second(now)

            # ============================================================
            # Decide which data set to use for the baseline:
            # - Hourly slot if it has enough samples (preferred)
            # - Otherwise, the rolling window
            # ============================================================
            data_source = None
            source_label = "rolling"

            if self.use_hourly_slots:
                current_hour = datetime.fromtimestamp(now).hour
                hourly_data = self._hourly_slots.get(current_hour)
                if hourly_data and len(hourly_data) >= self.min_samples:
                    data_source = list(hourly_data)
                    source_label = f"hourly[{current_hour}]"

            if data_source is None:
                if len(self._counts) >= self.min_samples:
                    data_source = list(self._counts)
                else:
                    # Not enough data yet - keep using floor values
                    self.is_ready = False
                    self.last_recalc_time = now
                    logger.info(
                        f"Baseline not ready: only {len(self._counts)} samples, "
                        f"need {self.min_samples}"
                    )
                    return

            # ============================================================
            # Compute mean and stddev
            # ============================================================
            raw_mean = statistics.mean(data_source)

            if len(data_source) >= 2:
                raw_stddev = statistics.stdev(data_source)
            else:
                raw_stddev = 0.0

            # Apply floor values to prevent division-by-tiny-numbers
            self.mean = max(raw_mean, self.floor_mean)
            self.stddev = max(raw_stddev, self.floor_stddev)

            # Same calculation for errors
            if len(self._error_counts) >= 2:
                self.error_mean = statistics.mean(self._error_counts)
                self.error_stddev = max(
                    statistics.stdev(self._error_counts),
                    self.floor_stddev,
                )
            else:
                self.error_mean = 0.0
                self.error_stddev = self.floor_stddev

            self.is_ready = True
            self.last_recalc_time = now

            logger.info(
                f"Baseline recalculated [{source_label}]: "
                f"mean={self.mean:.2f}, stddev={self.stddev:.2f}, "
                f"error_mean={self.error_mean:.2f}, "
                f"samples={len(data_source)}"
            )

    def get_stats(self):
        """Return current baseline values as a dict (for dashboard/audit)."""
        with self._lock:
            return {
                "mean": self.mean,
                "stddev": self.stddev,
                "error_mean": self.error_mean,
                "error_stddev": self.error_stddev,
                "is_ready": self.is_ready,
                "samples": len(self._counts),
                "last_recalc": self.last_recalc_time,
                "hourly_slot_sizes": {
                    h: len(d) for h, d in self._hourly_slots.items()
                } if self.use_hourly_slots else {},
            }


# ============================================================
# Background recalculation thread
# ============================================================

def start_baseline_thread(baseline, recalc_interval, stop_event):
    """Run baseline.recalculate() in a loop. Call this in a thread."""
    def _loop():
        while not stop_event.is_set():
            try:
                baseline.recalculate()
            except Exception as e:
                logger.exception(f"Baseline recalc failed: {e}")
            stop_event.wait(recalc_interval)

    t = threading.Thread(target=_loop, daemon=True, name="baseline-recalc")
    t.start()
    return t


# ============================================================
# Standalone test
# ============================================================
if __name__ == "__main__":
    import random

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    print("Standalone baseline test - simulating 90 seconds of traffic...")
    print("Will record ~5 req/sec normally, then a burst, then check baseline.\n")

    bl = RollingBaseline(
        window_seconds=120,        # smaller for testing
        recalc_interval=10,        # faster for testing
        min_samples=10,
        floor_mean=1.0,
        floor_stddev=1.0,
    )

    # Simulate 60 seconds of normal traffic (~5 req/sec)
    print("Phase 1: Normal traffic (5 req/sec)")
    for sec in range(60):
        for _ in range(5 + random.randint(-1, 1)):
            bl.record_request(is_error=random.random() < 0.05)
        time.sleep(1)
        if sec % 10 == 9:
            bl.recalculate()
            stats = bl.get_stats()
            print(f"  After {sec+1}s: ready={stats['is_ready']} "
                  f"mean={stats['mean']:.2f} stddev={stats['stddev']:.2f}")

    # Simulate burst
    print("\nPhase 2: Burst (50 req/sec for 5 seconds)")
    for sec in range(5):
        for _ in range(50):
            bl.record_request()
        time.sleep(1)

    # Final stats
    bl.recalculate()
    stats = bl.get_stats()
    print(f"\nFinal baseline: mean={stats['mean']:.2f}, "
          f"stddev={stats['stddev']:.2f}")
    print(f"(Note: burst data is in the window now, so mean will rise)")
    print("\nTest complete!")
