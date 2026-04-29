"""
monitor.py - Log file tailer

Watches the nginx JSON access log file in real-time. As new lines are
written, parses them into Python dicts and yields them to the caller.

Handles log rotation by checking the file's inode periodically.

Author: Vivian Nduka
"""

import json
import os
import time
import logging

logger = logging.getLogger(__name__)


class LogMonitor:
    """Tails a JSON log file and yields parsed log entries."""

    def __init__(self, log_path, poll_interval=0.1, rotation_check_interval=5):
        """
        Args:
            log_path: Path to the nginx JSON access log
            poll_interval: How long to sleep when no new lines (seconds)
            rotation_check_interval: How often to check for log rotation (seconds)
        """
        self.log_path = log_path
        self.poll_interval = poll_interval
        self.rotation_check_interval = rotation_check_interval
        self._file = None
        self._inode = None
        self._last_rotation_check = 0

    def _open(self):
        """Open the log file and seek to the end."""
        self._file = open(self.log_path, "r")
        self._file.seek(0, 2)  # 0 bytes from end-of-file = end of file
        self._inode = os.fstat(self._file.fileno()).st_ino
        logger.info(f"Opened {self.log_path} (inode {self._inode})")

    def _check_rotation(self):
        """Check if the log file was rotated (replaced with a new file).

        If so, close our current handle and reopen the new file.
        """
        now = time.time()
        if now - self._last_rotation_check < self.rotation_check_interval:
            return  # Don't check too often

        self._last_rotation_check = now

        try:
            current_inode = os.stat(self.log_path).st_ino
            if current_inode != self._inode:
                logger.warning(
                    f"Log rotated! Old inode {self._inode}, new {current_inode}. "
                    "Reopening file."
                )
                self._file.close()
                self._open()
        except FileNotFoundError:
            # Log file disappeared (mid-rotation). Wait briefly.
            logger.warning(f"Log file {self.log_path} not found, waiting...")
            time.sleep(self.poll_interval)

    def tail(self):
        """Generator yielding parsed log entries as they're written.

        Yields:
            dict: Parsed log entry with fields like source_ip, status, path, etc.
        """
        self._open()

        while True:
            line = self._file.readline()

            if not line:
                # No new lines - sleep briefly, check for rotation, try again
                self._check_rotation()
                time.sleep(self.poll_interval)
                continue

            line = line.strip()
            if not line:
                continue  # Skip blank lines

            # Try to parse as JSON. Skip malformed lines but keep going.
            try:
                entry = json.loads(line)
                yield entry
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed log line: {e}")
                continue


def parse_status(entry):
    """Helper: extract HTTP status code as int."""
    try:
        return int(entry.get("status", 0))
    except (ValueError, TypeError):
        return 0


def is_error_status(status_code):
    """Returns True if status is 4xx or 5xx."""
    return 400 <= status_code < 600


# Quick standalone test - run this file directly to test log tailing
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python monitor.py <path-to-log-file>")
        sys.exit(1)

    monitor = LogMonitor(sys.argv[1])
    print(f"Tailing {sys.argv[1]} (Ctrl+C to stop)...")
    try:
        for entry in monitor.tail():
            print(f"  {entry.get('source_ip', '?')} {entry.get('method', '?')} "
                  f"{entry.get('path', '?')} -> {entry.get('status', '?')}")
    except KeyboardInterrupt:
        print("\nStopped.")
