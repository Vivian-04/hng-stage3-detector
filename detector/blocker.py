"""
blocker.py - iptables wrapper for banning IPs

Wraps iptables commands behind a clean interface.
Tracks bans in memory so we can list/query them without parsing iptables output.

Author: Vivian Nduka
"""

import subprocess
import threading
import time
import logging

logger = logging.getLogger(__name__)


class IPBlocker:
    """Bans/unbans IPs using iptables INPUT chain DROP rules."""

    def __init__(self, chain="INPUT"):
        """
        Args:
            chain: iptables chain to operate on (INPUT for incoming traffic)
        """
        self.chain = chain

        # In-memory state: ip -> dict with metadata
        # {
        #   "banned_at": timestamp,
        #   "offense_count": int (1=first ban, 2=second, etc.),
        #   "duration_seconds": int,
        #   "permanent": bool,
        #   "condition": str (what triggered the ban)
        # }
        self._bans = {}
        self._lock = threading.Lock()

    def ban(self, ip, duration_seconds, condition, permanent=False):
        """Add an iptables DROP rule for the given IP.

        Returns True if newly banned, False if already banned.
        """
        with self._lock:
            if ip in self._bans:
                logger.info(f"IP {ip} already banned, skipping")
                return False

            # Run the iptables command
            cmd = ["sudo", "iptables", "-I", self.chain, "-s", ip, "-j", "DROP"]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    logger.error(
                        f"iptables ban for {ip} failed: {result.stderr.strip()}"
                    )
                    return False
            except subprocess.TimeoutExpired:
                logger.error(f"iptables ban for {ip} timed out")
                return False
            except Exception as e:
                logger.exception(f"iptables ban for {ip} crashed: {e}")
                return False

            # Track the ban
            offense_count = 1
            self._bans[ip] = {
                "banned_at": time.time(),
                "offense_count": offense_count,
                "duration_seconds": duration_seconds,
                "permanent": permanent,
                "condition": condition,
            }
            logger.warning(
                f"BANNED {ip} for {duration_seconds}s (condition: {condition})"
            )
            return True

    def unban(self, ip):
        """Remove the iptables DROP rule for the given IP.

        Returns True if successfully unbanned, False if not found / failed.
        """
        with self._lock:
            if ip not in self._bans:
                logger.warning(f"unban: {ip} not in ban list")
                return False

            cmd = ["sudo", "iptables", "-D", self.chain, "-s", ip, "-j", "DROP"]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    # Rule might already be gone; log but still remove from tracking
                    logger.warning(
                        f"iptables unban for {ip} returned non-zero: "
                        f"{result.stderr.strip()}"
                    )
            except subprocess.TimeoutExpired:
                logger.error(f"iptables unban for {ip} timed out")
                return False
            except Exception as e:
                logger.exception(f"iptables unban for {ip} crashed: {e}")
                return False

            # Update tracking - keep the offense count for backoff schedule
            offense_count = self._bans[ip]["offense_count"]
            del self._bans[ip]
            # We'll store offense history separately for backoff
            self._record_unban(ip, offense_count)

            logger.info(f"UNBANNED {ip}")
            return True

    def _record_unban(self, ip, offense_count):
        """Track offense count for an unbanned IP (used for backoff scheduling)."""
        # In-memory only; lost on restart but the kernel ban list persists
        if not hasattr(self, "_offense_history"):
            self._offense_history = {}
        self._offense_history[ip] = offense_count

    def get_offense_count(self, ip):
        """Return the number of times this IP has been banned previously."""
        if not hasattr(self, "_offense_history"):
            return 0
        return self._offense_history.get(ip, 0)

    def increment_offense_count(self, ip):
        """Bump offense count for an IP (called when re-banning)."""
        with self._lock:
            if ip in self._bans:
                self._bans[ip]["offense_count"] += 1

    def is_banned(self, ip):
        """Check if an IP is currently banned (according to our records)."""
        with self._lock:
            return ip in self._bans

    def list_bans(self):
        """Return current bans as a list of dicts."""
        with self._lock:
            now = time.time()
            result = []
            for ip, info in self._bans.items():
                age = now - info["banned_at"]
                remaining = info["duration_seconds"] - age
                result.append({
                    "ip": ip,
                    "banned_at": info["banned_at"],
                    "age_seconds": age,
                    "duration_seconds": info["duration_seconds"],
                    "remaining_seconds": remaining,
                    "offense_count": info["offense_count"],
                    "permanent": info["permanent"],
                    "condition": info["condition"],
                })
            return result

    def list_expired(self):
        """Return list of bans that have expired (ready to unban).

        Permanent bans never appear here.
        """
        with self._lock:
            now = time.time()
            expired = []
            for ip, info in self._bans.items():
                if info["permanent"]:
                    continue
                age = now - info["banned_at"]
                if age >= info["duration_seconds"]:
                    expired.append(ip)
            return expired


# ============================================================
# Standalone test
# ============================================================
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    # Use a fake test IP that won't affect real traffic
    TEST_IP = "192.0.2.42"  # TEST-NET-1 reserved range

    print(f"\nStandalone blocker test (using {TEST_IP})\n")

    blocker = IPBlocker()

    print("1. Initial state - listing bans (should be empty):")
    print(f"   {blocker.list_bans()}\n")

    print(f"2. Banning {TEST_IP} for 10 seconds...")
    success = blocker.ban(TEST_IP, duration_seconds=10, condition="test")
    print(f"   Success: {success}\n")

    print("3. Verifying iptables rule was added:")
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True,
    )
    if TEST_IP in result.stdout:
        print(f"   ✅ Found {TEST_IP} in iptables INPUT chain\n")
    else:
        print(f"   ❌ {TEST_IP} NOT in iptables output!")
        print(result.stdout)

    print("4. is_banned check:")
    print(f"   {TEST_IP} banned? {blocker.is_banned(TEST_IP)}")
    print(f"   1.1.1.1 banned? {blocker.is_banned('1.1.1.1')}\n")

    print(f"5. Unbanning {TEST_IP}...")
    success = blocker.unban(TEST_IP)
    print(f"   Success: {success}\n")

    print("6. Verifying iptables rule was removed:")
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True,
    )
    if TEST_IP not in result.stdout:
        print(f"   ✅ {TEST_IP} no longer in iptables INPUT chain\n")
    else:
        print(f"   ❌ {TEST_IP} still in iptables!")

    print("7. Final state:")
    print(f"   Active bans: {blocker.list_bans()}")
    print(f"   Offense count for {TEST_IP}: {blocker.get_offense_count(TEST_IP)}")

    print("\nTest complete!")
