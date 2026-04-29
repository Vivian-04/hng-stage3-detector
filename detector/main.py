"""
main.py - Orchestrator for the HNG Stage 3 Anomaly Detector

Loads config, instantiates all modules, wires them together,
and runs the main detection loop.

Usage:
    python3 main.py [path/to/config.yaml]

Author: Vivian Nduka
"""

import os
import sys
import signal
import logging
import threading
from datetime import datetime
from pathlib import Path

import yaml

# Make sibling modules importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from monitor import LogMonitor, parse_status, is_error_status
from baseline import RollingBaseline, start_baseline_thread
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import Unbanner
from notifier import SlackNotifier
from dashboard import DashboardServer


# ============================================================
# Logging setup
# ============================================================

def setup_logging(audit_log_path):
    """Configure logging - console + system log file (NOT audit log).

    System logs (warnings, errors, info from modules) go to detector.log.
    Audit log is reserved exclusively for structured BAN/UNBAN/GLOBAL events
    via the AuditLogger class.
    """
    audit_dir = Path(audit_log_path).parent
    audit_dir.mkdir(parents=True, exist_ok=True)

    # System log goes to detector.log - NOT the audit log
    system_log_path = audit_dir / "detector.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Console handler - all logs visible while running
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    ))
    root.addHandler(console)

    # System log file - all warnings/errors/info from modules
    sys_handler = logging.FileHandler(system_log_path)
    sys_handler.setLevel(logging.INFO)
    sys_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    ))
    root.addHandler(sys_handler)


# ============================================================
# Audit logging helper
# ============================================================

class AuditLogger:
    """Writes structured audit log entries.

    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_path):
        self.log_path = log_path
        self._lock = threading.Lock()
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    def log(self, action, ip, condition="", rate="", baseline="", duration=""):
        """Write a single audit entry."""
        ts = datetime.utcnow().isoformat() + "Z"
        entry = (
            f"[{ts}] {action} {ip} | {condition} | "
            f"rate={rate} | baseline={baseline} | duration={duration}\n"
        )
        with self._lock:
            with open(self.log_path, "a") as f:
                f.write(entry)


# ============================================================
# Main detector application
# ============================================================

class DetectorApp:
    def __init__(self, config_path):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.config = None
        self.shutdown_event = threading.Event()

        # Module instances (created in setup())
        self.monitor = None
        self.baseline = None
        self.detector = None
        self.blocker = None
        self.unbanner = None
        self.notifier = None
        self.dashboard = None
        self.audit = None

    def load_config(self):
        """Load the YAML config file."""
        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)

    def setup(self):
        """Instantiate all modules and wire them together."""
        cfg = self.config

        # --- Audit logger first (other modules don't need it) ---
        self.audit = AuditLogger(cfg["audit"]["log_path"])
        self.audit.log("STARTUP", "-", condition="detector starting")

        # --- Slack notifier ---
        self.notifier = SlackNotifier(
            webhook_url=cfg["slack"]["webhook_url"],
            username=cfg["slack"].get("username", "HNG-Detector"),
            icon_emoji=cfg["slack"].get("icon_emoji", ":shield:"),
            async_dispatch=cfg["slack"].get("async_dispatch", True),
        )

        # --- Rolling baseline ---
        self.baseline = RollingBaseline(
            window_seconds=cfg["baseline"]["window_seconds"],
            recalc_interval=cfg["baseline"]["recalc_interval"],
            min_samples=cfg["baseline"]["min_samples"],
            floor_mean=cfg["baseline"]["floor_mean"],
            floor_stddev=cfg["baseline"]["floor_stddev"],
            use_hourly_slots=cfg["baseline"]["use_hourly_slots"],
        )

        # --- Anomaly detector ---
        self.detector = AnomalyDetector(
            baseline=self.baseline,
            window_seconds=cfg["window"]["size_seconds"],
            z_threshold=cfg["detection"]["z_score_threshold"],
            rate_multiplier=cfg["detection"]["rate_multiplier_threshold"],
            error_surge_multiplier=cfg["detection"]["error_surge_multiplier"],
            tightened_z=cfg["detection"]["tightened_z_threshold"],
            tightened_rate_multiplier=cfg["detection"]["tightened_rate_multiplier"],
            max_tracked_ips=cfg["window"]["max_tracked_ips"],
        )

        # --- iptables blocker ---
        self.blocker = IPBlocker(chain=cfg["blocker"]["iptables_chain"])

        # --- Unbanner with callback ---
        def unban_callback(ip, ban_info):
            """When unbanner releases an IP, send Slack alert + audit."""
            self.notifier.send_unban_alert(ip, ban_info)
            self.audit.log(
                "UNBAN", ip,
                condition=ban_info.get("condition", ""),
                duration=f"{ban_info.get('age_seconds', 0):.0f}s",
            )

        self.unbanner = Unbanner(
            blocker=self.blocker,
            detector=self.detector,
            unban_schedule_seconds=cfg["blocker"]["unban_schedule_seconds"],
            permanent_after_offense=cfg["blocker"]["permanent_after_offense"],
            check_interval=cfg["blocker"]["unbanner_interval"],
            on_unban_callback=unban_callback,
        )

        # --- Log monitor ---
        self.monitor = LogMonitor(
            log_path=cfg["log"]["access_log_path"],
            poll_interval=cfg["log"]["poll_interval"],
            rotation_check_interval=cfg["log"]["rotation_check_interval"],
        )

        # --- Dashboard ---
        self.dashboard = DashboardServer(
            detector=self.detector,
            baseline=self.baseline,
            blocker=self.blocker,
            host=cfg["dashboard"]["host"],
            port=cfg["dashboard"]["port"],
            refresh_ms=cfg["dashboard"]["refresh_ms"],
            top_ips_count=cfg["dashboard"]["top_ips_count"],
        )

        self.logger.info("All modules initialized")

    def start_background(self):
        """Start all background threads."""
        # 1. Baseline recalculation thread
        start_baseline_thread(
            self.baseline,
            self.config["baseline"]["recalc_interval"],
            self.shutdown_event,
        )
        self.logger.info("Baseline thread started")

        # 2. Unbanner thread
        self.unbanner.start()

        # 3. Dashboard thread
        self.dashboard.run_threaded()
        self.logger.info("Dashboard thread started")

    def handle_anomaly(self, anomaly):
        """Process a detected anomaly: ban, alert, audit."""
        a = anomaly
        rate_str = f"{a['rate']}/min"
        baseline_str = f"mean={a['baseline_mean']:.2f},stddev={a['baseline_stddev']:.2f}"

        if a["type"] == "global":
            # Global anomaly: alert only, no ban
            self.notifier.send_global_alert(
                current_rate=a["rate"],
                baseline_mean=a["baseline_mean"],
                baseline_stddev=a["baseline_stddev"],
                condition=a["condition"],
            )
            self.audit.log(
                "GLOBAL_ALERT", "-",
                condition=a["condition"],
                rate=rate_str,
                baseline=baseline_str,
            )
            self.logger.warning(
                f"GLOBAL ANOMALY: rate={a['rate']} cond={a['condition']}"
            )
            return

        # Per-IP anomaly: ban + alert
        ip = a["ip"]

        # Determine ban duration via backoff
        duration_seconds, is_permanent = self.unbanner.calculate_ban_for_ip(ip)

        # Apply ban
        success = self.blocker.ban(
            ip=ip,
            duration_seconds=duration_seconds,
            condition=a["condition"],
            permanent=is_permanent,
        )

        if not success:
            # Already banned - just bump offense count
            return

        # Send Slack alert
        self.notifier.send_ban_alert(
            ip=ip,
            condition=a["condition"],
            current_rate=a["rate"],
            baseline_mean=a["baseline_mean"],
            baseline_stddev=a["baseline_stddev"],
            duration_seconds=duration_seconds,
            permanent=is_permanent,
            tightened=a.get("tightened", False),
        )

        # Audit log
        duration_str = "PERMANENT" if is_permanent else f"{duration_seconds}s"
        self.audit.log(
            "BAN", ip,
            condition=a["condition"],
            rate=rate_str,
            baseline=baseline_str,
            duration=duration_str,
        )

        self.logger.warning(
            f"BAN: {ip} for {duration_str} (cond: {a['condition']})"
        )

    def run_main_loop(self):
        """The heart of the detector: tail logs and process each entry."""
        self.logger.info("Starting main detection loop")
        self.audit.log("MAIN_LOOP_START", "-")

        for entry in self.monitor.tail():
            if self.shutdown_event.is_set():
                break

            # Extract relevant fields
            ip = entry.get("source_ip", "").strip()
            if not ip or ip == "-":
                continue  # Skip lines with no IP

            status = parse_status(entry)
            is_error = is_error_status(status)

            # Update baseline (every request)
            self.baseline.record_request(is_error=is_error)

            # Check for anomalies
            anomalies = self.detector.process_request(ip, is_error=is_error)

            # Handle each anomaly
            for anomaly in anomalies:
                try:
                    self.handle_anomaly(anomaly)
                except Exception as e:
                    self.logger.exception(f"Failed to handle anomaly: {e}")

    def shutdown(self):
        """Clean shutdown of all components."""
        self.logger.info("Shutting down...")
        self.shutdown_event.set()

        if self.unbanner:
            self.unbanner.stop()
        if self.notifier:
            self.notifier.stop()

        if self.audit:
            self.audit.log("SHUTDOWN", "-")
        self.logger.info("Shutdown complete")


# ============================================================
# Entry point
# ============================================================

def main():
    # Determine config path (CLI arg or default)
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "config.yaml",
        )

    # Load config first to get audit log path
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    # Set up logging
    setup_logging(cfg["audit"]["log_path"])
    logger = logging.getLogger(__name__)
    logger.info(f"Starting HNG Stage 3 Detector with config: {config_path}")

    # Build and start the app
    app = DetectorApp(config_path)
    app.load_config()
    app.setup()
    app.start_background()

    # Install signal handlers for graceful shutdown
    def handle_signal(signum, frame):
        logger.info(f"Received signal {signum}")
        app.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Run main loop (blocks until shutdown)
    try:
        app.run_main_loop()
    except KeyboardInterrupt:
        logger.info("Caught keyboard interrupt")
    except Exception as e:
        logger.exception(f"Main loop crashed: {e}")
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
