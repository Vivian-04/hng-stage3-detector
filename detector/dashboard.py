"""
dashboard.py - Flask web dashboard for live metrics

Displays banned IPs, global request rate, top 10 source IPs, CPU/memory
usage, effective baseline mean/stddev, and uptime.

Auto-refreshes every config.dashboard.refresh_ms milliseconds (≤3000).

Author: Vivian Nduka
"""

import time
import threading
import logging
from datetime import datetime, timedelta

import psutil
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)


# HTML template - embedded so we don't need a templates/ directory
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HNG Stage 3 - Anomaly Detector Dashboard</title>
    <meta http-equiv="refresh" content="{{ refresh_seconds }}">
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }
        h1 {
            color: #58a6ff;
            border-bottom: 2px solid #30363d;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .header-meta {
            color: #8b949e;
            font-size: 13px;
            margin-bottom: 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }
        .card h2 {
            margin: 0 0 12px 0;
            font-size: 14px;
            text-transform: uppercase;
            color: #8b949e;
            letter-spacing: 1px;
        }
        .big-number {
            font-size: 36px;
            font-weight: bold;
            color: #58a6ff;
            margin: 4px 0;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            border-bottom: 1px solid #21262d;
        }
        .stat-row:last-child { border-bottom: none; }
        .stat-label { color: #8b949e; }
        .stat-value { color: #c9d1d9; font-weight: 500; }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 6px 8px;
            border-bottom: 1px solid #21262d;
        }
        th {
            color: #8b949e;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 600;
        }
        tr:hover { background: #1c2128; }
        .ip-rate { color: #f78166; font-family: monospace; }
        .ip-banned { color: #ff7b72; font-family: monospace; }
        .ip-normal { color: #7ee787; font-family: monospace; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge-ok { background: #1f6feb; color: white; }
        .badge-alert { background: #da3633; color: white; }
        .badge-warn { background: #f0883e; color: white; }
        .footer {
            text-align: center;
            color: #6e7681;
            font-size: 12px;
            margin-top: 30px;
        }
        .empty {
            color: #6e7681;
            font-style: italic;
            padding: 12px 0;
        }
    </style>
</head>
<body>
    <h1>:shield: HNG Stage 3 - Anomaly Detector</h1>
    <div class="header-meta">
        Last update: {{ last_update }} (UTC) | Auto-refresh every {{ refresh_seconds }}s
        | Uptime: {{ uptime }}
        | <span class="badge {% if global_alert %}badge-alert{% else %}badge-ok{% endif %}">
            {% if global_alert %}GLOBAL ANOMALY{% else %}NORMAL{% endif %}
        </span>
    </div>

    <div class="grid">
        <!-- Global Rate -->
        <div class="card">
            <h2>Global Request Rate</h2>
            <div class="big-number">{{ global_rate }}</div>
            <div class="stat-row">
                <span class="stat-label">Requests in last 60s</span>
                <span class="stat-value">{{ global_rate }}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Tracked IPs</span>
                <span class="stat-value">{{ tracked_ips }}</span>
            </div>
        </div>

        <!-- Baseline -->
        <div class="card">
            <h2>Effective Baseline</h2>
            <div class="stat-row">
                <span class="stat-label">Mean (req/sec)</span>
                <span class="stat-value">{{ baseline_mean }}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Std Deviation</span>
                <span class="stat-value">{{ baseline_stddev }}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Error Mean</span>
                <span class="stat-value">{{ error_mean }}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Status</span>
                <span class="stat-value">
                    {% if baseline_ready %}
                    <span class="badge badge-ok">READY</span>
                    {% else %}
                    <span class="badge badge-warn">LEARNING</span>
                    {% endif %}
                </span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Samples</span>
                <span class="stat-value">{{ baseline_samples }}</span>
            </div>
        </div>

        <!-- System Resources -->
        <div class="card">
            <h2>System Resources</h2>
            <div class="stat-row">
                <span class="stat-label">CPU Usage</span>
                <span class="stat-value">{{ cpu_pct }}%</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Memory Usage</span>
                <span class="stat-value">{{ mem_pct }}% ({{ mem_used }}M / {{ mem_total }}M)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Process RSS</span>
                <span class="stat-value">{{ process_rss }}M</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Process Threads</span>
                <span class="stat-value">{{ process_threads }}</span>
            </div>
        </div>
    </div>

    <div class="grid">
        <!-- Top 10 IPs -->
        <div class="card">
            <h2>Top 10 Source IPs (by current rate)</h2>
            {% if top_ips %}
            <table>
                <thead>
                    <tr><th>#</th><th>IP Address</th><th>Rate (60s)</th><th>Status</th></tr>
                </thead>
                <tbody>
                {% for entry in top_ips %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td class="{% if entry.banned %}ip-banned{% else %}ip-normal{% endif %}">{{ entry.ip }}</td>
                        <td class="ip-rate">{{ entry.rate }}</td>
                        <td>
                            {% if entry.banned %}
                            <span class="badge badge-alert">BANNED</span>
                            {% else %}
                            <span class="badge badge-ok">OK</span>
                            {% endif %}
                        </td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty">No traffic yet</div>
            {% endif %}
        </div>

        <!-- Banned IPs -->
        <div class="card">
            <h2>Currently Banned ({{ banned_count }})</h2>
            {% if banned_ips %}
            <table>
                <thead>
                    <tr><th>IP</th><th>Offense</th><th>Remaining</th><th>Condition</th></tr>
                </thead>
                <tbody>
                {% for ban in banned_ips %}
                    <tr>
                        <td class="ip-banned">{{ ban.ip }}</td>
                        <td>#{{ ban.offense_count }}</td>
                        <td>
                            {% if ban.permanent %}
                            <span class="badge badge-alert">PERM</span>
                            {% else %}
                            {{ ban.remaining_str }}
                            {% endif %}
                        </td>
                        <td title="{{ ban.condition }}">{{ ban.condition[:40] }}{% if ban.condition|length > 40 %}...{% endif %}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty">No active bans</div>
            {% endif %}
        </div>
    </div>

    <div class="footer">
        HNG Stage 3 - Anomaly Detection Engine | Vivian Nduka |
        <a href="/api/stats" style="color:#58a6ff;">JSON API</a>
    </div>
</body>
</html>
"""


class DashboardServer:
    """Flask app exposing live detector metrics."""

    def __init__(self,
                 detector,
                 baseline,
                 blocker,
                 host="0.0.0.0",
                 port=8080,
                 refresh_ms=2000,
                 top_ips_count=10):
        """
        Args:
            detector: AnomalyDetector instance
            baseline: RollingBaseline instance
            blocker: IPBlocker instance
            host: Bind address (0.0.0.0 = all interfaces)
            port: Port to listen on
            refresh_ms: Auto-refresh interval in milliseconds
            top_ips_count: How many top IPs to display
        """
        self.detector = detector
        self.baseline = baseline
        self.blocker = blocker
        self.host = host
        self.port = port
        self.refresh_ms = refresh_ms
        self.top_ips_count = top_ips_count
        self.start_time = time.time()

        self.app = Flask(__name__)
        self._process = psutil.Process()

        self._register_routes()

    def _register_routes(self):
        """Wire up Flask routes."""

        @self.app.route("/")
        def index():
            data = self._gather_stats()
            return render_template_string(DASHBOARD_HTML, **data)

        @self.app.route("/api/stats")
        def api_stats():
            return jsonify(self._gather_stats(json_safe=True))

        @self.app.route("/api/health")
        def api_health():
            return jsonify({"status": "ok"}), 200

    def _gather_stats(self, json_safe=False):
        """Collect all metrics into a single dict."""
        # Detector stats
        det_stats = self.detector.get_stats()

        # Baseline stats
        bl_stats = self.baseline.get_stats()

        # Bans
        bans = self.blocker.list_bans()

        # System stats
        cpu_pct = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()

        # Process stats
        proc_info = self._process.memory_info()

        # Decorate top IPs with banned status
        banned_set = {b["ip"] for b in bans}
        top_ips = []
        for entry in det_stats.get("top_ips", [])[:self.top_ips_count]:
            top_ips.append({
                "ip": entry["ip"],
                "rate": entry["rate"],
                "banned": entry["ip"] in banned_set,
            })

        # Format ban list
        banned_ips = []
        for b in bans:
            if b["permanent"]:
                rem_str = "PERM"
            else:
                rem = max(0, int(b["remaining_seconds"]))
                if rem > 3600:
                    rem_str = f"{rem // 3600}h{(rem % 3600) // 60}m"
                elif rem > 60:
                    rem_str = f"{rem // 60}m{rem % 60}s"
                else:
                    rem_str = f"{rem}s"
            banned_ips.append({
                "ip": b["ip"],
                "offense_count": b["offense_count"],
                "permanent": b["permanent"],
                "remaining_str": rem_str,
                "condition": b["condition"],
            })

        # Uptime
        uptime_seconds = time.time() - self.start_time
        uptime_str = self._format_uptime(uptime_seconds)

        return {
            "global_rate": det_stats.get("global_rate", 0),
            "tracked_ips": det_stats.get("tracked_ips", 0),
            "global_alert": det_stats.get("global_alert_active", False),
            "baseline_mean": f"{bl_stats['mean']:.2f}",
            "baseline_stddev": f"{bl_stats['stddev']:.2f}",
            "error_mean": f"{bl_stats['error_mean']:.2f}",
            "baseline_ready": bl_stats["is_ready"],
            "baseline_samples": bl_stats["samples"],
            "cpu_pct": f"{cpu_pct:.1f}",
            "mem_pct": f"{mem.percent:.1f}",
            "mem_used": int(mem.used / (1024 * 1024)),
            "mem_total": int(mem.total / (1024 * 1024)),
            "process_rss": int(proc_info.rss / (1024 * 1024)),
            "process_threads": self._process.num_threads(),
            "top_ips": top_ips,
            "banned_ips": banned_ips,
            "banned_count": len(banned_ips),
            "uptime": uptime_str,
            "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "refresh_seconds": self.refresh_ms / 1000,
        }

    def _format_uptime(self, seconds):
        """Format uptime as 'Xh Ym Zs'."""
        td = timedelta(seconds=int(seconds))
        days = td.days
        hours = td.seconds // 3600
        minutes = (td.seconds % 3600) // 60
        secs = td.seconds % 60

        parts = []
        if days: parts.append(f"{days}d")
        if hours or days: parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        return " ".join(parts)

    def run(self):
        """Start the Flask dev server (blocks)."""
        logger.info(f"Dashboard starting on http://{self.host}:{self.port}")
        # Use Flask's built-in server - fine for our scale
        self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

    def run_threaded(self):
        """Start Flask in a daemon thread (non-blocking)."""
        t = threading.Thread(
            target=self.run,
            daemon=True,
            name="dashboard",
        )
        t.start()
        return t


# ============================================================
# Standalone test
# ============================================================
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    sys.path.insert(0, ".")
    from baseline import RollingBaseline
    from detector import AnomalyDetector
    from blocker import IPBlocker

    print("Standalone dashboard test")
    print("Will start Flask server on port 8080")
    print("Open: http://<your-server-ip>:8080\n")

    # Create stubs with fake data
    bl = RollingBaseline(min_samples=10)
    bl.is_ready = True
    bl.mean = 5.2
    bl.stddev = 1.4
    bl.error_mean = 0.3

    det = AnomalyDetector(baseline=bl)
    # Simulate some traffic
    import random
    for _ in range(50):
        det.process_request(f"10.0.0.{random.randint(1, 5)}", is_error=False)

    blocker = IPBlocker()

    # Manually fake one ban for display
    blocker._bans["192.0.2.99"] = {
        "banned_at": time.time() - 120,  # 2 min ago
        "offense_count": 1,
        "duration_seconds": 600,
        "permanent": False,
        "condition": "z_score>3.0 (z=8.45)",
    }

    server = DashboardServer(
        detector=det,
        baseline=bl,
        blocker=blocker,
        port=8080,
        refresh_ms=2000,
    )

    print("Press Ctrl+C to stop\n")
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nStopped.")
