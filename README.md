# HNG Stage 3 — Anomaly Detection Engine

A real-time HTTP traffic anomaly detector and DDoS detection tool built alongside a Nextcloud Docker stack.

## Live URLs
- **Metrics Dashboard:** http://13.63.158.14:8080
- **Server IP:** 13.63.158.14

## GitHub Repository
https://github.com/Vivian-04/hng-stage3-detector

## Blog Post
https://medium.com/@ifechukwudenduka/title-how-i-built-a-real-time-ddos-detection-tool-from-scratch-as-a-complete-beginner-58dae59147db

## Language Choice
**Python** — chosen for its readability, rich standard library, and ease of working with system tools like iptables and file tailing. Perfect for a daemon that needs to be maintainable and debuggable.

## How the Sliding Window Works
The sliding window uses Python's `collections.deque`. Every incoming request is timestamped and appended to two deques — one per IP, one global. On each new request, entries older than 60 seconds are popped from the left of the deque. The current request rate is simply the length of the deque (number of requests in the last 60 seconds). This gives a true rolling window with no stale data.

## How the Baseline Works
- **Window size:** 30 minutes (1800 seconds) of per-second request counts
- **Recalculation interval:** Every 60 seconds
- **Storage:** Per-hour slots so the detector prefers the current hour's data when enough samples exist
- **Floor values:** `floor_mean=1.0`, `floor_stddev=1.0` to avoid division-by-zero on quiet periods
- Mean and standard deviation are recomputed every 60 seconds in a background thread

## Detection Logic
An anomaly is flagged when either condition fires first:
1. **Z-score > 3.0** — current rate is more than 3 standard deviations above the mean
2. **Rate > 5x the baseline mean** — fires even when stddev is low
3. **Error surge** — if an IP's 4xx/5xx rate is 3x the baseline error rate, thresholds tighten automatically (z > 2.0 or rate > 3x mean)

## How iptables Blocks an IP
When a per-IP anomaly is detected, the blocker runs:
iptables -I INPUT -s <ip> -j DROP
This inserts a DROP rule at the top of the INPUT chain, silently discarding all packets from that IP. Bans follow a backoff schedule: 10 min → 30 min → 2 hours → permanent after 4 offenses. Every ban and unban triggers a Slack notification and audit log entry.

## Setup Instructions (Fresh VPS)

### 1. Install dependencies
```bash
sudo apt update && sudo apt install -y docker.io docker-compose python3 python3-pip git
```

### 2. Clone the repo
```bash
git clone https://github.com/Vivian-04/hng-stage3-detector.git
cd hng-stage3-detector
```

### 3. Configure
```bash
cp detector/config.example.yaml detector/config.yaml
nano detector/config.yaml  # Add your Slack webhook URL
```

### 4. Start the Docker stack
```bash
docker-compose up -d
```

### 5. Install Python dependencies
```bash
sudo pip3 install -r detector/requirements.txt --break-system-packages
```

### 6. Create logs directory and fix permissions
```bash
mkdir -p logs
sudo chown -R $USER:$USER logs
sudo chown -R $USER:$USER /var/lib/docker/volumes/HNG-nginx-logs/
```

### 7. Run the detector
```bash
sudo nohup python3 detector/main.py > logs/output.log 2>&1 &
```

### 8. View the dashboard
Open http://your-server-ip:8080 in your browser.

## Repository Structure
detector/
main.py           # Orchestrator
monitor.py        # Log tailer and parser
baseline.py       # Rolling baseline with hourly slots
detector.py       # Anomaly detection logic
blocker.py        # iptables ban/unban
unbanner.py       # Backoff unban scheduler
notifier.py       # Slack alerts
dashboard.py      # Flask metrics dashboard
config.example.yaml
requirements.txt
nginx/
nginx.conf
screenshots/
README.md
docker-compose.yml

