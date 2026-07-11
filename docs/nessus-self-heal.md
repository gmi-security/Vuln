# Nessus "download-failed" — permanent self-heal setup

The recurring `download-failed` scanner status means Nessus itself failed to
download/compile its plugin feed. The console can only observe it (it alerts
via Slack/email when the scanner degrades) — the fix has to run on the Nessus
host. This sets up a watchdog that detects the state and repairs it
automatically, forever.

## Why it keeps happening

In order of likelihood on a small droplet:

1. **Low disk space** — the plugin feed needs ~5 GB free in `/opt/nessus`
   during compile. When the disk creeps past that, every feed update fails.
2. **Low RAM during plugin compile** — compilation spikes memory; on a 2–4 GB
   box with no swap the process gets OOM-killed and the feed is left broken.
3. **Stale registration** — the activation code loses its binding and fetches
   start 401-ing until re-registered.
4. **Transient network failure mid-download** — Nessus does not always retry
   cleanly; it parks in `download-failed` until something kicks it.

## One-time hardening (do these once)

```bash
# 1. Swap file if RAM < 8 GB (prevents OOM during plugin compile)
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 2. Check free space — want 5 GB+ headroom
df -h /opt/nessus
```

## The watchdog (install on the Nessus host)

`/usr/local/bin/nessus-heal.sh`:

```bash
#!/usr/bin/env bash
# Detects a wedged Nessus plugin feed and repairs it. Safe to run repeatedly.
set -u
LOG="/var/log/nessus-heal.log"
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

STATUS=$(curl -sk --max-time 15 https://localhost:8834/server/status \
  | sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p')

if [ "$STATUS" = "ready" ] || [ "$STATUS" = "loading" ]; then
  exit 0  # healthy or busy compiling — leave it alone
fi

echo "$(ts) status='$STATUS' — healing" >> "$LOG"

# Free-space guard: refuse to compile into a full disk (fix that first).
FREE_GB=$(df -BG --output=avail /opt/nessus | tail -1 | tr -dc '0-9')
if [ "${FREE_GB:-0}" -lt 5 ]; then
  echo "$(ts) ABORT: only ${FREE_GB}G free in /opt/nessus — clean disk first" >> "$LOG"
  exit 1
fi

systemctl stop nessusd
/opt/nessus/sbin/nessuscli update --all >> "$LOG" 2>&1
systemctl start nessusd
echo "$(ts) heal complete — nessusd restarted, plugins recompiling" >> "$LOG"
```

```bash
sudo chmod +x /usr/local/bin/nessus-heal.sh
```

`/etc/systemd/system/nessus-heal.service`:

```ini
[Unit]
Description=Detect and repair a wedged Nessus plugin feed

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nessus-heal.sh
```

`/etc/systemd/system/nessus-heal.timer`:

```ini
[Unit]
Description=Run the Nessus feed heal check every 30 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nessus-heal.timer
systemctl list-timers nessus-heal.timer   # verify it's armed
```

## If the heal loop logs 401s from nessuscli

The activation code needs re-registering (do NOT do this while healthy — it
forces a full feed re-download):

```bash
sudo /opt/nessus/sbin/nessuscli fetch --register <ACTIVATION-CODE>
sudo systemctl restart nessusd
```

## What the console does now

The vuln console probes the scanner hourly and sends a Slack/email ops alert
on the transition to degraded (and again on recovery), so even if the
watchdog can't self-repair (disk full, dead activation), a human hears about
it within the hour instead of noticing weeks of empty scans.
