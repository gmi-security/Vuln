# Nessus scanner reliability — incident notes + permanent self-heal

This documents an actual incident (2026-07-11/12) on the GMI Nessus scanner
(`SOC-Nessus-Scanner`, `137.184.89.60`, Debian 12, 4 vCPU / 16 GB / 200 GB)
and the watchdog installed to stop it recurring unattended. Update this file
if a future incident reveals another root cause — treat it as the real
runbook, not aspirational documentation.

## What actually happened, in order

1. Scanner reported `status: "download-failed"` for an unknown period —
   the vuln console showed `reachable: true, ready: false` and every Nessus
   sync silently returned 0 findings.
2. `nessuscli update --all` revealed the real cause: `HTTP/1.1 401
   Unauthorized` on every plugin/license fetch, even though the license
   itself was NOT expired (`License Expiration: August 20, 2026` in the
   web UI) and the activation code was correctly formatted. Clock skew was
   ruled out (`timedatectl status` showed synchronized, NTP active).
   **Fix**: `nessuscli fetch --register <the-same-activation-code>` forced
   a fresh handshake and cleared the 401s immediately — the stored auth
   token/session had simply gone stale independent of the license.
3. The plugin feed then updated fine, but **Nessus Core Components**
   failed to install: `[warn] Could not create file
   /opt/nessus/sbin/nessusd` (and every other core binary/lib). Root
   cause: `/opt/nessus/var/nessus/tmp` was mounted as its own `tmpfs` with
   `noexec` (a deliberate hardening choice by whoever set up this box),
   which blocks the self-test binary (`nasl`) the updater must execute
   from that path as part of installing new core components.
   **Fix**: edit the `noexec` → `exec` in the one fstab line for that
   mount, remount live, retry.
4. The interrupted update then left the box in a genuinely broken state —
   `nessusd`, `nessuscli`, `nasl`, `openssl`, and the shared libs were all
   *missing* (deleted as step one of an atomic replace, never rewritten).
   `dpkg` still listed `nessus 10.11.2` as installed even though the files
   were gone. Retrying the online updater risked repeating the same
   failure.
   **Fix**: a copy of the original installer,
   `/root/Nessus-10.11.2-debian10_amd64.deb`, was still on the box.
   `dpkg -i` against it force-reinstalled every tracked file from a known
   local copy in one shot — independent of network, licensing, or the
   updater's own logic. This is the fastest recovery path and doesn't
   require downloading anything.
5. After reinstall, `engine_status.progress` visibly *dropped* (e.g. from
   93% to 25%) before climbing back to 100% — that's a full plugin
   recompile starting over after the core reinstall, not a regression.
   Confirm it's alive rather than hung via `ps aux | grep nessusd` (high
   `%CPU`, growing CPU time) or `journalctl -u nessusd -f`.

None of this was disk space or RAM — this box had 66 GB free and 16 GB RAM
the whole time. Don't assume it's resource exhaustion before checking the
actual error text; `nessuscli update --all`'s stderr names the real cause
almost every time.

## One-time hardening (do these once per box)

```bash
# Swap only if RAM < 8 GB — this box has 16 GB and does not need it.
free -h
# if under 8G total:
#   sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
#   sudo mkswap /swapfile && sudo swapon /swapfile
#   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Disk headroom — want 5 GB+ free in /opt/nessus.
df -h /opt/nessus

# Confirm the tmp mount is NOT noexec (breaks core-component installs).
grep nessus/tmp /etc/fstab
findmnt /opt/nessus/var/nessus/tmp
# if it shows "noexec":
#   sudo sed -i '/nessus\/tmp/s/noexec/exec/' /etc/fstab
#   sudo systemctl daemon-reload
#   sudo mount -o remount,exec /opt/nessus/var/nessus/tmp

# Keep the original installer .deb around — it's the fastest recovery
# path if a future update leaves core binaries half-installed. This box
# already has one at /root/Nessus-10.11.2-debian10_amd64.deb; if it's
# ever missing, fetch a fresh copy from tenable.com/downloads/nessus
# (browser download + scp — the CDN gates behind a EULA click-through).

# Clock — Tenable's fetch auth is timestamp-signed; drift causes 401s
# that look identical to a real license problem.
timedatectl status   # want "System clock synchronized: yes"
```

## The watchdog (install on the Nessus host)

Deliberately conservative: it retries the ONE safe, routine fix (a plugin
update) automatically, but never touches registration/activation on its
own. An activation 401 needs a human — Tenable's license server should not
be hit on an unattended timer when the cause might be a real account
issue, since repeated automated auth attempts can look like abuse.

`/usr/local/bin/nessus-heal.sh`:

```bash
#!/usr/bin/env bash
# Detects a wedged Nessus scanner and retries the routine fix (plugin
# update). Does NOT auto-touch registration — see header note above.
set -u
LOG="/var/log/nessus-heal.log"
STATE_DIR="/var/lib/nessus-heal"
FAIL_COUNT_FILE="$STATE_DIR/consecutive-failures"
MAX_AUTO_RETRIES=2   # after this many, stop and wait for a human

mkdir -p "$STATE_DIR"
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

STATUS=$(curl -sk --max-time 15 https://localhost:8834/server/status \
  | sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p' | head -1)

if [ "$STATUS" = "ready" ] || [ "$STATUS" = "loading" ]; then
  echo 0 > "$FAIL_COUNT_FILE"
  exit 0
fi

FAILS=$(cat "$FAIL_COUNT_FILE" 2>/dev/null || echo 0)
if [ "$FAILS" -ge "$MAX_AUTO_RETRIES" ]; then
  echo "$(ts) status='$STATUS' — already retried $FAILS time(s), holding off. Needs a human: check 'nessuscli fetch --check' and the Tenable portal." >> "$LOG"
  exit 1
fi

echo "$(ts) status='$STATUS' — attempting heal (try $((FAILS+1))/$MAX_AUTO_RETRIES)" >> "$LOG"

FREE_GB=$(df -BG --output=avail /opt/nessus | tail -1 | tr -dc '0-9')
if [ "${FREE_GB:-0}" -lt 5 ]; then
  echo "$(ts) ABORT: only ${FREE_GB}G free in /opt/nessus — clean disk first" >> "$LOG"
  exit 1
fi

UPDATE_OUT=$(/opt/nessus/sbin/nessuscli update --all 2>&1)
echo "$UPDATE_OUT" >> "$LOG"

if echo "$UPDATE_OUT" | grep -qE "401 Unauthorized|not configured to receive updates"; then
  echo "$(ts) AUTH FAILURE — Tenable rejected the activation code. Not retrying automatically: check portal.tenable.com, or force a fresh handshake with 'nessuscli fetch --register <code>' (same code is fine — it re-authenticates, doesn't need to change)." >> "$LOG"
  echo $((FAILS+1)) > "$FAIL_COUNT_FILE"
  exit 1
fi

if echo "$UPDATE_OUT" | grep -q "Could not create file"; then
  echo "$(ts) CORE INSTALL FAILURE — binaries may now be missing. Do NOT let this timer retry blindly. Recover with: dpkg -i /root/Nessus-*.deb (restores from local package copy)." >> "$LOG"
  echo $((FAILS+1)) > "$FAIL_COUNT_FILE"
  exit 1
fi

systemctl restart nessusd
echo "$(ts) heal attempt complete — nessusd restarted, plugins recompiling" >> "$LOG"
echo $((FAILS+1)) > "$FAIL_COUNT_FILE"
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
tail -f /var/log/nessus-heal.log          # watch it work over time
```

To clear the backoff after fixing something manually (registration, a
core reinstall):

```bash
echo 0 | sudo tee /var/lib/nessus-heal/consecutive-failures
```

## Manual recovery cheat sheet (if the watchdog can't self-heal)

```bash
# Auth/registration rejected (401 on every fetch):
sudo /opt/nessus/sbin/nessuscli fetch --check          # confirm the symptom
sudo /opt/nessus/sbin/nessuscli fetch --register <CODE> # forces a fresh handshake
sudo systemctl restart nessusd

# Core components fail to install ("Could not create file ..."):
ls /root/*.deb                                           # find a local installer copy
sudo dpkg -i /root/Nessus-<version>-debian10_amd64.deb   # force full reinstall
sudo systemctl daemon-reload
sudo systemctl start nessusd

# Confirm healthy:
curl -sk https://localhost:8834/server/status            # want "status":"ready"
```

## What the console does regardless

The vuln console probes the scanner hourly and sends a Slack/email ops
alert on the transition to degraded (and again on recovery), so even when
the watchdog correctly declines to auto-fix something (auth, a broken
install), a human hears about it within the hour instead of noticing weeks
of silently empty scans.
