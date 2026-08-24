# Deploying Surge to the Mac mini

Everything runs on one machine: an Apple M2 Mac mini with 8 GB of unified
memory. Backend, agent graph, nmap, Postgres, the local fallback model, and the
Next.js dashboard.

| Component | How it runs | Why |
|---|---|---|
| FastAPI + agent graph + nmap | native, **as root**, launchd | nmap needs raw sockets; see [Why root](#why-the-api-runs-as-root) |
| Postgres | native, Homebrew | Docker Desktop's Linux VM costs 1-2 GB we don't have |
| Next.js dashboard | native, launchd | one less moving part |
| Ollama (fallback model only) | native | only used when OpenRouter credits run out |

> **An earlier plan split this across an HCU Linux server and the Mac mini.**
> That server's VM never came up. Nothing is split any more — if you find a
> reference to `hcu-server`, `SERVER_ADDR`, or `docker-compose.hcu.yml`, it is
> stale and predates 2026-08-24.

## Why Docker is not used for the backend

`network_mode: host` and `cap_add: NET_RAW` are Linux-kernel features. On macOS,
Docker runs containers inside a Linux VM, so a "host-networked" container is
host-networked *to the VM*, not to the Mac. nmap would scan the VM's private
network and report one or two phantom hosts. The same reasoning rules out
containerising Postgres here — not correctness, just the VM's memory cost on an
8 GB box.

## The 8 GB memory budget

Measured, not guessed. The Python stack (torch + sentence-transformers + MiniLM
+ the XGBoost booster) peaks at **485 MB** resident.

| | |
|---|---|
| macOS baseline | ~2.5 GB |
| Backend (FastAPI + ML stack) | ~0.7-0.9 GB |
| Postgres | ~0.3 GB |
| Next.js production server | ~0.2 GB |
| nmap mid-scan | ~0.1-0.3 GB |
| **Headroom for a local model** | **~4 GB** |

That is why the local model is `qwen3:4b` (~2.5 GB at Q4_K_M) and not
`gpt-oss:20b` (~12-13 GB, does not fit at any quantisation).

---

# Setup

## 1. Prerequisites

`libomp` is not optional. XGBoost's macOS wheel links against `libomp.dylib`
at runtime, but it is a Homebrew system library rather than a pip dependency —
so `pip install xgboost` succeeds and then `import xgboost` fails with
"Library not loaded: @rpath/libomp.dylib". That takes down the whole CVSS
scoring path, and the failure only shows up mid-scan.

```bash
brew install nmap python@3.13 node postgresql@16 ollama libomp

# The address the dashboard will be reached at. Usually the LAN IP:
ipconfig getifaddr en0   # e.g. 10.10.160.55  — note this, the build needs it
```

## 2. Postgres

```bash
brew services start postgresql@16        # 'services', not 'postgres -D' — see note below
createuser -s surge
createdb -O surge surge
psql -d surge -c "ALTER USER surge WITH PASSWORD 'pick-something';"
psql -U surge -d surge -c "select version();"   # verify
```

Use `brew services start`, not a manual `pg_ctl`/`postgres` invocation. Only the
former registers a launchd job, and without it Postgres will not come back after
a reboot — which you will discover during the first power outage, not before.

The database stays on `localhost`. It needs no network exposure at all now that
nothing connects from another host.

## 3. Backend

```bash
cd /opt/surge/surge-ai              # adjust to wherever the repo lives
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-api.txt
cp ../.env.example .env
nano .env                           # fill in DATABASE_URL and OPENROUTER_API_KEY
```

Smoke-test in the foreground first — launchd would bury a connection error in a
log file:

```bash
sudo .venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000
curl http://localhost:8000/health   # {"status":"ok"}
```

The first start creates the schema. Confirm it actually did — this failed
silently in an earlier version and the fix is easy to regress:

```bash
psql -U surge -d surge -c "\dt"     # expect 6 tables, not "Did not find any relations"
```

## 4. Local fallback model

Only used when the OpenRouter balance drops below `SURGE_CREDIT_FLOOR`.

```bash
ollama serve &                      # binds 127.0.0.1:11434, which is all we need
ollama pull qwen3:4b
```

Keep thinking mode off. `MODEL_CONFIG["timeout"]` is 60 s and a reasoning trace
on this hardware will blow through it.

## 5. Dashboard

`NEXT_PUBLIC_*` are compiled into the bundle, so the address must be right
*before* you build. It must be an address **the browser can reach**, which
depends on where you view the dashboard from:

| Viewing from | Use |
|---|---|
| the Mac mini itself (monitor attached) | `http://localhost:8000` |
| a laptop on the same network | the mini's LAN IP, e.g. `http://10.10.160.55:8000` |
| off-site | a tailnet address, or whatever remote access you set up |

`localhost` only works if the browser is running *on the mini*. From any other
machine it resolves to that machine, and the dashboard will sit there failing to
fetch. Tailscale is entirely optional — it was only required back when the
backend lived on a second host.

Write `.env.local` with only the two public vars; do not copy the root `.env`,
which carries the Postgres password and the OpenRouter key:

```bash
cd /opt/surge/web-page
npm ci

cat > .env.local <<'EOF'
NEXT_PUBLIC_API_URL=http://10.10.160.55:8000
NEXT_PUBLIC_WS_URL=ws://10.10.160.55:8000
EOF

npm run build
npm start -- --hostname 0.0.0.0 --port 3000
```

Dashboard: `http://<that same address>:3000`

## 6. Install the services

```bash
sudo cp deploy/macmini/com.surge.api.plist      /Library/LaunchDaemons/
sudo cp deploy/macmini/com.surge.web.plist      /Library/LaunchDaemons/
sudo cp deploy/macmini/com.surge.schedule.plist /Library/LaunchDaemons/

# set UserName in the web and schedule plists; fix paths if not /opt/surge
sudo nano /Library/LaunchDaemons/com.surge.web.plist
sudo nano /Library/LaunchDaemons/com.surge.schedule.plist

sudo launchctl load -w /Library/LaunchDaemons/com.surge.api.plist
sudo launchctl load -w /Library/LaunchDaemons/com.surge.web.plist
sudo launchctl load -w /Library/LaunchDaemons/com.surge.schedule.plist
sudo launchctl list | grep surge
```

### Why the API runs as root

`config/constants.py` allows `-sS` and `-O` in the medium and high sanitiser
tiers, and the recon agent escalates to `--script=vuln` on the deepest tier. All
of those need raw sockets. Without root, nmap exits with "You requested a scan
type which requires root privileges" and discovery returns nothing — which looks
exactly like a quiet network rather than a permissions failure.

The web and schedule daemons do **not** need root and drop to a normal user via
`UserName`. Only the API is privileged.

`com.surge.api.plist` also sets `PATH` explicitly: launchd's default is
`/usr/bin:/bin:/usr/sbin:/sbin`, which does not include Homebrew's nmap.

## 7. The schedule

`com.surge.schedule.plist` runs a Quick scan at **09:00 and 15:00, Mon-Fri**
(10 firings/week). `deploy/macmini/scheduled_scan.py` gates each one:

1. **Overlap guard** — skips if a scan is already running. The slots are 6 h
   apart but a Deep scan runs 3-5 h, so they can collide. This is also why the
   scheduled type is `quick`.
2. **Credit check** — below `SURGE_CREDIT_FLOOR` (default $2), flips the API to
   offline so scans degrade to the local model rather than failing.
3. Only then does it POST the scan.

```bash
# dry-run it by hand before trusting the timer
sudo -u <user> /opt/surge/surge-ai/.venv/bin/python /opt/surge/deploy/macmini/scheduled_scan.py
tail -f /var/log/surge-schedule.log
```

Cost model behind the defaults: ~400 runs/yr against the OpenRouter balance,
`z-ai/glm-4.7` for analysis and `z-ai/glm-4.7-flash` for the JSON-only fast
tier. Re-check pricing before changing models; it moves.

## Power and unattended recovery

The Mac mini is expected to stay powered on continuously, so the goal here is
narrow: never sleep through a scan slot, and come back by itself if the building
loses power.

```bash
# Boot automatically when power is restored. THIS is the one that matters for a
# building outage — without it the mini stays off until someone presses the button.
sudo pmset -a autorestart 1

# Never sleep. An always-on box should not be sleeping at 09:00; if it does,
# launchd fires the job late (on wake) rather than on time.
sudo pmset -a sleep 0
sudo pmset -a disksleep 0

# Wake for network access, so you can still reach it over Tailscale.
sudo pmset -a womp 1

pmset -g            # verify: sleep 0, disksleep 0, autorestart 1, womp 1
```

Belt-and-braces, only useful if you decide to leave sleep enabled after all —
wake five minutes before each slot. Weekday codes are MTWRF (R = Thursday):

```bash
sudo pmset repeat wakeorpoweron MTWRF 08:55:00
```

### FileVault will defeat all of this

**Check `fdesetup status` on the Mac mini before relying on auto-restart.** With
FileVault enabled, a reboot halts at the unlock screen and the OS never finishes
starting, so no LaunchDaemon runs and no scan happens — the machine looks on but
Surge is dead until somebody types a password at the console. `autorestart` does
not help; it just gets you to the unlock prompt faster.

For a headless lab machine that has to recover on its own, FileVault needs to be
off. That is a real tradeoff — this box holds scan history and the OpenRouter key
in `surge-ai/.env` — so it is a decision to make deliberately, not by default. If
the data sensitivity means FileVault has to stay on, accept that power loss
requires a manual unlock and don't pretend the schedule is unattended.

### After a reboot, check these came back

```bash
sudo launchctl list | grep surge     # api, web, schedule
brew services list | grep postgres   # must be 'started', not 'none'
tail -20 /var/log/surge-schedule.log
```

The API and web daemons carry `RunAtLoad` + `KeepAlive`, so they return on their
own. Postgres only does if it was registered with `brew services start`, not
launched by hand.

## Operations

```bash
brew services list | grep postgres        # must say 'started'
tail -f /var/log/surge-api.err.log
tail -f /var/log/surge-schedule.log
sudo launchctl kickstart -k system/com.surge.api     # restart after a code change
sudo launchctl kickstart -k system/com.surge.web     # only serves; rebuild first if env changed
sudo launchctl kickstart -k system/com.surge.schedule
```

---

## Gotchas

- **Frontend env is build-time.** `NEXT_PUBLIC_API_URL` / `NEXT_PUBLIC_WS_URL`
  are compiled into the bundle. Changing them requires `npm run build` again;
  restarting the service will not pick them up.
- **`NEXT_PUBLIC_API_URL` is the Mac mini, not the HCU server.** The backend
  moved. This is the easiest thing to get backwards in the split layout.
- **The database is now across a network.** Both engines set `pool_pre_ping=True`
  so a connection idled out during a multi-hour Deep scan gets re-established
  instead of throwing. (Postgres is local now, so this is belt-and-braces.) If
  the database goes away mid-scan the scan still fails —
  it'll show up as `failed` on the next API start, via the stale-scan cleanup
  in `api/main.py`.
- **Scan artifacts live on the Mac mini.** `report/{timestamp}_{scan_id}/dashboard_data.json`
  is written locally and read back by `GET /topology`, which is what feeds live
  mode. Same box, so this works — but it means the artifacts are not backed up
  by the HCU server's `pgdata` volume. Only what's persisted to Postgres at scan
  completion survives a Mac mini rebuild.
- **`.env` must be readable by root** on the Mac mini, since the API daemon runs
  as root. If you keep the repo under a user home directory, check permissions.
- **First backend install is slow** — `requirements.txt` pulls torch and
  sentence-transformers.
