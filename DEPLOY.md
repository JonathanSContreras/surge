# Deploying Surge — HCU server + Mac mini

Split deployment. The two hosts have different jobs and only one of them scans:

| | HCU server | Mac mini |
|---|---|---|
| **Runs** | Postgres (Docker) + Ollama (native) | FastAPI + agent graph + nmap, Next.js dashboard |
| **Holds** | all scan state, the LLM | the scan artifacts for runs in progress |
| **Needs** | to be reachable on the tailnet | to sit on the network you intend to scan |
| **Docker?** | yes, for Postgres | **no** — see "Why the Mac mini can't use Docker" |

They find each other over Tailscale. Nothing here is exposed to the campus network.

> **Read this before wiring anything:** the XGBoost scorer and the SBERT
> embedding model are *not* on the HCU server, despite it being "the model box."
> `execution/cvss_regessor_model.py` loads `model/xgb_regressor.json` in-process
> at import, and `governance/xgboost_data_cleaning.py` loads
> `SentenceTransformer("all-MiniLM-L6-v2")` the same way. Both run inside the
> Python backend, so both live on the **Mac mini**. Only the LLM can be remote,
> because it's the only one behind an HTTP endpoint. The 37 MB `data/cve.csv` is
> *training* data and isn't needed at inference — it only has to be wherever you
> retrain.

---

## Why the Mac mini can't use Docker

The old single-host `docker-compose.yml` ran the backend with
`network_mode: host` + `cap_add: NET_RAW`. Both are Linux-kernel features.
On macOS, Docker runs containers inside a Linux VM, so a "host-networked"
container is host-networked *to the VM*, not to the Mac. nmap would scan the
VM's private network and come back with one or two phantom hosts.

So on the Mac mini the backend runs natively, as root, under launchd. The
frontend could go either way; it runs natively too, for one less moving part.

---

# Part A — HCU server (Postgres + Ollama)

## A1. Install Docker

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER    # log out/in for this to take effect
```

## A2. Start Postgres

```bash
tailscale ip -4          # note this — it goes in HCU_TAILSCALE_IP

cd /path/to/surge
cp .env.example .env
nano .env                # fill in POSTGRES_PASSWORD and HCU_TAILSCALE_IP

docker compose -f docker-compose.hcu.yml up -d
docker compose -f docker-compose.hcu.yml ps
```

Postgres binds to the Tailscale IP only. Do **not** change this to `0.0.0.0` —
that publishes the database to the campus network.

## A3. Open Ollama to the tailnet

Ollama binds `127.0.0.1:11434` by default, so the Mac mini can't reach it.

```bash
sudo systemctl edit ollama
```

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
ollama pull gpt-oss:20b
curl http://$(tailscale ip -4):11434/api/tags     # must respond, not just localhost
```

`0.0.0.0` is acceptable here where it wasn't for Postgres: check that the
campus firewall isn't forwarding 11434, and rely on the tailnet ACL. If you want
it airtight, bind to the Tailscale IP explicitly instead.

## A4. Verify from the Mac mini

Run these **on the Mac mini** — they're the whole contract between the hosts:

```bash
nc -vz hcu-server.your-tailnet.ts.net 5432
curl http://hcu-server.your-tailnet.ts.net:11434/api/tags
```

Both must succeed before Part B is worth attempting.

---

# Part B — Mac mini (scanner + site)

## B1. Prerequisites

```bash
brew install nmap python@3.12 node
sudo tailscale up
tailscale ip -4          # note this — it goes in NEXT_PUBLIC_API_URL
```

## B2. Backend

```bash
cd /opt/surge/surge-ai              # adjust to wherever the repo lives
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-api.txt

cp ../.env .env                     # backend reads ./.env from surge-ai/
```

Confirm the DB and LLM point at the HCU server, not localhost:

```bash
grep -E 'DATABASE_URL|TAILSCALE_URL' .env
```

Smoke-test before installing the service — running in the foreground surfaces
connection errors that launchd would bury in a log file:

```bash
sudo .venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000
# another terminal:
curl http://localhost:8000/health
```

`sudo` is not optional — see B4.

## B3. Frontend

`NEXT_PUBLIC_*` are compiled into the bundle, so the address has to be right
*before* you build. Write `.env.local` with only the two public vars — do **not**
copy the root `.env` here. It carries `POSTGRES_PASSWORD` and `OPENROUTER_API_KEY`, which have
no business sitting in the frontend's working directory:

```bash
cd /opt/surge/web-page
npm ci

cat > .env.local <<'EOF'
NEXT_PUBLIC_API_URL=http://macmini.your-tailnet.ts.net:8000
NEXT_PUBLIC_WS_URL=ws://macmini.your-tailnet.ts.net:8000
EOF

npm run build
npm start -- --hostname 0.0.0.0 --port 3000
```

Dashboard: `http://macmini.your-tailnet.ts.net:3000`

## B4. Install as services

```bash
sudo cp deploy/macmini/com.surge.api.plist /Library/LaunchDaemons/
sudo cp deploy/macmini/com.surge.web.plist /Library/LaunchDaemons/
sudo nano /Library/LaunchDaemons/com.surge.web.plist    # set UserName
# both plists assume /opt/surge — edit the paths if the repo lives elsewhere

sudo launchctl load -w /Library/LaunchDaemons/com.surge.api.plist
sudo launchctl load -w /Library/LaunchDaemons/com.surge.web.plist
sudo launchctl list | grep surge
```

**The API daemon runs as root on purpose.** `config/constants.py` allows `-sS`
and `-O` in the medium and high sanitizer tiers, and the recon agent escalates
to `-A --script=vuln` on Deep scans. All of those need raw sockets. Without root
nmap exits with "You requested a scan type which requires root privileges" and
discovery returns nothing — which looks exactly like "the network is empty."

macOS may also prompt for Full Disk Access the first time the daemon writes to
`report/`. Grant it under System Settings → Privacy & Security.

---

## Operations

```bash
# HCU server
docker compose -f docker-compose.hcu.yml logs -f db
docker compose -f docker-compose.hcu.yml down        # data persists in the pgdata volume

# Mac mini
tail -f /var/log/surge-api.err.log
sudo launchctl kickstart -k system/com.surge.api     # restart after a code change
sudo launchctl kickstart -k system/com.surge.web     # only serves; rebuild first if env changed
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
  instead of throwing. If the tailnet drops mid-scan, the scan still fails —
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
