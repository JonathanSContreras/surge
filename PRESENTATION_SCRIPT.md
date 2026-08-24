# SURGE — Presentation Script
**Multi-Agent Network Analysis Tool**
*Brianna Hinds · Jonathan Contreras · Sean Moning · Taurean Muhammad*

---

## SLIDE 1 — Title
**"Multi-Agent Network Analysis Tool"**

> **[Whoever opens]**
> "Good [morning/afternoon]. We're here to present SURGE — a multi-agent network analysis tool we built as our capstone project. I'm [name], and with me are Brianna, Jonathan, Sean, and Taurean."

---

## SLIDE 2 — 3 Questions. One Answer.

> "Before we get into the technical details, we want to frame everything with three questions: **What** is SURGE, **How** does it work, and **Why** does it matter. Those three questions are the backbone of this entire presentation."

---

## SLIDE 3 — What is SURGE?

> "SURGE is an automated, multi-agent security platform. At its core, it does three things:
>
> First — it **coordinates distributed AI agents** that analyze network activity, detect threats, and identify vulnerabilities across segmented environments.
>
> Second — those agents work **across our VLAN-segmented lab network**, spanning both the attacker segment and the user segment, to discover hosts, services, and risks.
>
> Third — all of that network data — topology, open ports, OS fingerprints, CVEs — is **analyzed and surfaced** in a live dashboard with clear, actionable insights."

---

## SLIDE 4 — How Does SURGE Work? (4-step flow)

> "The workflow breaks into four phases:
>
> **Deploy** — we stood up a VLAN-segmented lab network with Cisco switches, a router, and Raspberry Pis simulating end devices. That gives SURGE a realistic, enterprise-grade target.
>
> **Analyze** — the recon agent scans across subnets, identifies systems, finds vulnerabilities, and our ML model scores and prioritizes risk automatically.
>
> **Visualize** — as the scan progresses, a live network map renders in real time. Nodes are color-coded by severity. Agent activity streams directly to the dashboard.
>
> **Secure** — the reporter agent generates tailored reports for different audiences: executive, technical, and public — each with concrete remediation steps."

---

## SLIDE 5 — Building the Network

> **[Sean or Taurean — whoever owns the network layer]**
>
> "To give SURGE a realistic environment, we built our own lab network from scratch. The hardware stack:
>
> - **Two Cisco 2960-24TT switches** for Layer 2 VLAN segmentation, connected via an 802.1Q trunk
> - **A Cisco ISR4331 router** running router-on-a-stick — single physical port split into subinterfaces for VLAN 10 and VLAN 20
> - **Five Raspberry Pis** as end devices, simulating real user machines
> - **A WaveLink wireless AP** extending connectivity within the VLAN environment
>
> This isn't a flat network. It mirrors real enterprise topology — which is exactly what makes it a meaningful test environment for SURGE."

---

## SLIDE 6 — Why SURGE Matters

> "Why did we build this? Four reasons:
>
> **One — Networks are complex.** Modern environments span VLANs, subnets, firewalls, and NAT. A toy lab wouldn't expose real problems.
>
> **Two — Manual analysis is slow.** Analysts waste hours just on network discovery and scan configuration before any real vulnerability work begins.
>
> **Three — Threats hide across boundaries.** Attackers don't stay in one VLAN. A flat network wouldn't force SURGE to deal with that.
>
> **Four — Findings have to be understandable.** Security insights are useless if they're buried in raw data. SURGE's reports are designed for real audiences, not just security engineers.
>
> SURGE's answer to all four: automate the analysis, cross the network boundaries, and deliver clear outputs."

---

## SLIDE 7 — Network Add-ons

> "A few specific network configurations worth calling out:
>
> **NAT Overload (PAT)** — all internal 192.168.0.0/16 traffic exits through a single external IP via port address translation. We validated 65 active translations in testing.
>
> **DHCP** — the router hands out dynamic IPs for both VLANs, excluding the gateway, DNS through 8.8.8.8 — mirrors real-world enterprise DHCP.
>
> **Router-on-a-stick** — subinterface g0/0/1.1 for VLAN 10, g0/0/1.2 for VLAN 20. Controlled inter-VLAN routing without Layer 2 broadcast floods.
>
> **Tailscale VPN** — this one was critical for development. It let the whole team test SURGE against the physical lab network from off-campus.
>
> And looking ahead: we have two planned additions — **ACLs** between VLANs for Layer 3 enforcement, and an **IDS/IPS** device on the trunk link for east-west traffic inspection."

---

## SLIDE 8 — Architecture Diagram (Agent Pipeline + LLMs)

> **[Jonathan or Brianna]**
>
> "Here's how the full system is wired together. The frontend dashboard talks to a **FastAPI REST layer**. The API triggers the **LangGraph multi-agent pipeline**, which runs the scan asynchronously. Results flow back via REST and WebSocket for real-time updates.
>
> On the inference side, we run **three LLMs**:
> - **Qwen3-32B (~20GB)** on GPU 0 — handles vulnerability analysis, OS analysis, and reporting
> - **GPT-OSS-20B (~14GB)** on GPU 1 — handles recon decisions and data formatting
> - **OpenRouter (GLM-5)** as a cloud overflow — seamlessly takes over when both local GPUs are busy
>
> One flag — `USE_ONLINE=1` — swaps the entire inference layer between local and cloud. That's how we did fast iteration during development before the GPU server was fully set up."

---

## SLIDE 9 — Introducing Our Agents

> "SURGE started as a single agent. It grew to **seven**. Each one handles a specific job in the pipeline, and together they cover the full analysis lifecycle — from raw network discovery to a finished report."

---

## SLIDE 10 — Agent Categories

> "The seven agents fall into three categories:
> - **Scanner agents** — they interact directly with the network
> - **AI / Data agents** — they process and score what the scanners find
> - **Reporter agents** — they synthesize findings into human-readable outputs"

---

## SLIDE 11 — The Scanner Agents

> "**Recon Agent** — this is the entry point. It scans the network repeatedly, mapping all reachable devices and endpoints across subnets. It's what kicks off the entire pipeline.
>
> **OS Finder Agent** — takes every host and open port the Recon agent discovered and digs deeper: identifies the operating system, services, and software versions running on each one."

---

## SLIDE 12 — The AI / Data Agents

> "**Vulnerability Finder Agent** — parses the OS Finder results and hits the **CIRCL API** to look up CPEs and service banners. It identifies which hosts have known, active vulnerability reports.
>
> **CVSS Scorer Agent** — this is our ML component. It runs an **XGBoost regression model** to predict a CVSS score for every vulnerability found, then ranks them by risk. This is what powers the priority ordering in the dashboard."

---

## SLIDE 13 — The Reporter Agents

> "**Recon Analyzer** — summarizes the network topology: what ports are open, key observations, and suggested next steps for further reconnaissance.
>
> **OS Analyzer** — builds a structured table of operating systems, vendors, hosts, and CPE highlights from the combined scan data.
>
> **Reporter** — the final stage. It takes everything from all six agents and produces **three tailored reports**: a non-technical executive summary, a full technical breakdown for the security team, and a public-facing media report."

---

## SLIDE 14 — Full Workflow Diagram

> "Here's the complete agent graph — the actual execution order:
>
> Recon runs first, then forks into OS Finder and Recon Analyzer in parallel. OS Finder feeds OS Analyzer. Those two paths merge at the Vulnerability Finder, which then feeds the CVSS Scorer, and finally the Reporter closes out the pipeline.
>
> The critical milestone is the **CVSS Scorer** — once it finishes, it writes a results file that unlocks the live dashboard. Before that point, everything shows as pending. After that, the full vulnerability picture populates across all panels simultaneously."

---

## SLIDE 15 — Data Collection: How We Store It

> **[Jonathan]**
>
> "On the data layer: agents write their findings to a **SQLite database** via SQLAlchemy. The **FastAPI** layer exposes that data as a REST API. During an active scan, agents also push updates through a **WebSocket connection**, so the frontend gets real-time progress without polling for every status change.
>
> The frontend is a **Next.js dashboard** — it polls the REST API for historical data and subscribes to the WebSocket for live updates. The two modes switch automatically: when a scan is running, you're in Live mode; when it completes, the dashboard flips to Latest automatically."

---

## SLIDE 16 — Why We Self-Hosted

> "We made a deliberate choice to run inference locally. The goal was performance and privacy — no sensitive scan data leaving the network.
>
> Our original plan was vLLM, which is the high-performance inference engine. Problem: vLLM requires newer Ampere GPUs, compute 8.0 or higher. Our hardware is older than that.
>
> So we switched to **Ollama with GGUF quantization** — specifically Q4_K_M quantization. It's compatible with a wider range of CUDA GPUs, and the models fit in our available VRAM:
> - Qwen3-32B compresses to ~20GB
> - GPT-OSS-20B compresses to ~14GB
>
> We get local inference, no hardware upgrade required."

---

## SLIDE 17 — Testing With the Cloud First

> "While the GPU server was being set up, we didn't want to slow down development. So we used **OpenRouter** for instant access to cloud models — GLM-5 and DeepSeek — during the early iteration phase.
>
> The switch between local and cloud is a single environment flag: `USE_ONLINE=1`. Nothing else in the codebase changes. We tested remotely over Tailscale the whole time.
>
> Total cloud spend across the entire development cycle: **$3.43**."

---

## SLIDE 18 — Two GPUs, Two Models, One Pipeline

> "On the hardware side, we're running two GPUs in parallel with isolated CUDA contexts — no PCIe contention between them.
>
> GPU 0 runs Qwen3-32B for the heavier analytical work: vulnerability analysis, OS analysis, report writing.
>
> GPU 1 runs GPT-OSS-20B for recon decision-making and data formatting.
>
> They run simultaneously. When both are saturated, OpenRouter handles the overflow. We also reduced context windows from 128K to 8K for structured tasks — maintained output quality while significantly improving throughput."

---

## SLIDE 19 — Our Dashboard in 6 Parts

> **[Jonathan]**
>
> "The dashboard has six sections, each purpose-built:
>
> **Dashboard** — network overview: device list, activity feed, vulnerability chart, stat cards. Auto-switches between Live, Latest, and History mode depending on scan state.
>
> **Scans** — all past and active scans with status, duration, and a WebSocket-driven progress bar that tracks which agent is currently running.
>
> **Topology** — a full-screen interactive network graph built with D3 force-directed layout. Nodes are color-coded by CVE severity. Pan, zoom, click a node to see its CVEs.
>
> **Exploits** — the complete CVE list with severity scores, exploit availability, and status filters. Sortable by CVSS score. Every CVE ID links directly to its NVD entry.
>
> **Reports** — generate security reports on demand. Four types: Executive, Technical, Public, and Final Combined. The audience determines the depth and framing.
>
> **Agents** — live pipeline status showing which agent is currently running and overall completion percentage."

---

## SLIDE 20 — Q&A / Thank You

> "That's SURGE. From a VLAN-segmented lab network to a live, multi-agent security platform — built and tested end to end.
>
> We're happy to answer any questions."

---

## Suggested Speaker Split

| Slide | Speaker |
|---|---|
| 1 — Title | Any (opener) |
| 2–4 — What/How/Why intro | Brianna or Jonathan |
| 5–7 — Network hardware & config | Sean + Taurean |
| 8 — Architecture diagram | Brianna |
| 9–14 — Agents deep-dive | Brianna |
| 15 — Data layer | Jonathan |
| 16–18 — Self-hosting & GPU setup | Sean or Taurean |
| 19 — Dashboard walkthrough | Jonathan |
| 20 — Closing | All |

---

## Likely Q&A — Be Ready For These

**"How accurate is the CVSS scoring model?"**
> The model is an XGBoost regressor trained on historical CVE data. It predicts a CVSS score from vulnerability metadata — OS, service, banner string. We validate against the raw CIRCL-provided scores where available.

**"Why not just use Nessus or OpenVAS?"**
> Commercial scanners don't coordinate agents, don't produce narrative reports, and can't be extended with custom ML models. SURGE is designed as a research platform, not a drop-in replacement for a commercial tool.

**"Could this scale beyond a lab network?"**
> The architecture supports it — SQLite can be swapped to PostgreSQL, the API is stateless, and the agent pipeline is async. The constraint today is nmap scan time on large ranges.

**"What's the security model — could SURGE itself be exploited?"**
> The API doesn't expose credentials, and scan targets are configured server-side. In production, you'd lock down CORS, add authentication, and run it on an isolated management VLAN. The capstone scope doesn't include that hardening layer.

**"What would you do differently?"**
> Earlier end-to-end testing against the physical network. We did most early dev against a flat test range; the VLAN complexity surfaced late.
