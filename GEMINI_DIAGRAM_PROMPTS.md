# Gemini Prompts for Report Diagrams

Use these prompts in Gemini to generate each figure. After each one, export with a **white background** at high resolution. Insert into the report at the location described.

---

## Figure 2 — Agent Pipeline DAG
**Location:** Section 4.1 (Agent Pipeline Architecture), after the Reporter paragraph

> Create a technical directed acyclic graph (DAG) diagram for an AI agent pipeline. Use a clean, minimal engineering style with rectangular boxes, directional arrows, and clear labels. White background, black text, light blue fills on boxes.
>
> **Top-to-bottom flow:**
>
> 1. "Recon Agent (nmap)" at the top
> 2. Arrow splits (fan-out) into TWO parallel boxes side by side: "Recon Analyzer" and "OS Fingerprinter"
> 3. Both arrows converge (fan-in) into "OS Analyzer"
> 4. Arrow down to "Vulnerability Agent (CIRCL CVE API)"
> 5. Arrow down to "CVSS Data Formatter"
> 6. Arrow down to "CVSS Scoring (XGBoost)"
> 7. Arrow down to "Reporter Agent"
>
> Draw a bracket along the left side labeled "LangGraph StateGraph".
>
> On the right side, show two boxes representing LLM tiers:
> - "Fast Tier: Ollama (GPU 1, GPT-OSS-20B)" connected with dashed arrows to Recon Agent and CVSS Data Formatter
> - "Analysis Tier: OpenRouter (GLM-5)" connected with dashed arrows to Recon Analyzer, OS Analyzer, Vulnerability Agent, and Reporter
>
> Use a legend in the corner: solid arrow = data flow, dashed arrow = LLM inference call.

---

## Figure 3 — Database ER Diagram
**Location:** Section 4.3 (Database Schema), after the ActivityEventModel paragraph

> Create a database entity-relationship diagram. Clean engineering style, white background, no decorative elements. Use rectangles for tables with the table name as a bold header and field names listed below.
>
> **Tables and key fields:**
>
> 1. "ScanModel" (center): scan_id (PK), name, target_range, scan_type, status, created_at, devices_count, vulns_count, avg_cvss
> 2. "DeviceModel": id (PK), scan_id (FK), ip, hostname, os_name, severity, cvss_score
> 3. "VulnerabilityModel": id (PK), scan_id (FK), device_id (FK), cve_id, cvss_score_raw, cvss_score_predicted, severity, summary
> 4. "ReportModel": id (PK), scan_id (FK), template_id, executive_summary, key_findings
> 5. "ActivityEventModel": id (PK), scan_id (FK), event_type, message, ip, agent_node
>
> **Relationships:** Draw crow's foot notation lines:
> - ScanModel 1──* DeviceModel
> - ScanModel 1──* VulnerabilityModel
> - ScanModel 1──* ReportModel
> - ScanModel 1──* ActivityEventModel
> - DeviceModel 1──* VulnerabilityModel
>
> Use light blue header rows on each table. Keep it compact enough to fit on one page.

---

## Figure 4 — Dashboard Main View
**Location:** Section 4.4 (Frontend Dashboard), after the first paragraph about view modes

> **This should be a real screenshot.** Open hcu-surge.vercel.app in a browser, navigate to the Dashboard tab, and take a screenshot showing:
> - The D3 force-directed network topology graph with colored nodes
> - The device list sidebar
> - The activity feed
> - The vulnerability chart and exploit queue
>
> If no live scan data is available, use the sample/fallback data that loads by default. Crop to just the dashboard content (no browser chrome). Export at 2x resolution.

---

## Figure 5 — Exploits Page
**Location:** Section 4.4 (Frontend Dashboard), after the Exploits view paragraph

> **This should be a real screenshot.** Open hcu-surge.vercel.app, navigate to the Exploits tab, and take a screenshot showing:
> - The CVE vulnerability table with severity badges
> - The filter controls (severity, exploit availability, status)
> - The summary stat cards at the top
>
> If no live data, use the "Latest" view with whatever data is available. Crop to just the page content. Export at 2x resolution.

---

## Figure 6 — Lab Network Topology
**Location:** Section 4.5 (Network Infrastructure), after the Verification paragraph

> Create a network topology diagram. Clean engineering style, white background. Use standard network icons (rectangle for switches, trapezoid or rectangle for routers, shield for firewall).
>
> **Layout (left to right):**
>
> **Left zone — "VLAN 10 (Attackers, 192.168.10.0/24)":**
> - PC2 (192.168.10.5) and PC3 (192.168.10.6) connected to Switch 1 (Cisco 2960-24TT) on access ports
> - AI Scanner (192.168.1.9) also connected to Switch 1
>
> **Center — Switching & Routing:**
> - Switch 1 connected to Switch 2 via "802.1Q Trunk (F0/5)" label on the link
> - Switch 1 uplink to Router 1 (Cisco ISR4331) via trunk port
> - Router 1 has subinterfaces: "g0/0/1.1 — 192.168.10.1 (VLAN 10)" and "g0/0/1.2 — 192.168.1.1 (VLAN 20)"
> - Router 1 external: "g0/0/0 — 10.10.1.160"
>
> **Right zone — "VLAN 20 (Users, 192.168.1.0/24)":**
> - PC0 (192.168.1.7) and PC1 (192.168.1.8) connected to Switch 2 on access ports
>
> **Far right — Perimeter:**
> - Router 1 connects to "ASA 5506-X Firewall"
> - Firewall connects to Router 2 (ISR4331) labeled "External / HCU Engineering Network"
>
> Add "NAT/PAT" label on the link between Router 1 and Firewall. Add "Default Route: 0.0.0.0/0 via 10.10.1.1" annotation near Router 1.

---

## Figure 7 — Governance Tier Model
**Location:** Section 4.6 (Governance and Security Layer), after the "appends -oX flag" paragraph

> Create a three-column comparison diagram showing scan governance tiers. White background, clean style. Use a table or card layout with three columns:
>
> **Column 1 — "Low Tier (Quick Scan)"** with green header:
> - Allowed: -sn (host discovery), -T0 to -T4 (timing)
> - Ports: None (discovery only)
> - Timeout: Default
> - Blocked: Port scanning, service detection, scripts
>
> **Column 2 — "Medium Tier (Normal/Stealth)"** with amber/yellow header:
> - Allowed: -sS, -sV, -O, -sC (SYN scan, service/OS detection, light scripts)
> - Ports: Max 4,096
> - Timeout: 20 minutes
> - Blocked: Full port range, aggressive scripts
>
> **Column 3 — "High Tier (Deep Scan)"** with red header:
> - Allowed: -A, --script vuln (full recon, vulnerability scripts)
> - Ports: All 65,535
> - Timeout: 90 minutes
> - Blocked: Nothing (full capability)
>
> Below all three columns, add a shared red banner: "ALL TIERS: Block shell metacharacters (; & | ` $ ||), validate port expressions, enforce -oX XML output"
>
> Add an arrow across the top labeled "Increasing scan capability →"

---

## Figure 8 — ML Feature Engineering Pipeline
**Location:** Section 4.7 (Machine Learning Model), after the model description paragraph

> Create a left-to-right data pipeline diagram. White background, clean engineering style with rectangular boxes and arrows.
>
> **Input (left):**
> Box: "Raw CVE Entry" containing fields: cve_id, summary, access_vector, access_complexity, access_authentication, impact_*, cwe_name
>
> **Processing (center) — three parallel branches:**
> 1. Top branch: "Categorical CVSS Fields (6)" → "OneHotEncoder" → "One-Hot Features"
> 2. Middle branch: "CWE Name" → "TF-IDF Vectorizer" → "TF-IDF Features"
> 3. Bottom branch: "Vulnerability Summary" → "Sentence-BERT (all-MiniLM-L6-v2)" → "Embedding Features (384-dim)"
>
> **Merge (center-right):**
> All three feature branches merge with a "Concatenate" node → "137+ Feature Vector"
>
> **Output (right):**
> "137+ Feature Vector" → "XGBoost Regressor" → "Predicted CVSS Score (0-10)"
>
> Use light blue fills for processing boxes, light green for the final output. Add small feature count labels on each branch (e.g., "~20 features", "~30 features", "384 features").
