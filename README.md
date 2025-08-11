# AI Pentester
## Network Exploration (with Pentesting Capabilities)
Overview: 
An agentic network tool that has pentesting capabilities, network feedback, networking mapping, vulnerability scans, exploitation tool, and a vulnerability classifier.

The tools used will be:
- OpenAI gpt-oss (free-weight LLM)
- LangChain (the agent)
- Python for method definitions (nmap, explotations, etc.)
- PyTorch
    - network mapping (GNN)
    - vulnerability classification
- Next.js for dashboard
    - deployed on Vercel
    - uses custom API routes to access the agent

## Folder Structure:
```
./Surge
│   README.md
│   main.py
│       
├───model
│       NAME.py  # FIND A NAME FOR AGENT
│       toolkit.py
│
├───notebooks
│       nmap_gnn.ipynb
│       vulnerability_classifier.ipynb
│       
└───utils
        log.json
```
---

## Functionality Breakdown
### Agent
The LangChain agent will perform:
1) Reconnaissance via the `nmap` tool.
2) Vulnerability Detection via `OpenVAS`/`Nikto`.
3) Vulnerability Classification via PyTorch model classifying an identified vulnerability as None/Low/Medium/High/Critical
4) Prioritization which will sort vulnerabilities based on CVSS score
5) Exploitation via `Metasploit`, this will be controlled. It will either run real exploits or pseudo-exploits.
6) Reporting through log action and send to the dashboard.

When it comes to exploitation, the agent will exploit a vulernability based ona vulnerability score (CVSS) if it is a high vulnerability score then the agent will exploit those first. The agent will know what is deemed as vulnerable through the CVE database which data will be pulled from the `NVD API` and will be stored locally in a `Postgres` so the agent can search quickly. In the end this will be used to rank vulnerabilities and explain patches.

LangChain will wrap `nmap`, `nikto`, `OpenVAS`, `Metasploit`, etc. into the `Tool()` method so the LLM can call them in sequence.

### Dashboard
The dashboard built via `next.js` will contain graphs that are normally on a vulnerability dashboard but it will also include the GNN graph that was created and will dynmaically show/callout areas of the network the agent deemed as "risky". The graph view will be done through `D3.js` or `Cyroscape.js`.