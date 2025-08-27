# Agentic Network Analysis
## Network Exploration
Overview: 
An agentic network tool that has capabilities, network feedback capabilities, networking mapping, vulnerability scans, exploitation tool, and a vulnerability classifier. The brain of the agent will follow MITRE ATTACK strategies and workflows.

The tools used will be:
- OpenAI gpt-oss (free-weight LLM) (might use Claude)
- LangChain or LangGraph (the agent)
    - LangGraph gives us more control because this is a non-linear task
- LangSmith for analyzing the agents, making sure there is no hallucinations.
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
├───data
│       nmap_output.xml  # might change to be name of scan
│ 
├───model
│       sam.py
│       toolkit.py
│ 
├───notebooks
│       nmap_gnn.ipynb
│ 
├───output
│       xml_to_networkx.png
│ 
├───src
│       xml_to_network.py
│       
└───utils
        imports.py  # MIGHT DELETE
        log.json
```
---

## Functionality Breakdown
### Agents
The approach we are taking is a multi-agent system (MAS) where there is an agent for Reconnaissance, Vulnerability Identifying, Summary/Reporting Agent, and there will be subagents for Recon and Vulnerability whose's sole purpose would be to analyze the its parent's output.

The process start with:
1) Reconnaissance via the `nmap` tool.

After reconnaissance the agent will make a Next Best Action decision from the following choices:
- Reporting through log action and send to the dashboard.
- Port scanning (either stealthy, decoy, aggressive)
- OS Scanner
- Service enumerator
- Vulnerability Detection Scan (`nmap`) and then transition into `OpenVAS`/`Nikto`
- Prioritization which will sort vulnerabilities based on CVSS score
- Exploitation via `Metasploit`, this will be controlled. It will either run real exploits or pseudo-exploits.

When it comes to exploitation, the agent will exploit a vulnerability based on a vulnerability score (CVSS) if it is a high vulnerability score then the agent will exploit those first. Or there might be a EPSS score that determines what to exploit. The agent will know what is deemed as vulnerable through a classifier, from the CVE database which data will be pulled from the `NVD API` and will be stored locally in a `Postgres` so the agent can search quickly. In the end this will be used to rank vulnerabilities and explain patches.

For the `EPSS` score, that process will either be pulled from first.org (as a Python library `epss-api`) or created ourselves. 

The vulnerability classifier will be built via PyTorch model classifying an identified vulnerability as None/Low/Medium/High/Critical

LangChain will wrap `nmap`, `nikto`, `OpenVAS`, `Metasploit`, etc. into the `Tool()` method so the LLM can call them in sequence.

### Dashboard
The dashboard built via `next.js` will contain graphs that are normally on a vulnerability dashboard but it will also include the GNN graph that was created and will dynmaically show/callout areas of the network the agent deemed as "risky". The graph view will be done through `D3.js` or `Cyroscape.js`.