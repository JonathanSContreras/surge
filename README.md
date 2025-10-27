# Agentic Network Analysis
## Network Exploration
Overview: 
A multi-agentic network tool that has network discovery capabilities, where it will analyze a network is has authorized access to. This recon agent (workflow start) will attempt to get as much information as possible about the network, open devices, ports, OS, vulnerabilities, etc. After the recon agent runs, its output will get passed to other agents to label pinpoints in the targeted network. The brain of the agent will follow MITRE ATTACK strategies and workflows.

The tools used will be:
- OpenAI gpt-oss on HCU server
- LangGraph (the agent/workflow)
    - LangGraph gives us more control because this is a non-linear task
- LangSmith for analyzing the agents, making sure there is no hallucinations.
- Python for method definitions (nmap, explotations, etc.)
- PyTorch and ML Models
    - network mapping (GNN)
    - vulnerability classification  (XGBoost)
- Next.js for dashboard
    - deployed on Vercel
    - uses custom API routes to access the agent

## Folder Structure:
```
./Surge
│   README.md
│   main.py
│    
├───data  # test data for model or function tests
│       nmap_output.xml  # might change to be name of scan
│ 
├───model  # agentic model
│       sam.py
│       toolkit.py
│ 
├───notebooks  # Jupyter Notebooks for functionality testing
│       nmap_gnn.ipynb
│ 
├───output  # model/function outputs
│       xml_to_networkx.png
│ 
├───src  # function definitions
│       xml_to_network.py
│       
└───utils  # utility files
        imports.py  # MIGHT DELETE
        log.json
```
---

## Functionality Breakdown
### Agents
The approach we are taking is a multi-agent system (MAS) where there is an agent for Reconnaissance, Vulnerability Identifying, Summary/Reporting Agent, and there will be subagents for Recon and Vulnerability whose's sole purpose would be to analyze the its parent's output.

The process start with:
#### Recon Agent
Reconnaissance via the `nmap` tool, where the agent is given full range of nmap to pick the best scan for the goal of full network discovery. 
*might have more recon tools. It will also have access to the `PYTHON LIBRARY` so that it can figure out other possible network information. -> All outputs gets pushed to **Recon Analysis** agent.

#### Vulnerability Agent
Network vulnerability is a important role in identifying weaknesses in an organization's network. So this agent will be responible for taking the recon output and identifying what vulnerabilities are on the network in CVE format. -> This output then gets passed to a CVE formatter agent so the XGBoost model can run without breaking.

#### Vulnerability Classifier Agent
This agent will explicitly call a `XGBoost` model method, where each identified vulnerability gets a score and then labeled None/Low/Medium/High/Critical.

#### Reporter
This agent is fully responible for taking all outputs from all agents (except the Recon Agent) and writes out a detailed report for the organization. There will be two different types of outputted reports, (1) a very detailed, high-level analysis of all findings, this will be read by a SOC member or CIDO and can be understood by them. (2) A detailed analysis of issues in Layman's terms, so someone like a non-technical CIDO or a non-technical manager can understand the organization's network issues.


### Dashboard
The dashboard built via `React` will contain graphs that are normally on a vulnerability dashboard but it will also include the GNN graph that was created and will dynmaically show/callout areas of the network the agent deemed as "risky". The graph view will be done through `D3.js`.