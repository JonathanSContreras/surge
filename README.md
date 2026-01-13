# Senior Project: Multi-Agentic Network Analysis Tool
### Brianna Hinds - MAS Creator/Data Visualizer, Jonathan Contreras - Dashboard Creator, Taurean Muhammad and Sean Moning - Simulator Network Creator and MAS Cyber System Analyzer

## Folder Structure:
```
./Surge Project Folder
│   README.md
|   .gitignore 
|
├───<IP_ADDRESS_SUBNET>  # this is a folder created by the agentic workflow that holds all xml output that is generated per run (the purpose is so there is a centralized place to keep run information)
|       ...
│    
├───data  # contains data that helps with functions, output of network scan, CVE training data
│       nmap_output.xml  # might change to be name of scan
|       ...
│ 
├───model  # agentic model
|       agentic_prompts.py  # global file that contains ALL system prompts for each agent
|       globals.py  # global variables
|       helper.py  # helper functions used with the agentic workflow
│       sam.py  # the "main.py" file
│       tools.py  # houses all @tool methods for the agentic workflow
│ 
├───notebooks  # Jupyter Notebooks for functionality model testing
│       vuln_classifier.ipynb  # finalized CVSS classifier (uses XGB model)
|       vuln_xgb.ipynb  # testing of the XGB model
|       xlm_to_networkx.ipynb  #  parses an XML file and turns it into a networkx graph
│ 
├───output  # dump of all model/test run outputs (images, text files, etc.)
│       ...
│ 
├───src  # function definitions
│       xml_to_network.py
│       
└───utils  # utility files
        research.md  # brain dump of things to research through the project
        scan_dumps.txt  # scan dump, the reporting agent uses this to build its knowledge base
```

## Project Overview
This repo contains the build of a multi-agentic network tool that has network discovery and network analysis capabilities, where it will analyze a network that it has *strict* access to.

## Functionality Breakdown
The full agentic flow can be classified as a multi-agentic system (MAS) where there is an agent for Reconnaissance, Vulnerability Identification,Data Formatting, Summary/Reporting, and there are also subagents (children) for Recon and Vulnerability whose *sole* purpose would be to analyze its parent's output.

**The process starts with:**
#### Recon Agent
Reconnaisaance via the `nmap` tool, where the agent is given full range of `nmap` to pick the best scan to complete the goal of full network discovery. Full network discovery is hard to tell in when connected to a specific WiFi, so to ensure that there is that *full* network discovery we have setup a simulated network cabinet where we know what exactly is in the network. All outputs and knowledge this agent finds will get pushed to its child `Recon Analysis Agent`.

#### Vulnerability Agent
Network vulnerability is a very important role in identifying weaknesses in an organization's network. This agent will be solely responsible for taking the recon output and identifying what areas, devices, etc. is vulnerable in a CVE format. 
*This output then gets passed to a CVE formatter agent so that XGBoost model can run without breaking.*

#### Vulnerability Classifier Agent
This agent will exclusively call a `XGBoost` model method from the `tools.py` file called `cvss_scorer()`. Each identified vulnerability gets a score and then based on that value (from 0 to 10) will get one of the following labels: None/Low/Medium/High/Critical.

#### Reporter Agent
This agent is fully responsible for taking all outputs from all agents (except the Recon Agent) and writes out a detailed report for the organization. There will be two different types of outputted reports, (1) a very detailed, high-level analysis of all findings, this will be read by a SOC member or CIDO and can be understood by them. (2) A detailed analysis of issues in Layman's terms, so someone like a non-technical CIDO or a non-technical manager can understand the organization's network issues.


### Dashboard
#### UNDER - CONSTRUCTION (Jonathan's Job)
The dashboard built via `React` will contain graphs that are normally on a vulnerability dashboard but it will also include the GNN graph that was created and will dynmaically show/callout areas of the network the agent deemed as "risky". The graph view will be done through `D3.js`.
*End goal of the dashboard is to have the backend be integrated with my Python agentic code, all on the HCU server. So the HCU server will house: the CVE training data, Python code, Dashboard, and gpt-oss.*