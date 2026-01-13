# Project Process Braindump
> Author
> Brianna Hinds


#### Summer (May-July)
Spent time planning out the project and its scope we were debating on making it a network vulnerability agent vs an exploit/pentester agent. 

#### August
Decided to focus more on the network vulnerability side of the project (underpromising to over deliver). I took a step back and learned `LangGraph` and how it works. And we (Jonathan and I) transitioned the project scope from a single agentic workflow to a multi-agentic system (MAS). 

#### September
**9/23:**
- Working on RECON agent and its tools
- GOAL BY 10/1: get a simple workflow finished 
$$START -> RECON -> RECON ANALYSIS -> END$$
- RECON: free `nmap` scans, write to the log file, output `.xml` to be parsed by RECON ANALYSIS AGENT and VULNERABILITY AGENT
- RECON ANALYSIS: analyze `.xml` output

**9/24:**
- working on RECON workflow (mainly the RECON agent)
- decided to define a tiered sanitization for the nmap commands
- got it running but the gemini LLM is asking for user input (i.e. "Would you like to initiate a scan?")

### October
**10/14**
- got the recon agent fully running without having to ask for confirmation (used chatgpt)
- connected to a switch and was able to discover the switch and jonathan's device (192.163.2.0/24 and "low" scan)
- state is a JSON file ready for the recon analysis agent to analyze
- biggest thing is the change in messaging System Message -> AI Message -> Human Message -> etc.
- I am thinking of having a reprompt after the agent does not discover anything new after 2 iterations

**10/15**
- going from gpt oss to gemini means that the prompting will have to change
    - gpt needs a role-based message format (system, user, assistant) where system = context/rules, user = input/targets/history/etc
- got it working with gpt oss from jonathan's server
- BIG CHANGES:
    - instead of pushing an error that has any disallowed flags, it instead takes those flags out
    - changed the xml log output (from putting the raw file to outputting it to a .xml file and calling the path in the log)

**10/22**
- recon agent -> recon analysis agent is working 
- I am pushing for more aggressive scans which is making all the scans time out (NOT SCANNING NO OUTPUT)
    - I want the recon agent to be the ONLY agent that touches the 
- NEED TO DO: make the recon analysis agent read through the xml folder
    - possibly make a method that takes the target and makes it a folder
- starting to work on vulnerability agent

**10/23**
- worked on the data passing, made a folder to store all xml files created per run
- added a new state object (xml_content) that has all content from all xml files as a string so the recon analysis and vulnerabilty agent can look over
- when it comes to building a toolkit i want the recon agent to ONLY have access to the network
    - possible tools: 'scapy', 'pyshark'
- the vulnerability agent will take the xml_content state and possibly the recon results to create CVE type data
- MY GOAL: have the barebone agentic workflow done before Thanksgiving
- MY CURRENT ISSUES: find the sweet spot to declare a scan timeout, i need ti do aggressive recon scans to get everything but it takes long

#### SPRING
#### January
**1/13**
- cleaned up the README and the repository
- goal for the day is to go through the code and check for logic issues, my goal is to do a running of the code by the end of the week (1/16) when gpt-oss is on the server
- FODD FOR THOUGHT: figure out what subset mask I need to do to find everything within a WiFi network
- methods to clean up and why:
    - [] `cvss_scorer()` in tools.py: instead of training at every run I need to save the best XGBoost model and then just call its saved state
    - [] clean up the logging stuff in the `nmap_scanning()` tool: the commented out code just looks messy
    - [] see how to make the `cve_search()` in tools.py bet better in identifying vulnerabilities (right now it is just cve.circl API, see if i can do it using the banner grabs, port scanning etc)
    - [] see if the summarize recon results can be cleaned up a bit/actually pull the data
TODO TODAY:
    - [x] create a saved XGBoost model (find the best model with parameters)  
    - [x] clean up the cvss_scorer()  