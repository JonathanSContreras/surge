## Project Process Braindump
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