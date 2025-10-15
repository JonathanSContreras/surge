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

**9/24:**
- working on RECON workflow (mainly the RECON agent)
- decided to define a tiered sanitization for the nmap commands
- got it running but the gemini LLM is asking for user input (i.e. "Would you like to initiate a scan?")

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