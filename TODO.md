## Week 6
# 2/21 FIXES
- complete refactor of the vulnerability agent
- added dashboard data grab in the early stop of cvss_scoring()

#### Urgent
- update project structure in readme
- find a way to define the links of devices to each other
- refactor `address_grab.py` and `xml_parser.py` files (clean up comments and code)

#### Can Backburn
- work on the sweet spot for the timeout scan value  (THIS MIGHT NOT BE AN ISSUE, THE TIME MIGHT BE A HARDWARE ISSUE)
- add a flag sanitizer no OS/banner for recon analysis (I don't want the recon agent and os agent to be running the same scans)

### Future Changes
- implement some form of pentesting on vulnerabilities found (Jonny research)
- define a Agent governance that says the threshold of false positives, fake data, etc
- change AgentState to be more per agent and not specifics (i.e. `state["recon"]`) (?)
- see if there is a way to make threads of nmap scans (1 thread per unique IP)