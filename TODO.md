## Week 6
# 2/20 FIXES
- change the OS flags
- changed the nmap scan success definition
- added a txt write to the cvss_scoring agent
- added a json write data in cvss_scoring agent

#### Urgent
- find a way to define the links of devices to each other
- refactor `address_grab.py` and `xml_parser.py` files (clean up comments and code)

#### Can Backburn
- work on the sweet spot for the timeout scan value
- after xml parsed, build the networkx graph
- update project structure in readme
- add a flag sanitize no OS/banner for recon analysis


### Future Changes
- define a Agent governance that says the threshold of false positives, fake data, etc
- change AgentState to be more per agent and not specifics (i.e. `state["recon"]`)
- see if there is a way to make threads of nmap scans (1 thread per unique IP)