## Week 6
#### Urgent
- fix TypeError in `cvss_scorer` (it seems it is taking prediction_vals as a dict)
- figure out how to make json for Jonny's dashboard (try to do it without agents)

```json
// json output format example
{
    "id": "1",  // string (maybe can be order of object/index)
    "ip": "192.168.1.1",
    "severity": "critical",  // defining a word for a range
    "description": "Primary gateway ...",
    "deviceType": "router", // IoT, etc
    "hostname": "gateway-primary",
    "cvss": 9.8,  // float from cvss scorer
    "status": "up"  //up or down
}
```
- find a way to define the links of devices to each other


#### Can Backburn
- work on the sweet spot for the timeout scan value
- after xml parsed, build the networkx graph
- update project structure in readme


### Future Changes
- change AgentState to be more per agent and not specifics (i.e. `state["recon"]`)
- see if there is a way to make threads of nmap scans (1 thread per unique IP)