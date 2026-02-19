## Week 6
#### Urgent
- fix TypeError in `cvss_scorer` (it seems it is taking prediction_vals as a dict)
    - prediction_vals = agent state for some reason
    - parsed = list i.e. parsed [{'cve_id': 'CVE-2023-23397', 'mod_date': '2023-12-01 00:00:00', 'pub_date': '2023-11-01 00:00:00', 'cvss': 9.8, 'cwe_code': 284, 'cwe_name': 'Improper Access Control', 'summary': 'Local privilege escalation vulnerability in Windows 11 21H2 kernel.', 'access_authentication': 'USER', 'access_complexity': 'LOW', 'access_vector': 'LOCAL', 'impact_availability': 'PARTIAL', 'impact_confidentiality': 'PARTIAL', 'impact_integrity': 'PARTIAL', 'product': 'Windows 11', 'version': '21H2', 'host': '10.10.162.64'}]
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
- refactor `address_grab.py` and `xml_parser.py` files (less)


#### Can Backburn
- work on the sweet spot for the timeout scan value
- after xml parsed, build the networkx graph
- update project structure in readme


### Future Changes
- change AgentState to be more per agent and not specifics (i.e. `state["recon"]`)
- see if there is a way to make threads of nmap scans (1 thread per unique IP)