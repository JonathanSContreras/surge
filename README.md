# AI Pentester
## PHASE 1: Network Exploration
- The goal of this phase is to have the agent be able to COMPLETELY discover the full network of an unknown system without being detected. It will output a map at the end of each episode and any information it learned will be used in the next episode. 

*This phase is completely random and has nothing to do with a real network nor real Python networking libraries. This is used to build the initial RL model.*

---

ALGORITHM: Deep Q-Learning (since the network is unknown)

AGENT: "ethical hacker" (need to come up with name)

ENVIRONMENT: unknown network

ACTIONS:
- 0: port scan
- 1: network scan (try unknown devices)
- 2: t-shark/sniff traffic
- 3: signature detection
- 4: anomaly rules

STATES: (agent's current knowledge)
- list of known devices
- known open ports per device
- known vulnerabilities (through scan results)
- stealth level/risk of detection
- last action/target node
The format of this will be a dictionary that summarizes the knowledge.

REWARDS: 
- -1: scan failed/detection triggered
- +1: new device discovered
- +2: device scanned for open ports
- +3: credential/file access gained
- +5: full networkm discovered
The reward system will be a cumulative reward.

EPISODE TERMINATION:
An episode will end when the agent maps all reachable nodes OR gets detected too many times (the stealth score drops below 0)

LEVELS (not created more so for mental notes):
- LEVEL 1: discover nodes
- LEVEL 2: port scanning
- LEVEL 3: credential access
- LEVEL 4: file access/lateral movement

ENVIRONMENT CREATION:
- networkx and custom gym.Env