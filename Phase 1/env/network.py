import gym
from gym import spaces

import networkx as nx
import subprocess  # used with networkx to mimic real hacking processes
import socket

import numpy as np
import matplotlib.pyplot as plt  #visualize the what the agent discovers per episode (?)
import random
import datetime

# use ns3 (network simulator tool to simulate networks) instead of networkx  (might need Ubuntu, DO LATER)
# import ns.core
# import ns.network
# import ns.internet
# import ns.point_to_point

"""
TODO:
- implement anomaly based detection and signature based detection and find some way to reduce the stealth score (anomaly: reduce if it scans to much too often, signature: reduce if it does things that might be common to do)

"""
class NetworkEnvironment(gym.Env):
    """
    Custom wrapper class for OpenAI Gym + SimPy.

    CLASS CONTENTS
        __init__ 
        generate_network 
        reset
        _get_obs
        step
        render
    """
    def __init__(self, num_nodes=20, delay=0.05):
        super(NetworkEnvironment, self).__init__()

        self.graph = None  # networkx graph 
        self.num_nodes = num_nodes
        self.agent_pos = None
        self.discovered = set()
        self.stealth_score = 5  # reduce when detection happens
        self.delay = delay

        # used to keep track of agent's journey
        self.agent_step = 0

        # actions (0-10)
        self.action_space = spaces.Discrete(11)
        print(f"NUMBER OF ACTIONS: {self.action_space.n}")
        self.nA = self.action_space.n  # number of actions

        # observation: discovered nodes + current node ID + stealth
        self.observation_space = spaces.Dict({
            "current_node": spaces.Discrete(num_nodes),  # 20
            "discovered": spaces.MultiBinary(num_nodes),  # 20
            "stealth_score": spaces.Box(0, 10, shape=(1,), dtype=np.float32)  # 1 value
        })

        # number of states (states = agent's current knowledge)
        self.nS = (self.observation_space["current_node"].n + self.observation_space["discovered"].n + 1)  # 41  PROBLEM LINE (probably has to do with the way everything is being flattened/called)

        # create the random network
        self.generate_network()
        
    def generate_network(self, num_nodes=20):  # ground truth network for the agent to discover
        """
        Randomized network graph with 20 nodes, using the Erods Renyi Graph concept.
        """
        node_colors = []
        node_sizes = []
        self.graph = nx.erdos_renyi_graph(num_nodes, 0.3)  # random connectivity
        for node in self.graph.nodes:
            self.graph.nodes[node]["ip"] = f"10.10.4.{node+1}"
            self.graph.nodes[node]["admin"] = True if node == 0 else random.choice([True, False])
            self.graph.nodes[node]["open_ports"] = random.sample([22, 80, 443], k=random.randint(1, 3))
            self.graph.nodes[node]["services"] = {"80": "http", "22": "ssh", "443": "https"}

            # based if it is an admin or not change the color of the node and the size
            node_colors.append("#ffc300") if self.graph.nodes[node]["admin"] == True else node_colors.append("#1f78b4")
            node_sizes.append(600) if self.graph.nodes[node]["admin"] == True else node_sizes.append(300)

        # print(node_colors)
        # print(node_sizes)
        # print(G.nodes[node])
        nx.draw(self.graph, pos=nx.spring_layout(self.graph), node_color=node_colors, node_size=node_sizes, with_labels=True)

        # save the graph
        plt.savefig("network.png")
        plt.show()

        # return G

    def reset(self):
        """
        Resets the environment to the beginning of a new episode and returns the initial observation.
        """
        self.agent_pos = random.choice(list(self.graph.nodes))
        self.discovered = {self.agent_pos}
        self.stealth_score = 5

        return self._get_obs()

    def _get_obs(self):
        """
        Formats the current environment state into a structured observation, returning a dictionary of the agent's current node ID, the nodes discovered, and the current stealth level.
        """
        discovered = np.zeros(self.num_nodes, dtype=np.int32)
        for node in self.discovered:
            discovered[node] = 1
        return {
            "current_node": self.agent_pos,
            "discovered": discovered,
            "stealth_score": np.array([self.stealth_score], dtype=np.float32),
        }
    
    def flatten_observation(self, obs, num_nodes):
        """
        Converts the structured observation dict into a flat vector.
        """
        print(obs["current_node"])
        current_node_vec = np.eye(num_nodes)[obs["current_node"]]  # one hot encoding of position
        discovered_vec = obs["discovered"]
        stealth_vec = obs["stealth_score"]

        print("in flatten_observation method:", current_node_vec, discovered_vec, stealth_vec)

        # Concatenate all into one vector
        return np.concatenate((current_node_vec, discovered_vec, stealth_vec), axis=0)

    
    # NEED TO ADD MORE TO EXPLORE, DISCOVER AND DETECT
    # LOG ACTIONS
    def step(self, action):
        """
        Takes an action from the agent, updates the environment, and returns the next state, reward, and done flag.

        ARGS
            action: Action taken by the agent.
                - 0: port scan
                - 1: network scan (try unknown devices)
                - 2: t-shark/sniff traffic (packet sniffing)
                - 3: banner grab
                - 4: brute force login
                - 5: exploit service
                - 6: pivot host
                - 7: download files
                - 8: compress files
                - 8: idle
                - 10: exit
        """
        reward = 0
        done = False
        action_taken = ""

        if action == 0:  # port scan
            self._port_scan()
            reward += 1
            action_taken = "port scan"

        elif action == 1:  # network scan
            r = self._network_scan()
            reward += r
            action_taken = "network scan"

        elif action == 2:  # t-shark
            self._sniff()
            reward += 1
            action_taken = "sniffing traffic"

        elif action == 3:  # banner grab
            self._banner_grab()
            reward += 2
            action_taken = "banner grab"

        elif action == 4:  # brute force login
            user, pwd, r = self._brute_force_login()
            reward += r
            action_taken = f"attempting to log in using: USERNAME: {user}, PASSWORD: {pwd}"

        elif action == 5:  # exploit service
            self._exploit_service()
            reward += 1
            action_taken = "exploit service"

        elif action == 6:  # pivot host
            self._pivot_host()
            reward += 1
            action_taken = "pivot host"

        elif action == 7:  # download files
            self._download_file()
            reward += 2
            action_taken = "downloading files"

        elif action == 8:  # compress files
            self._compress_file()
            reward -= 0.5
            action_taken = "compressing files"

        elif action == 9:  # idle
            self._idle()
            reward += 1
            action_taken = "idle"

        elif action == 10:
            self._exit()
            done = True
            reward += 2
            action_taken = "exit network"

        else: # default
            reward += 0.5
            action_taken = "other"

        # risk of being caught
        if random.random() < 0.1:
            self.stealth_score -= 1
            reward -= 1

        # write to a log file
        timestamp = datetime.datetime.now()
        with open("./Phase 1/utils/log.txt", "a") as f:
            f.write(f"Timestamp: {timestamp}, Action Taken: {action_taken}\n")

        # if stealth is all gone
        if self.stealth_score < 0:
            done = True

        return self._get_obs(), reward, done, {}

    def render(self, mode="human", done=False):
        """
        Returns a summary of the movements of the agent. 

        ARGS
            mode: the type of rendering (human = readable by a person)
        """
        G = self.graph
        node_color = []

        for node in G.nodes:
            if node == self.agent_pos:
                node_color.append("#c1121f")  # this is the agents current position
            elif node in self.discovered:
                node_color.append("#6a994e")  # the agent has discovered this node
            elif G.nodes[node]["admin"] == True:  # admin
                node_color.append("#ffc300")
            else:
                node_color.append("#8d99ae")  # undiscovered

        plt.clf()
        nx.draw(G, pos=nx.spring_layout(G), with_labels=True, node_color=node_color, font_color="white")
        plt.title(f"Agent at: {self.agent_pos} | Discovered: {self.discovered} | Stealth: {self.stealth_score}")
        plt.pause(0.5)

        plt.savefig(f"Phase 1\model\journey\step{self.agent_step}.png")
        self.agent_step += 1
        plt.show()

        return (f"Agent at: {self.agent_pos} | Discovered: {self.discovered} | Stealth: {self.stealth_score}")
    
    #### ACTION METHODS
    """
    The agent is learning based on the MITRE ATT&CK Framework, where each of the 10 actions is either a tactic or a technique to move from node to node in the network.
    Depending on the output, the reward will be returned from the method itself.
    """
    def _port_scan(self):  # discovery
        ip = self.graph.nodes[self.agent_pos]["ip"]
        print(f"~ Port scanning {ip}")

        try: 
            result = subprocess.run(["ping", ip, "-n", "1"], capture_output=True, text=True)
            if "TTL=" in result.stdout:
                print(f"    Host {ip} is up")
            else:
                print(f"    Host {ip} is down")
        except Exception as e:
            print(f"    Port scan error: {e}")
            
    def _network_scan(self):  # discovery
        print("~ Scanning network neighbors.")

        neighbors = list(self.graph[self.agent_pos])
        for n in neighbors:
            ip = self.graph.nodes[n]["ip"]
            print(f"    Found neighbor: NODE {n}, IP {ip}")

            if n not in self.discovered:
                self.discovered.add(n)
                r = 1
            else:  # negative reward for going back to a discovered node (prevents infinite loops)
                r = -2

        print(r)
        return r

    def _sniff(self):  # collection
        print(f"~ Sniffing traffic near node {self.agent_pos}")
        fake_creds = random.choice(["admin:admin", "1234:1234", "root:toor"])
        print(f"~ Credentials found: {fake_creds}")

    def _banner_grab(self):  # discovery
        ip = self.graph.nodes[self.agent_pos]["ip"]
        ports = self.graph.nodes[self.agent_pos]["open_ports"]
        print(f"~ Grabbing banner from {ip} on port {ports[0]}")

        try:
            s = socket.create_connection((ip, ports[0]), timeout=2)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")
            s.close()
            print(f"    Banner: {banner.strip()}")
        except Exception as e:
            print(" Failed to grab banner: {e}")

    """WORK ON THIS TO POSSIBLY USE PASSWORD HACKING TOOLS"""
    def _brute_force_login(self):  # credential access
        common_users = ["admin", "user", "guest", "1234567890", "root"]
        common_pwds = ["admin", "1234", "password", "toor"]

        user = random.choice(common_users)
        pwd = random.choice(common_pwds)

        print(f"~ Attempting to log in with {user}, {pwd}")
        success = random.random() < 0.2

        if success:
            print(" Login successful.")
            r = 2
        else:
            print(" Login failed.")
            r = -1

        return user, pwd, r

    def _exploit_service(self):
        print("~ Running exploit on service")
        vulnerable = random.choice([True, False])
        if vulnerable:
            print("    Exploit successful")
        else:
            print("    Exploit failed")
  
    def _pivot_host(self):  # lateral movements
        print("~ Running exploit on service")
        vulnerable = random.choice([True, False])
        if vulnerable:
            print("    Exploit successful")
        else:
            print("    Exploit failed")

    def _download_file(self):  # collection
        print("~ Downloading sensitive files")
        files = ["passwd.txt", "confidential.docx", "backup.sql"]
        stolen = random.choice(files)
        print(f"    Downloaded: {stolen}")

    def _compress_file(self):  # exfiltration
        print("~ Compressing files for exfiltration.")
        print("~ Files sucessfully created: archive.zip")

    def _idle(self):  # defensive evasion
        print("~ Idling to avoid detection.")

    def _exit(self):  # exfiltration
        print("~ Exiting network - exfiltration complete.")

    ######################

# # testing network generation
# if __name__ == "__main__":
#     nw = NetworkEnvironment()
#     nw.generate_network()


#     env = NetworkEnvironment()
#     for i in range(1):
#         s = env.reset()
#         env.render()
#         while True:
#             action = np.random.choice(env.nA)
#             res = env.step(action)
#             print(f"Action: {env.s}, {action}, -> {res}")
#             env.render(done=res[2])
#             if res[2]:
#                 break

#     env.close()