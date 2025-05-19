import gym
from gym import spaces
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt  #visualize the what the agent discovers per episode (?)
import random
import datetime

# use ns3 (network simulator tool to simulate networks) instead of networkx  (might need Ubuntu, DO LATER)
# import ns.core
# import ns.network
# import ns.internet
# import ns.point_to_point

# SimPy (a good python/windows based network simulator library)
import simpy

"""
TODO:


"""

class Device:
    """
    Represents a simulated network device.
    """
    def __init__(self, simpy_env, node_id, is_admin=False):
        self.simpy_env = simpy_env
        self.node_id = node_id
        self.ip = f"10.10.4.{node_id}"
        self.open_ports = random.sample([22, 80, 443], k=random.randint(1, 3))
        self.is_admin = is_admin
        self.file_access = simpy.Resource(simpy_env, capacity=1)

    def __repr__(self):
        return f"Device({self.node_id}, Admin={self.is_admin})"


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

        self.simpy_env = simpy.Environment()
        self.num_nodes = num_nodes
        self.devices = []
        self.graph = {}  # adjacency list
        self.agent_pos = None
        self.discovered = set()
        self.stealth_score = 5  # reduce when detection happens
        self.delay = delay

        # actions (0-9)
        self.action_space = spaces.Discrete(10)
        """ACTION SPACE
        - network scan
        - port scan
        - banner grab
        - exploit service
        - brute force login
        - pivot host
        - download file
        - stay idle
        - exit network
        """
        print(f"NUMBER OF ACTIONS: {self.action_space.n}")
        self.nA = self.action_space.n  # number of actions

        # observation: discovered nodes + current node ID + stealth
        self.observation_space = spaces.Dict({
            "current_node": spaces.Discrete(num_nodes),
            "discovered": spaces.MultiBinary(num_nodes),
            "stealth_score": spaces.Box(0, 10, shape=(1,), dtype=np.float32)
        })

        # number of states (states = agent's current knowledge)
        self.nS = len(self.observation_space)

        # create the random network
        self.generate_network()
        plt.ion()  # enables interactive plotting
        
    def generate_network(self):
        """
        Creates a simulated network with SimPy devices and random topology.
        """
        self.devices = []

        for i in range(self.num_nodes):
            is_admin = True if i == 0 else random.choice([False, False, True])  # ensure 1 admin
            dev = Device(self.simpy_env, i, is_admin)
            self.devices.append(dev)

        # create a simple random adjacency list (graph)
        for i in range(self.num_nodes):
            neighbors = random.sample(range(self.num_nodes), k=random.randint(1, 3))
            self.graph[i] = list(set(neighbors) - {i})  # no self-loops


    def reset(self):
        """
        Resets the environment to the beginning of a new episode and returns the initial observation.
        """
        self.simpy_env = simpy.Environment()
        self.agent_pos = random.randint(0, self.num_nodes-1)
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
        # One-hot encode current_node
        current_node_vec = np.eye(num_nodes)[obs["current_node"]]

        # Discovered is already binary vector of size num_nodes
        discovered_vec = obs["discovered"]

        # Stealth score is already a 1-element array
        stealth_vec = obs["stealth_score"]

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
                - 2: t-shark/sniff traffic
                - 3: signature detection
                - 4: anomaly rules
                - 5: pivot host
                - 6: download file
                - 7: banner grab
                - 8: idle
                - 9: exit
        """
        reward = 0
        done = False
        action_taken = ""
        device = self.devices[self.agent_pos]

        if action == 0:  # port scan
            reward += 1
            action_taken = "port scan"

        elif action == 1:  # network scan
            neighbors = self.graph[self.agent_pos]
            for n in neighbors:
                if n not in self.discovered:
                    self.discovered.add(n)
                    reward += 1
                else:  # negative reward for going back to a discovered node (prevents infinite loops)
                    reward -= 2
            action_taken = "network scan"

        elif action == 2:  # t-shark
            reward += 2
            action_taken = "sniffing traffic"

        elif action == 3:  # signature detection
            reward += 2
            action_taken = "signature detection"

        elif action == 4:  # anomaly rules
            reward += 3
            action_taken = "anomaly rules"

        elif action == 5:  # pivot host
            reward += 3
            action_taken = "pivot host"

        elif action == 6:  # download file
            with device.file_access.request() as req:
                self.simpy_env.process(self.simpy_env.timeout(1))  # simulate access delay
                reward += 3            
            action_taken = "downloading a file"

        elif action == 7:  # banner grab
            reward += 3
            action_taken = "grabbing a banner"

        elif action == 8:  # idle
            reward -= 0.5
            action_taken = "waiting"

        elif action == 9:  # exit
            done = True
            reward += 2
            action_taken = "exiting network"

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
        G = nx.Graph()

        # add nodes and edges
        for node, neighbors in self.graph.items():
            G.add_node(node)
            for n in neighbors:
                G.add_edge(node, n)

        node_colors = []
        node_sizes = []

        for node in G.nodes:
            if node == self.agent_pos:
                node_colors.append("red")  # current position
                node_sizes.append(800)
            elif node in self.discovered:
                node_colors.append("green")  # discovered
                node_sizes.append(500)
            elif self.devices[node].is_admin:
                node_colors.append("orange")  # admin but not discovered yet
                node_sizes.append(500)
            else:
                node_colors.append("gray")  # unknown
                node_sizes.append(300)

            pos = nx.spring_layout(G, seed=42)

        plt.clf()
        nx.draw(
            G,
            pos,
            with_labels=True,
            node_color=node_colors,
            node_size=node_sizes,
            font_color="white"
        )

        plt.title(f"Agent Position: {self.agent_pos} | Stealth: {self.stealth_score}")
        plt.pause(0.5)

        # return (f"Agent at: {self.agent_pos}, Discovered: {self.discovered}")
    
    def close(self):
        pass

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