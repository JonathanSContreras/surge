import gym
from gym import spaces
import networkx as nx
import numpy as np
import matplotlib as plt  #visualize the what the agent discovers per episode
import random
import datetime

"""
    Custom wrapper class for OpenAI Gym.
"""
class NetworkEnvironment(gym.Env):
    def __init__(self, num_nodes=20):
        super(NetworkEnvironment, self).__init__()

        self.graph = None
        self.num_nodes = num_nodes
        self.agent_pos = None
        self.discovered = set()
        self.stealth_score = 5  # reduce when detection happens

        # actions (0-4)
        self.action_space = spaces.Discrete(5)

        # observation: discovered nodes + current node ID + stealth
        self.observation_space = spaces.Dict({
            "current_node": spaces.Discrete(num_nodes),
            "discovered": spaces.MultiBinary(num_nodes),
            "stealth_score": spaces.Box(0, 10, shape=(1,), dtype=np.float32)
        })

        # create the random network
        self.generate_network()
        

    def generate_network(self):
        """
        Creates a random network graph with attributes, using the Erdos-Renyi model.
        """
        self.graph = nx.erdos_renyi_graph(self.num_nodes, 0.3)
        for node in self.graph.nodes:
            self.graph.nodes[node]['ip'] = f"192.168.0.{node}"
            self.graph.nodes[node]['open_ports'] = random.sample([22, 80, 443], k=random.randint(1, 3))
            self.graph.nodes[node]['admin'] = random.choice([True, False])

    def reset(self):
        """
        Resets the environment to the beginning of a new episode and returns the initial observation.
        """
        self.agent_pos = random.choice(list(self.graph_nodes))
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
    
    # NEED TO ADD MORE TO EXPLORE, DISCOVER AND DETECT
    # LOG ACTIONS
    def step(self, action):
        """
        Takes an action from the agent, updates the environment, and returns the next state, reward, and done flag.

        :action: Action taken by the agent.
            - 0: port scan
            - 1: network scan (try unknown devices)
            - 2: t-shark/sniff traffic
            - 3: signature detection
            - 4: anomaly rules
        """
        reward = 0
        done = False
        action_taken = ""

        if action == 0:  # port scan
            reward += 1
            action_taken = "port scan"
        elif action == 1:  # network scan
            new_nodes = list(self.graph.neighbors(self.agent_pos))
            for n in new_nodes:
                if n not in self.discovered:
                    self.discovered.add(n)
                    reward += 1
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

        # risk of being caught
        if random.random() < 0.1:
            self.stealth_score -= 1
            reward -= 1

        # write to a log file
        timestamp = datetime.datetime.now()
        with open("Phase 1\utils\log.txt", "a") as f:
            f.write(f"Timestamp: {timestamp}, Action Taken: {action_taken}")


        # if stealth is all gone
        if self.stealth_score < 0:
            done = True

        return self._get_obs(), reward, done, {}

    def render(self, mode="human"):
        """
        Returns a summary of the movements of the agent.

        :mode: the type of rendering (human = readable by a person)
        """
        return (f"Agent at: {self.agent_pos}, Discovered: {self.discovered}")