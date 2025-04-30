"""
    Deep Q-Learning AI Agent.
    @author :  Brianna Hinds
""" 

import numpy as np
from collections import defaultdict

# THINK OF A NAME FOR THE AI AGENT :)
class Agent: 
    def __init__(self, env, lr=0.01, discount_factor=0.9, epsilon_greedy=0.9, epsilon_min=0.1, decay=0.95):
        self.env = env
        self.lr = lr
        self.discount_factor = discount_factor
        self.epsilon_greedy = epsilon_greedy
        self.epsilon_min = epsilon_min
        self.decay = decay

        # q-table
        self.q_table = defaultdict(lambda: np.zeros(self.env.nA))

    def choose_action(self):
        pass

    def _learn(self):
        pass

    def adjust_epsilon(self):
        pass

    def display_state(self):
        """
        After the end of each episode the nodes that the model discovers will be diplayed.
            - green nodes = discovered
            - red nodes = not discovered
        """
        pass