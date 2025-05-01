"""
    Deep Q-Learning AI Agent.
    @author :  Brianna Hinds
""" 

import numpy as np
from collections import defaultdict

# THINK OF A NAME FOR THE AI AGENT :)
class Agent: 
    """
    DQL RL Pentester Agent.

    CLASS CONTENTS
        __init__
        choose_action
        _learn
        adjust_epsilon
        display_state
    """
    def __init__(self, env, lr=0.01, discount_factor=0.9, epsilon_greedy=0.9, epsilon_min=0.1, decay=0.95):
        self.env = env
        self.lr = lr
        self.discount_factor = discount_factor
        self.epsilon_greedy = epsilon_greedy
        self.epsilon_min = epsilon_min
        self.decay = decay

        # q-table
        self.q_table = defaultdict(lambda: np.zeros(self.env.nA))

    def choose_action(self, state):
        """
        Returns an action based on the e-greedy policy. A random uniform number is selected to determine whether the next action should be random or deterministic.

        ARGS
            state: 
        """

        if np.random.uniform() < self.epsilon_greedy:
            action = np.random.choice(self.env.nA)
        else:
            q_vals = self.q_table[state]
            perm_actions = np.random.permutation(self.env.nA)
            q_vals = [q_vals[a] for a in perm_actions]
            perm_q_argmax = np.argmax(q_vals)
            action = perm_actions[perm_q_argmax]

        return action

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
        if self.epsilon_greedy > self.epsilon_min:
            self.epsilon_greedy *= self.decay