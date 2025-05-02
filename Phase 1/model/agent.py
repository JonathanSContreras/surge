"""
    Deep Q-Learning AI Agent.
    @author :  Brianna Hinds

    REFERENCES: 
    https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html
""" 

import numpy as np
import random
import math
from collections import namedtuple, deque
import matplotlib.pyplot as plt

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

# REPLAY MEMORY
Transition = namedtuple("Transition", ("state", "action", "next_state", "reward"))

class ReplayMemory(object):
    """
    Stores the observations of the agent in tuples.

    CLASS CONTENTS
        __init__
        push
        sample
        __len__
    """
    def __init__(self, capacity):
        """
        DESCRIPTION

        ARGS
            capacity: 
        """
        self.memory = deque([], maxlen=capacity)

    def push(self, *args):
        """Save a transition."""
        self.memory.append(Transition(*args))

    def sample(self, batch_size):
        """
        Selecting a random batch of transitions for training.

        ARGS
            batch_size: 
        """
        return random.sample(self.memory, batch_size)

    def __len__(self):
        """
        Length of the memory.
        """
        return self.memory
    
class DQN(nn.Module):
    """
    Deep-Q Learning network responsible for approximating Q-values.

    CLASS CONTENTS
        __init__
        forward
    """

    def __init__(self, n_observations, n_actions):
        super(DQN, self).__init__()

        # network architecture
        self.l1 = nn.Linear(n_observations, 128)
        self.l2 = nn.Linear(128, 128)
        self.l3 = nn.Linear(128, n_actions)

    def forward(self, x):
        """
        Feed-forward function for the Deep-Q Learning NN.

        ARGS
            x: 
        """
        x = F.relu(self.l1(x))
        x = F.relu(self.l2(x))

        return self.l3

# THINK OF A NAME FOR THE AI AGENT :)
class Agent: 
    """
    Brain that interacts with the network environment. Manages episodes, choose actions, optimizes the DQN.

    CLASS CONTENTS
        __init__
        select_action
        optimize_model
        plot_durations
    """
    def __init__(self, env, state_dim, action_dim):
        # hyperparameter definitions
        self.env = env
        self.steps_done = 0
        self.batch_size = 128
        self.gamma = 0.99
        self.eps_start = 0.9
        self.eps_end = 0.05
        self.eps_delay = 1000
        self.tau = 0.005 #?
        self.lr = 0.0001

        # model instantiation
        self.policy_net = DQN(state_dim, action_dim)
        self.target_net = DQN(state_dim, action_dim)
        self.target_net.load_state_dict(self.policy_net.state_dict())

        # optimizer
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=self.lr, amsgrad=True)
        self.agent_memory = ReplayMemory(10000)

    def select_action(self, state):
        global steps_done
        self.sample = random.random()

        self.eps_threshold = self.eps_end + (self.eps_start - self.eps_end) * math.exp(-1 * steps_done / self.eps_delay)
        steps_done += 1

        if self.sample > self.eps_threshold:
            with torch.no_grad():
                # t.max(1) returns the highest largest column value for each row
                return self.policy_net(state).max(1).indices.view(1, 1)
        else:
            return torch.tensor([[self.env.action_space.sample()]], dtype=torch.long)
        
        self.episode_durations = []
   
    def optimize_model(self):
        if len(self.agent_memory) < self.batch_size:
            return
        
        self.transitions = self.agent_memory.sample(self.batch_size)
        
        # transpose batch
        self.batch = Transition(*zip(self.transitions))

        # compute mask of non-final states and concatenate the batch elements
        self.non_final_mask = torch.tensor(tuple(map(lambda s: s is not None, self.batch.next_state)), dtype=torch.bool)
        self.non_final_next_states = torch.cat([s for s in self.batch.next_state if s is not None])
        self.state_batch = torch.cat(self.batch.state)
        self.action_batch = torch.cat(self.batch.action)
        self.reward_batch = torch.cat(self.batch.reward)

        # compute Q(s_t, a) -> actions that would have been taken for each state according to policy_net
        self.state_action_values = self.policy_net(self.state_batch).gather(1, self.action_batch)

        # compute V(s_{t+1}) -> expected value of actions for non-final-next-states
        self.next_state_values = torch.zeros(self.batch_size)
        with torch.no_grad():
            self.next_state_values[self.non_final_mask] = self.target_net(self.non_final_next_states).max(1).values

        # compute the expected Q values
        self.expected_state_action_values = (self.next_state_values * self.gamma) + self.reward_batch

        # compute Huber loss
        self.criterion = nn.SmoothL1Loss()
        self.loss = self.criterion(self.state_action_values, self.expected_state_action_values.unsqueeze(1))

        # optimize the model
        self.optimizer.zero_grad()
        self.loss.backward()

        # in place gradient-clipping
        nn.utils.clip_grad_value_(self.policy_net.parameters(), 100)
        self.optimizer.step()

        # train model
        self.epochs = 500
        self.training(self.epochs)

    def training(self, epochs):
        """
        Main training loop.

        ARGS
            epochs: number of times the agent will attempt to explore the network (episode ends at terminal states)
        """
        for episode in range(epochs):
            state, pos, score = self.env.reset()
            self.state = torch.tensor(state, dtype=torch.float32).unsqueeze(0)

            for t in pos():
                self.action = self.select_action(state)
                observation, reward, terminated, truncated = self.env.step(self.action.item())
                self.reward = torch.tensor([reward]) 
                done = terminated or truncated

                if terminated:
                    self.next_state = None
                else:
                    self.next_state = torch.tensor(observation, dtype=torch.float32).unsqueeze(0)

                # store the agent's transition in memory
                self.agent_memory.push(self.state, self.action, self.next_state, self.reward)

                # move to the next state
                self.state = self.next_state
                self.total_reward = self.reward.item()

                # perform one step of the optimization (on policy network)
                self.optimize_model()

                # soft update of the target network's weight
                self.target_net_state_dict = self.target_net.state_dict()
                self.policy_net_state_dict = self.policy_net.state_dict()

                for key in self.policy_net_state_dict:
                    self.target_net_state_dict[key] = self.policy_net_state_dict[key]*self.tau + self.target_net_state_dict[key]*(1-self.tau)
                
                self.target_net.load_state_dict(self.target_net_state_dict)

                if done:
                    self.episode_duration.append(t+1)
                    self.plot_durations()
                    break

            print(f"Episode {episode + 1}, Total Reward: {self.total_reward}")


        
    def plot_durations(self, show_results=False):
        plt.figure(1)
        self.durations_t = torch.tensor(self.episode_durations, dtype=torch.float)

        if show_results:
            plt.title("Result")
        else:
            plt.clf()
            plt.title("Training...")

        plt.xlabel("Episode")
        plt.ylabel("Duration")
        plt.plot(self.durations_t.numpy())

        # take 100 episode average and plot 
        if len(self.durations_t) >= 100:
            means = self.durations_t.unfold(0, 100, 1).mean(1).view(-1)
            means = torch.cat((torch.zeros(99), means))
            plt.plot(means.numpy())

        plt.show()

    def display_state(self):
        pass



    # def choose_action(self, state):
    #     """
    #     Returns an action based on the e-greedy policy. A random uniform number is selected to determine whether the next action should be random or deterministic.

    #     ARGS
    #         state: current condition of the agent (the agent's knowledge)
    #     """

    #     if np.random.uniform() < self.epsilon_greedy:
    #         action = np.random.choice(self.env.nA)
    #     else:
    #         q_vals = self.q_table[state]
    #         perm_actions = np.random.permutation(self.env.nA)
    #         q_vals = [q_vals[a] for a in perm_actions]
    #         perm_q_argmax = np.argmax(q_vals)
    #         action = perm_actions[perm_q_argmax]

    #     return action

    # def _learn(self, transition):
    #     """
    #     Updates the rule for the Q-learning algorithn.

    #     ARGS
    #         transition:
    #     """
    #     s, a, r, next_s, done = transition
    #     q_val = self.q_table[s][a]

    #     if done:
    #         q_target = r
    #     else:
    #         q_target = r + self.discount_factor*np.max(self.q_table[next_s])

    #     # update q_table
    #     self.q_table[s][a] += self.lr * (q_target - q_val)

    #     # adjust the epsilon
    #     self._adjust_epsilon()

    # def _adjust_epsilon(self):
    #     """
    #     Adjusts the epsilon value until it reaches the minimum epsilon value.
    #     """
    #     if self.epsilon_greedy > self.epsilon_min:
    #         self.epsilon_greedy *= self.decay

    # def display_state(self):
    #     """
    #     After the end of each episode the nodes that the model discovers will be diplayed.
    #         - green nodes = discovered
    #         - red nodes = not discovered
    #     """
    #     pass
