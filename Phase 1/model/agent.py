"""
Deep Q-Learning AI Agent.
@author :  Brianna Hinds

REFERENCES: 
https://pytorch.org/tutorials/intermediate/reinforcement_q_learning.html
""" 

# import numpy as np
import random
import math
from collections import namedtuple, deque
import matplotlib.pyplot as plt

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

# REPLAY MEMORY: experience replay
Transition = namedtuple("Transition", ("state", "action", "next_state", "reward"))

class ReplayMemory(object):
    """
    Stores the observations of the agent in tuples.

    CLASS CONTENTS
        __init__
        push
        sample
        __len__
        reset
    """
    def __init__(self, capacity):
        """
        Inititalization of the agent's Memory.

        ARGS
            capacity: defined as how long the agent's memory will be
        """
        self.memory = deque([], maxlen=capacity)

    def push(self, *args):
        """
        Save a transition
        """
        self.memory.append(Transition(*args))

    def sample(self, batch_size):
        """
        Selecting a random batch of transitions for training.

        ARGS
            batch_size: number of values to get at each sampling
        """
        return random.sample(self.memory, batch_size)

    def __len__(self):
        """
        Length of the memory.
        """
        return len(self.memory)
    
    def reset(self):
        """
        Resetting the memory of the agent.
        """
        self.memory.clear()
    
class DQN(nn.Module):
    """
    Deep-Q Learning network responsible for approximating Q-values.

    CLASS CONTENTS
        __init__
        forward
    """

    def __init__(self, n_observations, n_actions):
        """
        Initializer for the DQN model, defines the NN.

        ARGS
            n_observations: input value for the NN model
            n_actions: output value for the NN model (choices the agent can do)
        """
        super(DQN, self).__init__()

        # network architecture
        # print("number of observations:", n_observations)
        self.l1 = nn.Linear(n_observations, 128)
        self.l2 = nn.Linear(128, 128)
        self.l3 = nn.Linear(128, n_actions)

    def forward(self, x):
        """
        Feed-forward function for the Deep-Q Learning NN.

        ARGS
            x: the input data to the network
        """
        x = F.relu(self.l1(x))
        x = F.relu(self.l2(x))

        return self.l3(x)

# THINK OF A NAME FOR THE AI AGENT :)
class Agent: 
    """
    Brain that interacts with the network environment. Manages episodes, chooses actions, optimizes the DQN.

    CLASS CONTENTS
        __init__
        select_action
        optimize_model
        plot_durations
    """
    def __init__(self, env, state_dim, action_dim):
        """
        Initializer for the Agent's NN model, defines the hyperparameters and important values to the Bellman equation.

        ARGS
            env: environment object for the model to learn in
            state_dim: dimension of the agent's state
            action_dim: dimension of the agent's actions (number of actions the agent can do)
        """
        # hyperparameter definitions
        # using a epsilon greedy exploration
        self.env = env
        self.steps_done = 0
        self.batch_size = 128  # number of transitions sampled from the buffer
        self.gamma = 0.99  # discount factor
        self.eps_start = 0.9  # starting value of epsilon
        self.eps_end = 0.05  # ending value of epsilon
        self.eps_decay = 1000  # controls the rate of exponential decay (higher = slower decay)
        self.tau = 0.005 # update rate of the target network
        self.lr = 0.0001  # learning rate of the Adam optimizer

        self.steps_done = 0
        self.episode_durations = []

        # model instantiation
        self.policy_net = DQN(state_dim, action_dim)
        self.target_net = DQN(state_dim, action_dim)
        self.target_net.load_state_dict(self.policy_net.state_dict())

        # optimizer
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=self.lr, amsgrad=True)
        self.agent_memory = ReplayMemory(10000)

    def preprocess_state(self, state):
        """
        Flattens the state, to be pushed into the DQN as a Tenor object

        ARGS:
            state: dictionary object that contains what node the agent is on, node's discovered, and stealth score
        """
        flat_state = self.env.flatten_observation(state, self.env.num_nodes)
        return torch.tensor(flat_state, dtype=torch.float32).unsqueeze(0)

    def select_action(self, state):  # state is already flatten and turned in a tensor
        """
        Select an action according to an epsilon greedy policy.

        ARGS:
            state: flattened Tensor object that contains what node the agent is on, node's discovered, and stealth score
        """
        # print(f"in select_action method: {state}")
        # flatten_state = self.env.flatten_observation(state, self.env.num_nodes)
        # flatten_state_tensor = torch.tensor(flatten_state, dtype=torch.float32)
        
        # epsilon greedy
        print("state size", len(state))
        self.sample = random.random()
        self.eps_threshold = self.eps_end + (self.eps_start - self.eps_end) * math.exp(-1. * self.steps_done / self.eps_decay)
        self.steps_done += 1

        if self.sample > self.eps_threshold:
            with torch.no_grad():
                # t.max(1) returns the highest largest column value for each row
                # print("in select_action function: STATE", state)
                return self.policy_net(state).max(1).indices.view(1, 1)  # ERROR LINE
        else:
            return torch.tensor([[self.env.action_space.sample()]], dtype=torch.long)
        
   
    def optimize_model(self):
        """
        Performs a single step of the optimization.
        """
        if len(self.agent_memory) < self.batch_size:
            return
        
        # sample and concatentate random batch
        # https://stackoverflow.com/a/19343/3343043  converts batch-array of Transitions to Transition of batch-arrays
        self.transitions = self.agent_memory.sample(self.batch_size)
        self.batch = Transition(*zip(*self.transitions))

        # compute mask of non-final states and concatenate the batch elements
        self.non_final_mask = torch.tensor(tuple(map(lambda s: s is not None, self.batch.next_state)), dtype=torch.bool)
        self.non_final_next_states = torch.cat([s for s in self.batch.next_state if s is not None])
        self.state_batch = torch.cat(self.batch.state)
        self.action_batch = torch.cat(self.batch.action)
        self.reward_batch = torch.cat(self.batch.reward)

        # compute Q(s_t, a) -> the model will compute Q(s_t) and then the actions that would have been taken for each state according to policy_net
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

        # # train model
        # self.epochs = 500
        # self.training(self.epochs)

    def training(self, epochs):
        """
        Main training loop.

        ARGS
            epochs: number of times the agent will attempt to explore the network (episode ends at terminal states)
        """
        for episode in range(epochs):
            # reset the environment and get the initial state
            obs = self.env.reset()
            self.state = self.preprocess_state(obs)
            print("in training method", self.state)


            """NOTE
            obs : state, pos and score of the agent all together
            """
            self.total_reward = 0
            max_steps_per_episode = 100
            for t in range(max_steps_per_episode):
                # print(t)
                # print(pos)
                self.action = self.select_action(self.state)
                next_obs, reward, terminated, truncated = self.env.step(self.action.item())
                print(self.env.render())  # graph of what the agent just discovered

                self.reward = torch.tensor([reward], dtype=torch.float32) 
                done = terminated or truncated

                if terminated:
                    print("was terminated")
                    self.next_state = None
                else:
                    # flatten the observation to feed into the NN
                    self.next_state = self.preprocess_state(next_obs)

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
                    self.target_net_state_dict[key] = self.policy_net_state_dict[key] * self.tau + self.target_net_state_dict[key] * (1 - self.tau)
                
                self.target_net.load_state_dict(self.target_net_state_dict)

                if done:
                    self.episode_durations.append(t + 1)
                    self.plot_durations()
                    break

            print(f"Episode {episode + 1}, Total Reward: {self.total_reward}, Epsilon Value: {self.eps_threshold:.4f}")

    def plot_durations(self, show_results=False):
        """
        Helper for plotting duration of episodes.
        """
        plt.figure(1)
        self.durations_t = torch.tensor(self.episode_durations, dtype=torch.float)

        if show_results:
            plt.title("Result")
        else:
            plt.clf()
            plt.title("Training...")

        plt.xlabel("Episode")
        plt.ylabel("Duration (steps)")
        plt.plot(self.durations_t.numpy())

        # take 100 episode average and plot 
        if len(self.durations_t) >= 100:
            means = self.durations_t.unfold(0, 100, 1).mean(1).view(-1)
            means = torch.cat((torch.zeros(99), means))
            plt.plot(means.numpy())

        plt.pause(2)
        # plt.show()