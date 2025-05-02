# imports
from env.network import NetworkEnvironment
from model.agent import Agent

# initializes the imports
environment = NetworkEnvironment()  # ERROR NETWORK LINE self.nA (object of type discrete has no len())

# get the state and action size
state_size = environment.nS
action_size = environment.nA
bob = Agent(environment, state_size, action_size)

# run an episode loop
bob.training(500)