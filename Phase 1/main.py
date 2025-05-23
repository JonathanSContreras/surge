# imports
from env.network import NetworkEnvironment
from model.agent import Agent

# initializes the imports
environment = NetworkEnvironment() 

# get the state and action size
state_size = environment.nS
action_size = environment.nA
print("state_size", state_size)
print("action_size", action_size)
bob = Agent(environment, state_size, action_size)  

# run an episode loop
print("Starting training loop")
epochs = 10  # start with 10, 50, 100 then go to 100 then 500
bob.training(epochs)  
print("Training done.")