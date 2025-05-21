# this will be a test so that the log file can hold more information in a log file (nodes discovered, information discovered, etc)

"""WHAT I WANT
i want something like this 

5/21/2025 12:03 PM
    Agent at NODE NUMBER -> action taken

    Timestamp: 2025-05-19 17:06:14.454247, Action Taken: port scan

"""


def values():
    # method to output fake values
    node = 12
    action_taken = "port scanned"
    port = 80
    
    return f"Timestamp: 2025-05-21 17:06:14.454247 -> Agent at node: {node}, Action Taken: {action_taken}, Port: {port}"

print(values())