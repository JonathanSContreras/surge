# building a network with 20 nodes


import networkx as nx
import matplotlib.pyplot as plt
import random

def build_network(num_nodes=20):  # ground truth network for the agent to discover
    node_colors = []
    node_sizes = []
    G = nx.erdos_renyi_graph(num_nodes, 0.3)  # random connectivity
    for node in G.nodes:
        G.nodes[node]["ip"] = f"10.10.4.{node+1}"
        G.nodes[node]["admin"] = True if node == 0 else random.choice([True, False])
        G.nodes[node]["open_ports"] = random.sample([22, 80, 443], k=random.randint(1, 3))
        G.nodes[node]["services"] = {"80": "http", "22": "ssh", "443": "https"}

        # based if it is an admin or not change the color of the node and the size
        node_colors.append("#ffc300") if G.nodes[node]["admin"] == True else node_colors.append("#1f78b4")
        node_sizes.append(600) if G.nodes[node]["admin"] == True else node_sizes.append(300)

    # print(node_colors)
    # print(node_sizes)
    print(G.nodes[node])
    nx.draw(G, pos=nx.spring_layout(G), node_color=node_colors, node_size=node_sizes, with_labels=True)

    # save the graph
    plt.savefig("network.png")
    plt.show()
    
    return G



def test():
    lst = []

    for i in range(20):
        print(i)
        lst.append(i) if i==10 else print("not 10")

        print(lst)

    print(lst)

    


if __name__ == "__main__":
    build_network()
