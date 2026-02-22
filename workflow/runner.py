from workflow.graph import build_mas_graph

def output_graph_png(graph):
    wf_graph = graph.get_graph().draw_mermaid_png()

    with open("surge_graph.png", "wb") as f:
        f.write(wf_graph)

    print("Graph saved as 'surge_graph.png")

def run_workflow(initial_state: dict) -> dict:
    """
    Executes the compiled MAS graph.
    """

    graph = build_mas_graph()

    # COMMENT OUT (this is just so we can get a visual)
    output_graph_png(graph)

    final_state = graph.invoke(initial_state)

    return final_state

