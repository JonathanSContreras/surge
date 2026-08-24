from __future__ import annotations

from typing import AsyncGenerator, Any

from workflow.graph import build_mas_graph

def output_graph_png(graph):
    wf_graph = graph.get_graph().draw_mermaid_png()

    with open("surge_graph.png", "wb") as f:
        f.write(wf_graph)

    print("Graph saved as 'surge_graph.png")

def run_workflow(initial_state: dict) -> dict:
    """
    Executes the compiled MAS graph (synchronous, CLI path).
    """

    graph = build_mas_graph()

    # COMMENT OUT (this is just so we can get a visual)
    output_graph_png(graph)

    final_state = graph.invoke(initial_state)

    return final_state


def stream_workflow(initial_state: dict) -> Any:
    """
    Returns a synchronous generator that yields one dict per completed node.
    Each yielded value has the shape: { node_name: state_update_dict }

    Intended to be consumed inside a thread-pool worker (run_in_executor)
    so the FastAPI event loop is never blocked.

    Example usage in an async context:
        loop = asyncio.get_running_loop()
        gen = await loop.run_in_executor(None, lambda: list(stream_workflow(state)))
    """
    graph = build_mas_graph()
    return graph.stream(initial_state)

