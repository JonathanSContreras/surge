import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  SimulationNodeDatum,
  SimulationLinkDatum,
} from 'd3-force';
import { ForceNode, ForceEdge, NetworkTopology } from '../types/network-topology';

export function createForceSimulation(
  nodes: ForceNode[],
  edges: ForceEdge[],
  width: number,
  height: number
) {
  // Clone nodes to avoid mutation
  const simulationNodes = nodes.map(n => ({ ...n })) as (ForceNode & SimulationNodeDatum)[];

  // Dynamic spacing based on node count
  const nodeCount = nodes.length;

  // Adjust forces based on network size
  // More nodes = more spacing needed
  const linkDistance = nodeCount <= 8 ? 80 : nodeCount <= 15 ? 100 : 120;
  const chargeStrength = nodeCount <= 8 ? -300 : nodeCount <= 15 ? -400 : -500;
  const collisionRadius = nodeCount <= 8 ? 30 : nodeCount <= 15 ? 35 : 40;

  // Create simulation
  const simulation = forceSimulation(simulationNodes)
    .force(
      'link',
      forceLink<ForceNode & SimulationNodeDatum, SimulationLinkDatum<ForceNode & SimulationNodeDatum>>(edges)
        .id((d: any) => d.id)
        .distance(linkDistance)        // Distance between connected nodes (dynamic)
        .strength(1)                   // Link strength
    )
    .force(
      'charge',
      forceManyBody()
        .strength(chargeStrength)      // Repulsion force (dynamic, more negative = more repel)
    )
    .force('center', forceCenter(width / 2, height / 2))
    .force('collision', forceCollide().radius(collisionRadius)); // Prevent overlap (dynamic)

  return simulation;
}

export function transformTopologyData(topology: NetworkTopology): {
  nodes: ForceNode[];
  edges: ForceEdge[];
} {
  return {
    nodes: topology.devices.map(d => ({ ...d })),
    edges: topology.connections.map(c => ({
      ...c,
      source: c.from,
      target: c.to,
    })),
  };
}
