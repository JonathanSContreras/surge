import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  forceX,
  forceY,
  SimulationNodeDatum,
  SimulationLinkDatum,
} from 'd3-force';
import { ForceNode, ForceEdge, NetworkTopology } from '../types/network-topology';

const PADDING = 40;
const NODE_RADIUS = 16;

export function createForceSimulation(
  nodes: ForceNode[],
  edges: ForceEdge[],
  width: number,
  height: number
) {
  const simulationNodes = nodes.map(n => ({ ...n })) as (ForceNode & SimulationNodeDatum)[];

  const nodeCount = nodes.length;
  const linkDistance = nodeCount <= 8 ? 80 : nodeCount <= 15 ? 100 : 120;
  const chargeStrength = nodeCount <= 8 ? -300 : nodeCount <= 15 ? -400 : -500;
  const collisionRadius = nodeCount <= 8 ? 30 : nodeCount <= 15 ? 35 : 40;

  const centerX = width / 2;
  const centerY = height / 2;

  const simulation = forceSimulation(simulationNodes)
    .force(
      'link',
      forceLink<ForceNode & SimulationNodeDatum, SimulationLinkDatum<ForceNode & SimulationNodeDatum>>(edges)
        .id((d: ForceNode & SimulationNodeDatum) => d.id)
        .distance(linkDistance)
        .strength(1)
    )
    .force(
      'charge',
      forceManyBody()
        .strength(chargeStrength)
    )
    .force('center', forceCenter(centerX, centerY))
    .force('collision', forceCollide().radius(collisionRadius))
    .force('x', forceX(centerX).strength(0.05))
    .force('y', forceY(centerY).strength(0.05));

  simulation.on('tick', () => {
    const minX = PADDING + NODE_RADIUS;
    const maxX = width - PADDING - NODE_RADIUS;
    const minY = PADDING + NODE_RADIUS;
    const maxY = height - PADDING - NODE_RADIUS;

    simulationNodes.forEach(node => {
      if (node.x !== undefined && node.y !== undefined) {
        node.x = Math.max(minX, Math.min(maxX, node.x));
        node.y = Math.max(minY, Math.min(maxY, node.y));
      }
    });
  });

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
