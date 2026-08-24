import { describe, it, expect } from 'vitest';
import { transformTopologyData, createForceSimulation } from '../utils/force-layout';
import { NetworkTopology } from '../types/network-topology';

describe('force-layout utilities', () => {
  const mockTopology: NetworkTopology = {
    devices: [
      { id: '1', ip: '192.168.1.1', severity: 'low', deviceType: 'router' },
      { id: '2', ip: '192.168.1.2', severity: 'high', deviceType: 'server' },
    ],
    connections: [
      { from: '1', to: '2' },
    ],
  };

  describe('transformTopologyData', () => {
    it('should transform devices to force nodes', () => {
      const { nodes } = transformTopologyData(mockTopology);
      
      expect(nodes).toHaveLength(2);
      expect(nodes[0].id).toBe('1');
      expect(nodes[0].ip).toBe('192.168.1.1');
    });

    it('should transform connections to force edges', () => {
      const { edges } = transformTopologyData(mockTopology);
      
      expect(edges).toHaveLength(1);
      expect(edges[0].source).toBe('1');
      expect(edges[0].target).toBe('2');
    });
  });

  describe('createForceSimulation', () => {
    it('should create a simulation with correct node count', () => {
      const { nodes, edges } = transformTopologyData(mockTopology);
      const simulation = createForceSimulation(nodes, edges, 800, 600);
      
      expect(simulation.nodes()).toHaveLength(2);
    });

    it('should constrain nodes within bounds after tick', () => {
      const { nodes, edges } = transformTopologyData(mockTopology);
      const width = 400;
      const height = 300;
      const simulation = createForceSimulation(nodes, edges, width, height);
      
      simulation.tick(100);
      
      const simNodes = simulation.nodes();
      simNodes.forEach(node => {
        expect(node.x).toBeGreaterThanOrEqual(40);
        expect(node.x).toBeLessThanOrEqual(width - 40);
        expect(node.y).toBeGreaterThanOrEqual(40);
        expect(node.y).toBeLessThanOrEqual(height - 40);
      });
    });
  });
});
