'use client';

import { NetworkGraphForce } from '../_components/NetworkGraphForce';
import { sampleTopology } from '../_components/data/sample-topology';

export function Topology() {
  return (
    <div className="max-w-[1800px] mx-auto p-6">
      {/* Full-screen network graph */}
      <div style={{ height: 'calc(100vh - 120px)' }}>
        <NetworkGraphForce topology={sampleTopology} />
      </div>
    </div>
  );
}
