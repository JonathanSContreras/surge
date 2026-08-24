# Network Topology Graph - Force-Directed Layout Guide

## Overview

The network topology graph now supports automatic force-directed layout using D3.js, creating an organic, Obsidian-style visualization of your network.

## Features

✅ **Force-Directed Layout** - Nodes automatically arrange themselves organically
✅ **Dynamic Spacing** - Automatically adjusts spacing based on number of nodes (8, 15, or 50+ nodes)
✅ **Path Highlighting** - Connected edges light up in green when hovering on a node
✅ **Device Type Icons** - Visual icons for routers, servers, workstations, firewalls, etc.
✅ **Severity Coloring** - Color-coded nodes based on security risk levels
✅ **Interactive Tooltips** - Hover to see IP, hostname, device type, severity, and description
✅ **Smooth Animations** - Framer Motion animations for interactions
✅ **Future-Proof** - Designed for future expansion to rich connection metadata

## JSON Data Structure

### Basic Example

```json
{
  "devices": [
    {
      "id": "1",
      "ip": "192.168.1.10",
      "severity": "critical",
      "description": "Primary gateway with outdated firmware",
      "deviceType": "router",
      "hostname": "gateway-primary",
      "cvss": 9.8
    },
    {
      "id": "2",
      "ip": "192.168.1.45",
      "severity": "high",
      "description": "Database server with SQL injection vulnerability",
      "deviceType": "server"
    }
  ],
  "connections": [
    { "from": "1", "to": "2" },
    { "from": "1", "to": "3" }
  ]
}
```

### Required Fields

#### Device (Node)
- `id` (string) - Unique identifier
- `ip` (string) - IP address (displayed in tooltip)
- `severity` ("low" | "medium" | "high" | "critical") - Risk severity level
- `deviceType` ("router" | "switch" | "firewall" | "server" | "workstation" | "iot" | "unknown")

#### Connection (Edge)
- `from` (string) - Source device ID
- `to` (string) - Target device ID

### Optional Fields

#### Device
- `description` (string) - Description shown in tooltip
- `hostname` (string) - Device hostname
- `cvss` (number) - CVSS vulnerability score
- `status` ("online" | "offline" | "scanning")
- `metadata` (object) - Custom data for your use case

#### Connection
- `connectionType` (string) - Type of connection (reserved for future use)
- `bandwidth` (number) - Connection bandwidth (reserved for future use)
- `latency` (number) - Connection latency (reserved for future use)
- `protocol` (string) - Network protocol (reserved for future use)
- `strength` (number) - Link strength for layout algorithm

### Network Topology Wrapper
- `scanDate` (string) - ISO timestamp of scan
- `networkName` (string) - Name of the network
- `metadata` (object) - Custom metadata

## Device Types & Icons

| Device Type | Icon | Use Case |
|------------|------|----------|
| `router` | Router icon | Gateways, routers |
| `switch` | CPU icon | Network switches |
| `firewall` | Shield icon | Firewalls, security appliances |
| `server` | Server icon | Database, web, app servers |
| `workstation` | Monitor icon | Desktop computers |
| `iot` | CPU icon | IoT devices, sensors |
| `unknown` | Help circle | Unidentified devices |

## Severity Levels & Colors

| Severity | Color | Hex |
|----------|-------|-----|
| `critical` | Red | #FF1744 |
| `high` | Orange-red | #FF6F00 |
| `medium` | Orange | #FFB300 |
| `low` | Green | #00E676 |

Critical severity nodes also get a glowing halo effect.

## Usage

### Toggle Between Layouts

In `Dashboard.tsx`:

```typescript
// Set to true for force-directed, false for original static layout
const USE_FORCE_LAYOUT = true;

{USE_FORCE_LAYOUT ? (
  <NetworkGraphForce
    topology={yourNetworkData}
    hoveredDeviceId={hoveredDeviceId}
  />
) : (
  <NetworkGraph hoveredDeviceId={hoveredDeviceId} />
)}
```

### Load Your Own Data

Replace the sample data in `Dashboard.tsx`:

```typescript
import { NetworkTopology } from '../_components/types/network-topology';

// Load from API
const [topology, setTopology] = useState<NetworkTopology | null>(null);

useEffect(() => {
  fetch('/api/network-topology')
    .then(res => res.json())
    .then(data => setTopology(data));
}, []);

// Or import from JSON file
import networkData from './data/my-network.json';
```

### Customize Force Simulation

The simulation automatically adjusts spacing based on node count:
- **≤8 nodes**: Tighter spacing (distance: 80, charge: -300, collision: 30)
- **9-15 nodes**: Medium spacing (distance: 100, charge: -400, collision: 35)
- **16+ nodes**: Wide spacing (distance: 120, charge: -500, collision: 40)

To manually adjust, edit `src/app/_components/utils/force-layout.ts`:

```typescript
export function createForceSimulation(...) {
  // Adjust these values for custom spacing
  const linkDistance = nodeCount <= 8 ? 80 : nodeCount <= 15 ? 100 : 120;
  const chargeStrength = nodeCount <= 8 ? -300 : nodeCount <= 15 ? -400 : -500;
  const collisionRadius = nodeCount <= 8 ? 30 : nodeCount <= 15 ? 35 : 40;
}
```

## File Structure

```
src/app/_components/
├── types/
│   └── network-topology.ts       # TypeScript interfaces
├── utils/
│   ├── force-layout.ts           # D3 force simulation logic
│   └── device-icons.tsx          # Device type icon mappings
├── data/
│   └── sample-topology.ts        # Sample network data
├── NetworkGraph.tsx              # Original static layout
└── NetworkGraphForce.tsx         # New force-directed layout
```

## Future Expansion

The JSON structure is designed to support rich connection metadata:

```typescript
{
  "connections": [
    {
      "from": "1",
      "to": "2",
      "connectionType": "tcp",
      "bandwidth": 1000,      // Mbps
      "latency": 15,          // ms
      "protocol": "https",
      "packetLoss": 0.01      // percentage
    }
  ]
}
```

Future features:
- Dashed/solid/animated edges based on connection type
- Edge width varies by bandwidth
- Edge color indicates connection health
- Edge tooltips with protocol/latency details
- Filter edges by type

## Performance

- **Throttled Updates**: Graph updates at ~30fps instead of 60fps for better performance
- **Tested**: Works smoothly with 100+ nodes
- **Optimization**: Simulation automatically stops after convergence
- **Tip**: For very large graphs (500+ nodes), consider reducing force strength or using clustering

## Troubleshooting

### Nodes Don't Appear
- Check that all device IDs are unique
- Verify `deviceType` is one of the valid types
- Ensure `severity` is one of: "low", "medium", "high", "critical"

### Connections Don't Render
- Verify `from` and `to` IDs match existing device IDs
- Check browser console for errors

### Layout Looks Chaotic
- Increase repulsion: change `strength(-300)` to `strength(-500)` in force-layout.ts
- Increase collision radius: change `.radius(30)` to `.radius(40)`
- Adjust link distance: change `.distance(80)` to `.distance(120)`

## Example: Complete Network

See `src/app/_components/data/sample-topology.ts` for a full example with 8 devices showing all device types and severity levels.
