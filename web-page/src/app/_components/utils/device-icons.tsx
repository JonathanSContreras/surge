import { Router, Server, Monitor, Shield, Cpu, HelpCircle, Network, LucideIcon } from 'lucide-react';
import { DeviceType } from '../types/network-topology';

export const DEVICE_ICONS: Record<DeviceType, LucideIcon> = {
  router: Router,
  switch: Cpu,
  firewall: Shield,
  server: Server,
  workstation: Monitor,
  iot: Cpu,
  unknown: HelpCircle,
  subnet: Network,
};

export function getDeviceIcon(deviceType: DeviceType): LucideIcon {
  return DEVICE_ICONS[deviceType] || DEVICE_ICONS.unknown;
}
