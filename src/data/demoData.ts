import type { SecurityEvent } from '../types/security';

// Primary attack sequence for Rahul (USR101) - INC-001
export const primaryAttackEvents: SecurityEvent[] = [
  {
    event_id: 'E001',
    timestamp: '2026-10-07 22:01:10',
    event_type: 'LOGIN',
    user_id: 'USR101',
    user_name: 'Rahul',
    device_id: 'DEV21',
    device_name: 'Laptop-99',
    ip_address: '185.44.21.8',
    application: 'VPN Gateway',
    server_id: '',
    server_name: '',
    destination_ip: '',
    severity: 'medium',
    description: 'Unusual login from unmapped geographical IP (185.44.21.8)',
  },
  {
    event_id: 'E002',
    timestamp: '2026-10-07 22:03:10',
    event_type: 'FAILED_LOGIN',
    user_id: 'USR101',
    user_name: 'Rahul',
    device_id: 'DEV21',
    device_name: 'Laptop-99',
    ip_address: '185.44.21.8',
    application: 'Active Directory / VPN',
    server_id: '',
    server_name: '',
    destination_ip: '',
    severity: 'high',
    description: '7 consecutive failed authentication attempts from new device',
  },
  {
    event_id: 'E003',
    timestamp: '2026-10-07 22:05:10',
    event_type: 'SERVER_ACCESS',
    user_id: 'USR101',
    user_name: 'Rahul',
    device_id: 'DEV21',
    device_name: 'Laptop-99',
    ip_address: '185.44.21.8',
    application: 'SSH / Bastion Host',
    server_id: 'SRV12',
    server_name: 'Server-12',
    destination_ip: '',
    severity: 'high',
    description: 'Privileged access established to core database Server-12',
  },
  {
    event_id: 'E004',
    timestamp: '2026-10-07 22:07:10',
    event_type: 'PROCESS_EXECUTION',
    user_id: 'USR101',
    user_name: 'Rahul',
    device_id: 'DEV21',
    device_name: 'Laptop-99',
    ip_address: '185.44.21.8',
    application: 'CrowdStrike EDR',
    server_id: 'SRV12',
    server_name: 'Server-12',
    destination_ip: '',
    severity: 'critical',
    description: 'Suspicious PowerShell execution: powershell -e aW52b2tlLW1pbWlrYXR6',
  },
  {
    event_id: 'E005',
    timestamp: '2026-10-07 22:10:10',
    event_type: 'NETWORK_CONNECTION',
    user_id: 'USR101',
    user_name: 'Rahul',
    device_id: 'DEV21',
    device_name: 'Laptop-99',
    ip_address: '185.44.21.8',
    application: 'Palo Alto Firewall',
    server_id: 'SRV12',
    server_name: 'Server-12',
    destination_ip: '91.22.18.4',
    severity: 'critical',
    description: 'Outbound TCP connection established to blacklisted IP 91.22.18.4:443',
  },
  {
    event_id: 'E006',
    timestamp: '2026-10-07 22:14:10',
    event_type: 'DATA_EXFILTRATION',
    user_id: 'USR101',
    user_name: 'Rahul',
    device_id: 'DEV21',
    device_name: 'Laptop-99',
    ip_address: '185.44.21.8',
    application: 'DLP Sentinel',
    server_id: 'SRV12',
    server_name: 'Server-12',
    destination_ip: '91.22.18.4',
    severity: 'critical',
    description: 'Encrypted payload stream (142MB) transferred to external host',
  },
];

// Scenario 2: Priya (USR204) - Lateral Movement
export const lateralMovementEvents: SecurityEvent[] = [
  {
    event_id: 'E101',
    timestamp: '2026-10-07 21:15:00',
    event_type: 'LOGIN',
    user_id: 'USR204',
    user_name: 'Priya',
    device_id: 'DEV44',
    device_name: 'Workstation-44',
    ip_address: '10.0.4.12',
    application: 'Windows RDP',
    server_id: 'SRV04',
    server_name: 'Server-04',
    severity: 'medium',
    description: 'RDP connection initiated across internal subnet boundaries',
  },
  {
    event_id: 'E102',
    timestamp: '2026-10-07 21:22:30',
    event_type: 'PROCESS_EXECUTION',
    user_id: 'USR204',
    user_name: 'Priya',
    device_id: 'DEV44',
    device_name: 'Workstation-44',
    ip_address: '10.0.4.12',
    application: 'EDR Agent',
    server_id: 'SRV04',
    server_name: 'Server-04',
    severity: 'high',
    description: 'WMI query invoked to enumerate domain controller administrators',
  }
];

// Helper to generate 5000 realistic background events
export function generate5000DemoEvents(): SecurityEvent[] {
  const users = [
    { id: 'USR101', name: 'Rahul' },
    { id: 'USR102', name: 'Amit' },
    { id: 'USR103', name: 'Neha' },
    { id: 'USR104', name: 'Siddharth' },
    { id: 'USR204', name: 'Priya' },
    { id: 'USR309', name: 'Vikram' },
    { id: 'USR107', name: 'Ananya' },
    { id: 'USR108', name: 'Rohan' },
    { id: 'USR109', name: 'Kavya' },
    { id: 'USR110', name: 'Rajesh' },
  ];

  const devices = [
    { id: 'DEV21', name: 'Laptop-99' },
    { id: 'DEV01', name: 'Laptop-01' },
    { id: 'DEV02', name: 'Laptop-02' },
    { id: 'DEV44', name: 'Workstation-44' },
    { id: 'DEV12', name: 'Dev-Macbook' },
  ];

  const servers = [
    { id: 'SRV12', name: 'Server-12' },
    { id: 'SRV01', name: 'Auth-Server-01' },
    { id: 'SRV02', name: 'App-Server-02' },
    { id: 'SRV03', name: 'DB-Server-Master' },
  ];

  const apps = ['VPN Gateway', 'Okta SSO', 'Active Directory', 'EDR Agent', 'Palo Alto Firewall', 'Cloudflare WAF'];
  const eventTypes = ['LOGIN', 'FAILED_LOGIN', 'SERVER_ACCESS', 'HTTP_REQUEST', 'DNS_QUERY', 'FILE_READ', 'TOKEN_REFRESH'];

  const generated: SecurityEvent[] = [];

  // Start time: 2026-10-07 00:00:00
  let baseTime = new Date('2026-10-07T00:00:00Z').getTime();

  for (let i = 1; i <= 4990; i++) {
    baseTime += Math.floor(Math.random() * 12000) + 1000;
    const user = users[i % users.length];
    const device = devices[i % devices.length];
    const server = servers[i % servers.length];
    const app = apps[i % apps.length];
    const type = eventTypes[i % eventTypes.length];
    
    // Normal routine events
    generated.push({
      event_id: `E${String(i + 1000).padStart(5, '0')}`,
      timestamp: new Date(baseTime).toISOString().replace('T', ' ').substring(0, 19),
      event_type: type,
      user_id: user.id,
      user_name: user.name,
      device_id: device.id,
      device_name: device.name,
      ip_address: `10.24.1.${(i % 250) + 1}`,
      application: app,
      server_id: server.id,
      server_name: server.name,
      destination_ip: type === 'DNS_QUERY' ? `8.8.8.8` : undefined,
      severity: i % 45 === 0 ? 'medium' : 'low',
      description: `Standard ${type.toLowerCase()} event recorded by ${app}`,
    });
  }

  // Inject primary attack events and lateral movement events to ensure suspicious items are detected
  const allEvents = [...primaryAttackEvents, ...lateralMovementEvents, ...generated];

  // Sort by timestamp ascending
  return allEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}
