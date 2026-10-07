import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const attackScenario1 = [
  { event_id: 'E001', timestamp: '2026-10-07 22:01:10', event_type: 'LOGIN', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'medium', description: 'Unusual login attempt from unmapped external IP 185.44.21.8' },
  { event_id: 'E002', timestamp: '2026-10-07 22:02:05', event_type: 'FAILED_LOGIN', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'Failed authentication attempt (Password mismatch)' },
  { event_id: 'E003', timestamp: '2026-10-07 22:02:15', event_type: 'FAILED_LOGIN', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'Failed authentication attempt (Password mismatch)' },
  { event_id: 'E004', timestamp: '2026-10-07 22:02:24', event_type: 'FAILED_LOGIN', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'Failed authentication attempt (Password mismatch)' },
  { event_id: 'E005', timestamp: '2026-10-07 22:02:40', event_type: 'FAILED_LOGIN', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'Failed authentication attempt (Password mismatch)' },
  { event_id: 'E006', timestamp: '2026-10-07 22:03:02', event_type: 'FAILED_LOGIN', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'Failed authentication attempt (Password mismatch)' },
  { event_id: 'E007', timestamp: '2026-10-07 22:03:30', event_type: 'LOGIN_SUCCESS', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'medium', description: 'Successful authentication following multiple failed attempts' },
  { event_id: 'E008', timestamp: '2026-10-07 22:04:10', event_type: 'VPN_CONNECTION', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'VPN session established from unrecognized device DEV099' },
  { event_id: 'E009', timestamp: '2026-10-07 22:07:00', event_type: 'SERVER_ACCESS', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'SSH Bastion', server_id: 'SRV012', destination_ip: '', severity: 'high', description: 'Privileged SSH session established to Finance-Database SRV012' },
  { event_id: 'E010', timestamp: '2026-10-07 22:09:15', event_type: 'PROCESS_EXECUTION', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'CrowdStrike EDR', server_id: 'SRV012', destination_ip: '', severity: 'critical', description: 'Suspicious PowerShell command: powershell -e aW52b2tlLW1pbWlrYXR6' },
  { event_id: 'E011', timestamp: '2026-10-07 22:10:30', event_type: 'PRIVILEGE_ESCALATION', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'Active Directory', server_id: 'SRV012', destination_ip: '', severity: 'critical', description: 'Unauthorized token duplication to NT AUTHORITY\\SYSTEM' },
  { event_id: 'E012', timestamp: '2026-10-07 22:12:00', event_type: 'FILE_ACCESS', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'Finance DB', server_id: 'SRV012', destination_ip: '', severity: 'high', description: 'Bulk file access: 420 financial records extracted from SRV012' },
  { event_id: 'E013', timestamp: '2026-10-07 22:14:00', event_type: 'NETWORK_CONNECTION', user_id: 'USR101', device_id: 'DEV099', ip_address: '185.44.21.8', application: 'Palo Alto Firewall', server_id: 'SRV012', destination_ip: '185.44.21.8', severity: 'critical', description: 'High volume outbound encrypted traffic stream to 185.44.21.8' }
];

const attackScenario2 = [
  { event_id: 'E101', timestamp: '2026-10-07 21:05:10', event_type: 'LOGIN', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'Okta SSO', server_id: '', destination_ip: '', severity: 'low', description: 'User login from primary workstation DEV020' },
  { event_id: 'E102', timestamp: '2026-10-07 21:10:20', event_type: 'SERVER_ACCESS', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'Windows RDP', server_id: 'SRV003', destination_ip: '', severity: 'medium', description: 'RDP connection established to Auth-Server-03 SRV003' },
  { event_id: 'E103', timestamp: '2026-10-07 21:15:30', event_type: 'PROCESS_EXECUTION', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'CrowdStrike EDR', server_id: 'SRV003', destination_ip: '', severity: 'high', description: 'WMI query invoked to enumerate domain controller admin credentials' },
  { event_id: 'E104', timestamp: '2026-10-07 21:20:40', event_type: 'PRIVILEGE_ESCALATION', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'Active Directory', server_id: 'SRV003', destination_ip: '', severity: 'critical', description: 'Domain Admin privileges granted via Kerberoasting ticket reuse' },
  { event_id: 'E105', timestamp: '2026-10-07 21:28:00', event_type: 'NETWORK_CONNECTION', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'Palo Alto Firewall', server_id: 'SRV003', destination_ip: '10.0.8.50', severity: 'high', description: 'Lateral SMB connection initiated from SRV003 to SRV008' },
  { event_id: 'E106', timestamp: '2026-10-07 21:35:10', event_type: 'SERVER_ACCESS', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'SSH Bastion', server_id: 'SRV014', destination_ip: '', severity: 'critical', description: 'Pivoted lateral connection established to Core-Vault-14 SRV014' },
  { event_id: 'E107', timestamp: '2026-10-07 21:40:20', event_type: 'FILE_ACCESS', user_id: 'USR205', device_id: 'DEV020', ip_address: '172.16.4.25', application: 'Admin Console', server_id: 'SRV014', destination_ip: '', severity: 'critical', description: 'Sensitive credential vault dumping executed on SRV014' }
];

const attackScenario3 = [
  { event_id: 'E201', timestamp: '2026-10-07 23:15:00', event_type: 'FAILED_LOGIN', user_id: 'USR310', device_id: 'DEV088', ip_address: '91.22.18.4', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'high', description: 'Multiple failed logins from new external IP 91.22.18.4' },
  { event_id: 'E202', timestamp: '2026-10-07 23:18:20', event_type: 'LOGIN_SUCCESS', user_id: 'USR310', device_id: 'DEV088', ip_address: '91.22.18.4', application: 'VPN Gateway', server_id: '', destination_ip: '', severity: 'medium', description: 'Late night login from unrecognized device DEV088' },
  { event_id: 'E203', timestamp: '2026-10-07 23:22:10', event_type: 'SERVER_ACCESS', user_id: 'USR310', device_id: 'DEV088', ip_address: '91.22.18.4', application: 'SSH Bastion', server_id: 'SRV004', destination_ip: '', severity: 'high', description: 'Access granted to File-Repository-04 SRV004' },
  { event_id: 'E204', timestamp: '2026-10-07 23:26:40', event_type: 'FILE_ACCESS', user_id: 'USR310', device_id: 'DEV088', ip_address: '91.22.18.4', application: 'DLP Sentinel', server_id: 'SRV004', destination_ip: '', severity: 'high', description: 'Mass file read: 1400 confidential engineering archives accessed' },
  { event_id: 'E205', timestamp: '2026-10-07 23:31:10', event_type: 'COMMAND_EXECUTION', user_id: 'USR310', device_id: 'DEV088', ip_address: '91.22.18.4', application: 'CrowdStrike EDR', server_id: 'SRV004', destination_ip: '', severity: 'critical', description: 'Staging command executed: tar -czf exfil.tar.gz /var/confidential/' },
  { event_id: 'E206', timestamp: '2026-10-07 23:35:00', event_type: 'NETWORK_CONNECTION', user_id: 'USR310', device_id: 'DEV088', ip_address: '91.22.18.4', application: 'Palo Alto Firewall', server_id: 'SRV004', destination_ip: '91.22.18.4', severity: 'critical', description: 'Outbound TCP connection sending exfil payload stream to 91.22.18.4' }
];

const falsePositiveScenario = [
  { event_id: 'E301', timestamp: '2026-10-07 14:00:10', event_type: 'MFA_SUCCESS', user_id: 'USR102', device_id: 'DEV003', ip_address: '10.10.20.18', application: 'Okta SSO', server_id: '', destination_ip: '', severity: 'low', description: 'Hardware token MFA authentication verified' },
  { event_id: 'E302', timestamp: '2026-10-07 14:02:15', event_type: 'SERVER_ACCESS', user_id: 'USR102', device_id: 'DEV003', ip_address: '10.10.20.18', application: 'SSH Bastion', server_id: 'SRV012', destination_ip: '', severity: 'medium', description: 'Scheduled audit access to Finance-Database SRV012 under change ticket CHG-8821' },
  { event_id: 'E303', timestamp: '2026-10-07 14:05:00', event_type: 'FILE_ACCESS', user_id: 'USR102', device_id: 'DEV003', ip_address: '10.10.20.18', application: 'Finance DB', server_id: 'SRV012', destination_ip: '', severity: 'low', description: 'Read operation on quarterly audit ledger table' },
  { event_id: 'E304', timestamp: '2026-10-07 14:15:00', event_type: 'LOGOUT', user_id: 'USR102', device_id: 'DEV003', ip_address: '10.10.20.18', application: 'Okta SSO', server_id: '', destination_ip: '', severity: 'low', description: 'Normal audit session closed successfully' }
];

// Background normal routine events
const normalUsers = [
  { id: 'USR001', dev: 'DEV002', ip: '10.10.20.12' },
  { id: 'USR103', dev: 'DEV004', ip: '10.10.20.22' },
  { id: 'USR104', dev: 'DEV005', ip: '10.10.20.25' },
  { id: 'USR105', dev: 'DEV006', ip: '10.10.20.30' },
  { id: 'USR106', dev: 'DEV007', ip: '10.10.20.35' },
  { id: 'USR107', dev: 'DEV008', ip: '10.10.20.40' },
  { id: 'USR108', dev: 'DEV009', ip: '10.10.20.45' },
  { id: 'USR109', dev: 'DEV010', ip: '10.10.20.50' },
  { id: 'USR110', dev: 'DEV011', ip: '10.10.20.55' }
];

const normalApps = ['Okta SSO', 'Microsoft 365', 'Email Exchange', 'Jira Software', 'GitHub Enterprise'];
const normalTypes = ['LOGIN', 'MFA_SUCCESS', 'API_ACCESS', 'FILE_ACCESS', 'DNS_REQUEST', 'LOGOUT'];

const backgroundEvents = [];
let baseTime = new Date('2026-10-07T08:00:00Z').getTime();

for (let i = 1; i <= 4950; i++) {
  baseTime += Math.floor(Math.random() * 8000) + 1000;
  const userObj = normalUsers[i % normalUsers.length];
  const app = normalApps[i % normalApps.length];
  const type = normalTypes[i % normalTypes.length];
  const timeStr = new Date(baseTime).toISOString().replace('T', ' ').substring(0, 19);

  backgroundEvents.push({
    event_id: `E${String(i + 1000).padStart(5, '0')}`,
    timestamp: timeStr,
    event_type: type,
    user_id: userObj.id,
    device_id: userObj.dev,
    ip_address: userObj.ip,
    application: app,
    server_id: i % 10 === 0 ? 'SRV002' : '',
    destination_ip: type === 'DNS_REQUEST' ? '8.8.8.8' : '',
    severity: 'low',
    description: `Standard ${type.toLowerCase()} operation via ${app}`
  });
}

const allEvents = [
  ...attackScenario1,
  ...attackScenario2,
  ...attackScenario3,
  ...falsePositiveScenario,
  ...backgroundEvents
].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

const header = 'event_id,timestamp,event_type,user_id,device_id,ip_address,application,server_id,destination_ip,severity,description\n';
const csvLines = allEvents.map(e => `${e.event_id},${e.timestamp},${e.event_type},${e.user_id},${e.device_id},${e.ip_address},${e.application},${e.server_id},${e.destination_ip},${e.severity},"${e.description}"`).join('\n');

const fullCsv = header + csvLines;

fs.mkdirSync(path.join(__dirname, 'demo-data'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'public', 'demo-data'), { recursive: true });

fs.writeFileSync(path.join(__dirname, 'demo-data', 'security_events.csv'), fullCsv);
fs.writeFileSync(path.join(__dirname, 'public', 'demo-data', 'security_events.csv'), fullCsv);

// Copy all other datasets
const files = ['users.csv', 'devices.csv', 'servers.csv', 'ip_addresses.csv', 'applications.csv', 'scenarios.json'];
files.forEach(f => {
  const src = path.join(__dirname, 'demo-data', f);
  const dst = path.join(__dirname, 'public', 'demo-data', f);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dst);
  }
});

console.log('Successfully generated security_events.csv with', allEvents.length, 'events and copied all demo files!');
