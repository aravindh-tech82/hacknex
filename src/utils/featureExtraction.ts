import type { SecurityEvent, BehavioralFeatures } from '../types/security';

/**
 * Extracts structured numerical behavioral features from a stream of security events
 * associated with a user or entity.
 */
export function extractBehavioralFeatures(
  events: SecurityEvent[],
  userId: string,
  _baselineEvents?: SecurityEvent[]
): BehavioralFeatures {
  if (!events || events.length === 0) {
    return {
      userId,
      failed_login_count: 0,
      successful_login_count: 0,
      unique_ip_count: 0,
      unique_device_count: 0,
      new_device: 0,
      new_ip: 0,
      unusual_login_hour: 0,
      sensitive_server_access: 0,
      suspicious_process_count: 0,
      external_connection_count: 0,
      event_frequency: 0,
      number_of_servers_accessed: 0,
      number_of_applications_used: 0,
      number_of_destination_ips: 0,
      file_access_count: 0,
      authentication_failure_ratio: 0,
    };
  }

  // Known normal baseline devices & IPs for corporate fleet
  const knownCorporateDevices = new Set([
    'DEV001', 'DEV002', 'DEV003', 'DEV004', 'DEV007', 'DEV008', 'DEV009', 'DEV015',
    'Laptop-01', 'Laptop-02', 'Laptop-03', 'Workstation-44', 'Dev-Macbook',
  ]);

  const internalIpPrefixes = ['10.', '172.16.', '172.20.', '192.168.'];

  // Known sensitive servers requiring elevated security clearance
  const sensitiveServers = new Set([
    'SRV012', 'SRV014', 'SRV015', 'SRV011', 'SRV010', 'SRV013', 'SRV016',
    'SRV12', 'Finance-Database', 'Core-Vault-14', 'Backup-Storage-15', 'Customer-DB-11',
  ]);

  const uniqueIps = new Set<string>();
  const uniqueDevices = new Set<string>();
  const uniqueServers = new Set<string>();
  const uniqueApps = new Set<string>();
  const uniqueDestIps = new Set<string>();

  let failedLogins = 0;
  let successfulLogins = 0;
  let hasNewDevice = 0;
  let hasNewIp = 0;
  let unusualHourCount = 0;
  let sensitiveServerAccess = 0;
  let suspiciousProcesses = 0;
  let externalConnections = 0;
  let fileAccessCount = 0;

  events.forEach((evt) => {
    const desc = (evt.description || '').toLowerCase();
    const type = (evt.event_type || '').toUpperCase();
    const dev = evt.device_id || '';
    const ip = evt.ip_address || '';
    const srv = evt.server_id || evt.server_name || '';
    const app = evt.application || '';
    const dest = evt.destination_ip || '';

    if (ip) uniqueIps.add(ip);
    if (dev) uniqueDevices.add(dev);
    if (srv) uniqueServers.add(srv);
    if (app) uniqueApps.add(app);
    if (dest) uniqueDestIps.add(dest);

    // 1. Logins & Failures
    if (type === 'FAILED_LOGIN' || desc.includes('failed auth') || desc.includes('password mismatch')) {
      failedLogins++;
    } else if (type === 'LOGIN' || type === 'LOGIN_SUCCESS' || type === 'MFA_SUCCESS') {
      successfulLogins++;
    }

    // 2. Unrecognized device check
    if (
      dev.includes('99') ||
      dev.includes('88') ||
      dev.includes('010') ||
      dev.includes('011') ||
      dev.includes('014') ||
      desc.includes('unrecognized device') ||
      desc.includes('unmapped') ||
      desc.includes('new device') ||
      (!knownCorporateDevices.has(dev) && dev.startsWith('DEV'))
    ) {
      hasNewDevice = 1;
    }

    // 3. New / External IP check
    const isInternal = internalIpPrefixes.some((prefix) => ip.startsWith(prefix));
    if (!isInternal && ip !== '' && !ip.startsWith('127.')) {
      hasNewIp = 1;
    }

    // 4. Unusual login hour (Off-hours: 21:00 to 06:00)
    if (evt.timestamp) {
      const timePart = evt.timestamp.includes(' ') ? evt.timestamp.split(' ')[1] : evt.timestamp;
      const hour = parseInt(timePart.substring(0, 2), 10);
      if (!isNaN(hour) && (hour >= 21 || hour < 6)) {
        unusualHourCount++;
      }
    }

    // 5. Sensitive server access
    if (sensitiveServers.has(srv) || desc.includes('sensitive') || desc.includes('database') || desc.includes('vault')) {
      sensitiveServerAccess++;
    }

    // 6. Suspicious process executions
    if (
      type === 'PROCESS_EXECUTION' ||
      type === 'COMMAND_EXECUTION' ||
      desc.includes('powershell -e') ||
      desc.includes('mimikatz') ||
      desc.includes('wmi') ||
      desc.includes('vssadmin') ||
      desc.includes('tar') ||
      desc.includes('dump') ||
      desc.includes('xmrig') ||
      desc.includes('reverse tcp shell') ||
      desc.includes('sudoers') ||
      desc.includes('ntdsutil')
    ) {
      suspiciousProcesses++;
    }

    // 7. External outbound connections
    if (
      type === 'NETWORK_CONNECTION' ||
      type === 'DATA_EXFILTRATION' ||
      (dest && !internalIpPrefixes.some((prefix) => dest.startsWith(prefix)))
    ) {
      externalConnections++;
    }

    // 8. File accesses
    if (type === 'FILE_ACCESS' || desc.includes('file read') || desc.includes('ledger') || desc.includes('dumped')) {
      fileAccessCount++;
    }
  });

  const totalLogins = failedLogins + successfulLogins;
  const authFailureRatio = totalLogins > 0 ? parseFloat((failedLogins / totalLogins).toFixed(3)) : 0;

  // Approximate event frequency (events per recorded window, normalized)
  const eventFrequency = Math.min(10, parseFloat((events.length / 5).toFixed(2)));

  return {
    userId,
    failed_login_count: failedLogins,
    successful_login_count: successfulLogins,
    unique_ip_count: uniqueIps.size,
    unique_device_count: uniqueDevices.size,
    new_device: hasNewDevice,
    new_ip: hasNewIp,
    unusual_login_hour: unusualHourCount > 0 ? 1 : 0,
    sensitive_server_access: sensitiveServerAccess,
    suspicious_process_count: suspiciousProcesses,
    external_connection_count: externalConnections,
    event_frequency: eventFrequency,
    number_of_servers_accessed: uniqueServers.size,
    number_of_applications_used: uniqueApps.size,
    number_of_destination_ips: uniqueDestIps.size,
    file_access_count: fileAccessCount,
    authentication_failure_ratio: authFailureRatio,
  };
}
