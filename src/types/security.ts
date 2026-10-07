export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  user_id: string;
  user_name?: string;
  device_id: string;
  device_name?: string;
  ip_address: string;
  application: string;
  server_id?: string;
  server_name?: string;
  destination_ip?: string;
  severity: SeverityLevel;
  description: string;
}

export interface ThreatEvidence {
  id: string;
  title: string;
  severity: SeverityLevel;
  timestamp: string;
  eventId: string;
  description: string;
}

export interface ActionItem {
  id: number;
  text: string;
  target: string;
  completed: boolean;
  timestamp?: string;
}

export interface GraphNodeData {
  id: string;
  label: string;
  type: 'USER' | 'DEVICE' | 'IP' | 'APPLICATION' | 'SERVER' | 'EVENT' | 'EXTERNAL_IP';
  risk: SeverityLevel;
  subtext?: string;
  relatedEventCount?: number;
  details?: Record<string, string>;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
}

export interface ThreatIncident {
  id: string;
  title: string;
  severity: SeverityLevel;
  threatScore: number;
  user: {
    id: string;
    name: string;
  };
  device: {
    id: string;
    name: string;
  };
  sourceIp: string;
  targetServer: string;
  destinationIp?: string;
  attackPattern: string;
  status: 'active' | 'investigating' | 'contained' | 'resolved';
  detectedAt: string;
  summary: string;
  evidenceList: ThreatEvidence[];
  timelineEvents: SecurityEvent[];
  graphNodes: GraphNodeData[];
  graphEdges: GraphEdgeData[];
  recommendedActions: ActionItem[];
}
