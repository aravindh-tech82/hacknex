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

// 1. Behavioral Features extracted from Security Events
export interface BehavioralFeatures {
  userId: string;
  failed_login_count: number;
  successful_login_count: number;
  unique_ip_count: number;
  unique_device_count: number;
  new_device: number; // 0 or 1
  new_ip: number; // 0 or 1
  unusual_login_hour: number; // 0 or 1 (e.g. 22:00 - 06:00)
  sensitive_server_access: number;
  suspicious_process_count: number;
  external_connection_count: number;
  event_frequency: number; // events per minute or normalized rate
  number_of_servers_accessed: number;
  number_of_applications_used: number;
  number_of_destination_ips: number;
  file_access_count: number;
  authentication_failure_ratio: number;
}

// 2. Isolation Forest Anomaly Detection Result
export interface IsolationForestResult {
  anomalyScore: number; // 0.0 to 1.0 (raw isolation score)
  anomalyScorePct: number; // 0 to 100 normalized
  isAnomalous: boolean;
  label: 'ANOMALOUS' | 'SUSPICIOUS' | 'NORMAL';
  confidence: number;
  averagePathLength: number;
  expectedPathLength: number;
  explanation: string;
}

// 3. XGBoost Threat Classification Result
export interface FeatureContribution {
  feature: string;
  displayName: string;
  value: number;
  contribution: number;
  impact: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface XGBoostResult {
  attackProbability: number; // 0.0 to 1.0
  attackProbabilityPct: number; // 0 to 100
  predictedClass: 'CRITICAL_THREAT' | 'HIGH_RISK' | 'SUSPICIOUS' | 'LOW_RISK' | 'NORMAL';
  confidence: number;
  topFeatures: FeatureContribution[];
  explanation: string;
}

// 4. Combined Threat Score Result
export interface CombinedThreatScore {
  finalScore: number; // 0 to 100
  ruleScore: number;
  anomalyScorePct: number;
  xgbProbPct: number;
  ruleWeight: number;
  anomalyWeight: number;
  xgbWeight: number;
  breakdown: {
    ruleContribution: number;
    anomalyContribution: number;
    xgbContribution: number;
  };
  severity: SeverityLevel;
  requiresContainment: boolean;
}

// 5. LLM AI Investigator Assessment Result
export interface LLMInvestigationResult {
  threatTitle: string;
  whySuspicious: string[];
  aiAssessment: string;
  recommendedActions: string[];
  falsePositiveAnalysis?: string;
  source: 'LLM_API' | 'LOCAL_FORENSIC_ENGINE';
  status: 'READY' | 'ANALYZED' | 'UNAVAILABLE';
}

// Complete Threat Incident representation
export interface ThreatIncident {
  id: string;
  title: string;
  severity: SeverityLevel;
  threatScore: number; // Final combined threat score
  ruleScore: number;
  anomalyResult: IsolationForestResult;
  xgboostResult: XGBoostResult;
  combinedScore: CombinedThreatScore;
  features: BehavioralFeatures;
  llmAssessment?: LLMInvestigationResult;
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
  falsePositiveReasoning?: string;
}
