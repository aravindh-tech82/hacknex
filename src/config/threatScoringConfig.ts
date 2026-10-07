/**
 * Centralized Threat Scoring Configuration
 * 
 * Defines transparent weights for combining deterministic rule engine signals,
 * Isolation Forest anomaly detection, and XGBoost threat classification.
 */

export interface ThreatScoringWeights {
  RULE_WEIGHT: number;
  ANOMALY_WEIGHT: number;
  XGBOOST_WEIGHT: number;
}

export const THREAT_SCORING_WEIGHTS: ThreatScoringWeights = {
  RULE_WEIGHT: 0.40,      // Deterministic rules baseline (40%)
  ANOMALY_WEIGHT: 0.25,   // Isolation Forest unsupervised anomaly signal (25%)
  XGBOOST_WEIGHT: 0.35,   // XGBoost supervised threat classification probability (35%)
};

export const THREAT_THRESHOLDS = {
  CRITICAL: 90,
  CONTAINMENT_TRIGGER: 91, // Auto-containment triggered when final score >= 91
  HIGH: 70,
  MEDIUM: 40,
  LOW: 0,
};

export const AI_MODEL_STATUS = {
  ISOLATION_FOREST: 'ACTIVE' as const,
  XGBOOST: 'ACTIVE' as const,
  LLM_INVESTIGATOR: 'CONFIGURED' as const,
};
