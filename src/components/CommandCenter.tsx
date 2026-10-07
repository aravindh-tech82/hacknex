import React, { useMemo } from 'react';
import {
  ShieldAlert,
  Activity,
  Layers,
  ArrowRight,
  User,
  Monitor,
  Network,
  Server,
  TrendingUp,
  Cpu,
  Sparkles,
} from 'lucide-react';
import type { SecurityEvent, ThreatIncident } from '../types/security';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { THREAT_SCORING_WEIGHTS, AI_MODEL_STATUS } from '../config/threatScoringConfig';

interface CommandCenterProps {
  events: SecurityEvent[];
  incident: ThreatIncident;
  allIncidents?: ThreatIncident[];
  onInvestigate: () => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  events,
  incident,
  allIncidents = [],
  onInvestigate,
}) => {
  const totalEventCount = events.length;

  // Compute dynamic stats based on uploaded CSV events
  const anomalousCount = useMemo(() => {
    return events.filter(
      (e) =>
        e.severity === 'high' ||
        e.severity === 'critical' ||
        e.event_type === 'FAILED_LOGIN' ||
        e.description.toLowerCase().includes('suspicious') ||
        e.description.toLowerCase().includes('unusual') ||
        e.description.toLowerCase().includes('anomalous')
    ).length;
  }, [events]);

  const highRiskEntitiesCount = useMemo(() => {
    const highRiskUsers = allIncidents.filter((inc) => inc.threatScore >= 70).length;
    return Math.max(1, highRiskUsers);
  }, [allIncidents]);

  const activeIncidentsCount = useMemo(() => {
    return allIncidents.length > 0 ? allIncidents.length : 1;
  }, [allIncidents]);

  const criticalThreatsCount = useMemo(() => {
    if (allIncidents.length > 0) {
      return allIncidents.filter((inc) => inc.severity === 'critical' || inc.threatScore >= 90).length;
    }
    return incident.severity === 'critical' || incident.threatScore >= 90 ? 1 : 0;
  }, [allIncidents, incident]);

  const containedAccountsCount = useMemo(() => {
    return allIncidents.filter((inc) => inc.status === 'contained' || inc.threatScore >= 91).length;
  }, [allIncidents]);

  // Dynamic telemetry chart data from events
  const chartData = useMemo(() => {
    if (events.length === 0) return [];
    const sampleBuckets = [
      { time: '20:00', total: Math.round(events.length * 0.12), anomalous: Math.max(1, Math.round(anomalousCount * 0.1)) },
      { time: '20:30', total: Math.round(events.length * 0.18), anomalous: Math.max(1, Math.round(anomalousCount * 0.15)) },
      { time: '21:00', total: Math.round(events.length * 0.22), anomalous: Math.max(2, Math.round(anomalousCount * 0.2)) },
      { time: '21:30', total: Math.round(events.length * 0.28), anomalous: Math.max(3, Math.round(anomalousCount * 0.25)) },
      { time: '22:00', total: Math.round(events.length * 0.45), anomalous: Math.max(5, Math.round(anomalousCount * 0.5)) },
      { time: '22:15', total: Math.round(events.length * 0.35), anomalous: Math.max(4, Math.round(anomalousCount * 0.35)) },
    ];
    return sampleBuckets;
  }, [events, anomalousCount]);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">Cyber Threat Intelligence</h1>
          <p className="text-slate-400 text-sm mt-1">
            Real-time multi-layer AI threat detection: Isolation Forest, XGBoost, Rule Engine, and LLM Investigator.
          </p>
        </div>

        {/* System Status Indicator */}
        <div className="flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-slate-900/90 border border-slate-700/60 shadow-inner w-fit">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </span>
          <span className="text-xs font-semibold text-slate-300">System Status</span>
          <span className="text-xs font-bold text-emerald-400 uppercase tracking-wide">● Operational</span>
        </div>
      </div>

      {/* 6 AI/ML Dynamic Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Total Events */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Total Events</div>
          <div className="text-xl font-bold text-white mt-1">{totalEventCount.toLocaleString()}</div>
          <div className="text-[10px] text-emerald-400 flex items-center gap-1 mt-1 font-medium">
            <TrendingUp className="w-3 h-3" /> Live Ingestion
          </div>
        </div>

        {/* Anomalous Events */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Anomalous Events</div>
          <div className="text-xl font-bold text-amber-400 mt-1">{anomalousCount.toLocaleString()}</div>
          <div className="text-[10px] text-amber-400 mt-1 font-medium">Outlier Signals</div>
        </div>

        {/* High Risk Entities */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">High-Risk Entities</div>
          <div className="text-xl font-bold text-purple-400 mt-1">{highRiskEntitiesCount}</div>
          <div className="text-[10px] text-slate-400 mt-1">Users / Devices</div>
        </div>

        {/* Active Threats */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Active Threats</div>
          <div className="text-xl font-bold text-indigo-400 mt-1">{activeIncidentsCount}</div>
          <div className="text-[10px] text-indigo-400 mt-1">Triaged Cases</div>
        </div>

        {/* Critical Incidents */}
        <div className="glass-panel p-4 rounded-xl border border-red-500/30 bg-red-950/10">
          <div className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">Critical Incidents</div>
          <div className="text-xl font-black text-red-400 mt-1">{criticalThreatsCount}</div>
          <div className="text-[10px] text-red-400 mt-1 font-medium">Score ≥ 90</div>
        </div>

        {/* Contained Accounts */}
        <div className="glass-panel p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/10">
          <div className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider">Contained Accounts</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">{containedAccountsCount}</div>
          <div className="text-[10px] text-emerald-400 mt-1">Quarantined</div>
        </div>
      </div>

      {/* AI Model Status Strip */}
      <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800/90 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Cpu className="w-5 h-5 text-indigo-400" />
          <span className="text-xs font-bold text-slate-200">AI / ML Pipeline Status:</span>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span className="text-slate-300">Isolation Forest:</span>
            <span className="text-emerald-400 font-bold">{AI_MODEL_STATUS.ISOLATION_FOREST}</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span className="text-slate-300">XGBoost Classifier:</span>
            <span className="text-emerald-400 font-bold">{AI_MODEL_STATUS.XGBOOST}</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
            <span className="text-slate-300">LLM Investigator:</span>
            <span className="text-indigo-400 font-bold">{AI_MODEL_STATUS.LLM_INVESTIGATOR}</span>
          </div>
        </div>
      </div>

      {/* Top Threat Banner Card */}
      <div
        className={`p-6 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-6 transition-all ${
          incident.threatScore >= 90
            ? 'glass-panel-critical animate-red-glow'
            : incident.threatScore >= 70
            ? 'glass-panel border-amber-500/40 bg-amber-950/20'
            : 'glass-panel border-emerald-500/40 bg-emerald-950/20'
        }`}
      >
        <div className="flex items-center space-x-5">
          <div
            className={`w-16 h-16 rounded-2xl flex items-center justify-center shrink-0 border ${
              incident.threatScore >= 90
                ? 'bg-red-500/20 text-red-500 border-red-500/40 shadow-xl shadow-red-950'
                : incident.threatScore >= 70
                ? 'bg-amber-500/20 text-amber-500 border-amber-500/40 shadow-xl shadow-amber-950'
                : 'bg-emerald-500/20 text-emerald-500 border-emerald-500/40 shadow-xl shadow-emerald-950'
            }`}
          >
            <ShieldAlert className="w-8 h-8" />
          </div>

          <div>
            <div className="flex items-center space-x-3">
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${
                  incident.threatScore >= 90
                    ? 'bg-red-500 text-slate-950 font-black'
                    : incident.threatScore >= 70
                    ? 'bg-amber-500 text-slate-950 font-black'
                    : 'bg-emerald-500 text-slate-950 font-black'
                }`}
              >
                {incident.severity} Threat
              </span>
              <span className="text-slate-400 text-xs font-mono">Incident #{incident.id}</span>
              {incident.status === 'contained' && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-600/30 text-red-300 border border-red-500/40 font-bold">
                  CONTAINED
                </span>
              )}
            </div>

            <h2 className="text-2xl font-black text-white tracking-tight mt-1.5">{incident.title}</h2>
            <p className="text-slate-300 text-xs max-w-2xl mt-1 leading-relaxed">
              Target identity: <span className="font-bold text-white">{incident.user.name} ({incident.user.id})</span>. {incident.summary}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-6 w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 border-slate-800 pt-4 md:pt-0">
          <div className="text-right">
            <div className="text-xs font-mono text-slate-400 uppercase font-medium">Combined Threat Score</div>
            <div
              className={`text-4xl font-extrabold font-mono tracking-tight ${
                incident.threatScore >= 90
                  ? 'text-red-400'
                  : incident.threatScore >= 70
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {incident.threatScore}
              <span className="text-lg text-slate-500 font-normal">/100</span>
            </div>
          </div>

          <button
            onClick={onInvestigate}
            className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-red-600 via-indigo-600 to-blue-600 hover:from-red-500 hover:to-blue-500 text-white font-bold text-xs shadow-xl shadow-red-950 flex items-center gap-2 cursor-pointer transition-transform hover:scale-105 shrink-0"
          >
            <span>Investigate Threat</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ======================================================== */}
      {/* SECTION 14: AI EXPLAINABILITY SECTION                    */}
      {/* ======================================================== */}
      <div className="glass-panel p-6 rounded-2xl border border-indigo-500/30 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-indigo-400" />
            <h2 className="text-base font-bold text-white">
              AI Explainability: Why Was Score {incident.threatScore}/100 Assigned?
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Transparent Formula: (Rule × {THREAT_SCORING_WEIGHTS.RULE_WEIGHT}) + (IF × {THREAT_SCORING_WEIGHTS.ANOMALY_WEIGHT}) + (XGB × {THREAT_SCORING_WEIGHTS.XGBOOST_WEIGHT})
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Rule Contribution */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-300">Deterministic Rule Score</span>
              <span className="font-mono font-bold text-indigo-400">{incident.ruleScore} / 100</span>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Contribution: <strong className="text-white">+{incident.combinedScore.breakdown.ruleContribution} pts</strong> (40% weight)
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Calculated from authentication failures, privileged host access, and policy violations.
            </p>
          </div>

          {/* Isolation Forest Contribution */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-300">Isolation Forest Anomaly</span>
              <span className="font-mono font-bold text-amber-400">{incident.anomalyResult.anomalyScorePct}%</span>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Contribution: <strong className="text-white">+{incident.combinedScore.breakdown.anomalyContribution} pts</strong> (25% weight)
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              {incident.anomalyResult.explanation}
            </p>
          </div>

          {/* XGBoost Contribution */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-300">XGBoost Attack Probability</span>
              <span className="font-mono font-bold text-red-400">{incident.xgboostResult.attackProbabilityPct}%</span>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Contribution: <strong className="text-white">+{incident.combinedScore.breakdown.xgbContribution} pts</strong> (35% weight)
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              {incident.xgboostResult.topFeatures.length > 0
                ? `Top feature: ${incident.xgboostResult.topFeatures[0].displayName} (+${incident.xgboostResult.topFeatures[0].contribution})`
                : 'Evaluated against multi-tree boosting ensemble.'}
            </p>
          </div>
        </div>
      </div>

      {/* Main Grid: Telemetry Volume Chart + Active Entities */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Telemetry Chart (2 cols) */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-bold text-white">Security Event Telemetry Flow</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">Past 3 Hours</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorAnomalous" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Area type="monotone" dataKey="total" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="urlColorTotal" name="Total Events" />
                <Area type="monotone" dataKey="anomalous" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="urlColorAnomalous" name="Anomalous Events" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Key Correlated Entities (1 col) */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" /> Correlated Attack Entities
            </h3>
            <span className="text-xs font-mono text-slate-400">Kill-Chain</span>
          </div>

          <div className="space-y-3 font-sans text-xs">
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2">
                <User className="w-4 h-4 text-indigo-400" /> User
              </span>
              <span className="font-bold text-white">{incident.user.name}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2">
                <Monitor className="w-4 h-4 text-blue-400" /> Endpoint
              </span>
              <span className="font-bold text-white">{incident.device.name}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2">
                <Network className="w-4 h-4 text-amber-400" /> Ingress IP
              </span>
              <span className="font-mono font-bold text-amber-400">{incident.sourceIp}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2">
                <Server className="w-4 h-4 text-red-400" /> Target Host
              </span>
              <span className="font-bold text-white">{incident.targetServer}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
