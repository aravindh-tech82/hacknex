import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  ShieldAlert,
  Lock,
  Unlock,
  Radio,
  Cpu,
  Layers,
  Activity,
  ArrowRight,
} from 'lucide-react';
import type { SecurityEvent, ThreatIncident } from '../types/security';
import { analyzeSecurityEvents } from '../utils/threatEngine';
import { THREAT_THRESHOLDS } from '../config/threatScoringConfig';

interface LiveMonitorProps {
  events: SecurityEvent[];
  onInvestigateIncident: (incident: ThreatIncident) => void;
}

export const LiveMonitor: React.FC<LiveMonitorProps> = ({ events, onInvestigateIncident }) => {
  const [streamIndex, setStreamIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [speedMultiplier, setSpeedMultiplier] = useState<number>(1);
  const [isContained, setIsContained] = useState<boolean>(false);
  const [isRecovered, setIsRecovered] = useState<boolean>(false);
  const timerRef = useRef<any>(null);

  // If events list is huge (e.g. 5000), prioritize a rich representative slice of 30-50 events
  // that contains attack progression (e.g. starts normal -> failed logins -> server access -> mimikatz -> exfil)
  const replayEvents = useMemo(() => {
    if (!events || events.length === 0) return [];
    if (events.length <= 40) return events;

    // Pick top events with suspicious activities mixed with normal baseline
    const suspicious = events.filter((e) => e.severity === 'critical' || e.severity === 'high');
    const normal = events.filter((e) => e.severity === 'low' || e.severity === 'medium');

    // Create a 25-event dramatic sequence
    const combined = [...normal.slice(0, 5), ...suspicious, ...normal.slice(5, 10)];
    return combined.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()).slice(0, 25);
  }, [events]);

  const currentStreamEvents = useMemo(() => {
    return replayEvents.slice(0, Math.max(1, streamIndex));
  }, [replayEvents, streamIndex]);

  // Compute live threat intelligence on the fly from current stream
  const liveIncident = useMemo(() => {
    return analyzeSecurityEvents(currentStreamEvents);
  }, [currentStreamEvents]);

  // Auto-containment trigger when threat crosses critical threshold (>= 91)
  useEffect(() => {
    if (liveIncident.threatScore >= THREAT_THRESHOLDS.CONTAINMENT_TRIGGER && !isRecovered) {
      setIsContained(true);
    }
  }, [liveIncident.threatScore, isRecovered]);

  // Timer loop for replay
  useEffect(() => {
    if (isPlaying) {
      const intervalMs = Math.max(100, Math.round(1000 / speedMultiplier));
      timerRef.current = setInterval(() => {
        setStreamIndex((prev) => {
          if (prev >= replayEvents.length) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, intervalMs);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, speedMultiplier, replayEvents.length]);

  const handleStart = () => {
    if (streamIndex >= replayEvents.length) {
      setStreamIndex(1);
    } else if (streamIndex === 0) {
      setStreamIndex(1);
    }
    setIsPlaying(true);
  };

  const handlePause = () => {
    setIsPlaying(false);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setStreamIndex(1);
    setIsContained(false);
    setIsRecovered(false);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 flex items-center gap-1.5">
              <Radio className="w-3 h-3 text-red-400 animate-pulse" /> LIVE STREAM SIMULATOR
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Events: {streamIndex} / {replayEvents.length}
            </span>
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight mt-1 flex items-center gap-3">
            Real-Time Security Event Monitor
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Sequential event replay simulating real-time SOC monitoring with continuous ML scoring and auto-containment.
          </p>
        </div>

        {/* Live Playback Controls */}
        <div className="flex flex-wrap items-center gap-3 bg-slate-900/90 p-2.5 rounded-2xl border border-slate-800 shadow-xl">
          <button
            onClick={isPlaying ? handlePause : handleStart}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-md ${
              isPlaying
                ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-amber-950'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950'
            }`}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5" /> Pause
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Start Stream
              </>
            )}
          </button>

          <button
            onClick={handleReset}
            className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Reset
          </button>

          <div className="h-5 w-px bg-slate-800 mx-1"></div>

          {/* Speed Selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
            {[1, 2, 5, 10].map((s) => (
              <button
                key={s}
                onClick={() => setSpeedMultiplier(s)}
                className={`px-2.5 py-1 rounded-lg font-bold transition-all cursor-pointer ${
                  speedMultiplier === s
                    ? 'bg-indigo-600 text-white shadow-sm shadow-indigo-950'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Critical Threat Notification Alert */}
      {liveIncident.threatScore >= THREAT_THRESHOLDS.CONTAINMENT_TRIGGER && (
        <div className="p-6 rounded-2xl bg-red-950/40 border border-red-500/60 shadow-2xl shadow-red-950/60 flex flex-col sm:flex-row items-center justify-between gap-4 animate-red-glow">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0 mt-0.5">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-black uppercase px-2 py-0.5 rounded bg-red-500 text-slate-950">
                  CRITICAL THREAT DETECTED
                </span>
                <span className="text-xs font-mono text-red-300 font-bold">
                  Score: {liveIncident.threatScore}/100
                </span>
              </div>
              <h3 className="text-lg font-black text-white mt-1">
                {liveIncident.attackPattern} — {liveIncident.user.name} ({liveIncident.user.id})
              </h3>
              <p className="text-xs text-red-200/80 mt-0.5">
                Threat crossed containment threshold (≥91). Automated SOC containment protocol engaged.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            {isContained && !isRecovered ? (
              <button
                onClick={() => setIsRecovered(true)}
                className="px-4 py-2.5 rounded-xl bg-emerald-600/30 hover:bg-emerald-600/40 border border-emerald-500/50 text-emerald-300 font-bold text-xs flex items-center gap-2 transition-all cursor-pointer"
              >
                <Unlock className="w-3.5 h-3.5" /> Approve Recovery
              </button>
            ) : (
              <button
                onClick={() => {
                  setIsContained(true);
                  setIsRecovered(false);
                }}
                className="px-4 py-2.5 rounded-xl bg-red-600/30 hover:bg-red-600/40 border border-red-500/50 text-red-300 font-bold text-xs flex items-center gap-2 transition-all cursor-pointer"
              >
                <Lock className="w-3.5 h-3.5" /> Keep Locked
              </button>
            )}

            <button
              onClick={() => onInvestigateIncident(liveIncident)}
              className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-indigo-950 transition-all cursor-pointer"
            >
              <span>Investigate Incident</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Real-Time Live Intelligence Layer Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Card 1: Final Combined Score */}
        <div
          className={`p-5 rounded-2xl border transition-all ${
            liveIncident.threatScore >= 90
              ? 'glass-panel-critical shadow-lg shadow-red-950/40'
              : liveIncident.threatScore >= 70
              ? 'glass-panel border-amber-500/40 bg-amber-950/20'
              : 'glass-panel'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Combined Threat Score</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-4xl font-black font-mono tracking-tight transition-all ${
                liveIncident.threatScore >= 90
                  ? 'text-red-400'
                  : liveIncident.threatScore >= 70
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {liveIncident.threatScore}
            </span>
            <span className="text-xs font-mono text-slate-500">/ 100</span>
          </div>
          <div className="w-full bg-slate-800/80 rounded-full h-1.5 mt-3 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                liveIncident.threatScore >= 90
                  ? 'bg-red-500'
                  : liveIncident.threatScore >= 70
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${liveIncident.threatScore}%` }}
            ></div>
          </div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
            <span>Status:</span>
            <span
              className={`font-bold uppercase ${
                isContained && !isRecovered
                  ? 'text-red-400'
                  : liveIncident.threatScore >= 70
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {isContained && !isRecovered ? 'CONTAINED' : liveIncident.severity}
            </span>
          </div>
        </div>

        {/* Card 2: Isolation Forest Anomaly Detection */}
        <div className="glass-panel p-5 rounded-2xl">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Isolation Forest Anomaly</span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
              UNSUPERVISED
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-3xl font-black font-mono ${
                liveIncident.anomalyResult.isAnomalous
                  ? 'text-red-400'
                  : liveIncident.anomalyResult.anomalyScorePct >= 40
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {liveIncident.anomalyResult.anomalyScorePct}%
            </span>
            <span
              className={`text-xs font-bold px-2 py-0.5 rounded ${
                liveIncident.anomalyResult.label === 'ANOMALOUS'
                  ? 'bg-red-500/20 text-red-400'
                  : liveIncident.anomalyResult.label === 'SUSPICIOUS'
                  ? 'bg-amber-500/20 text-amber-400'
                  : 'bg-emerald-500/20 text-emerald-400'
              }`}
            >
              {liveIncident.anomalyResult.label}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 line-clamp-2 leading-relaxed">
            {liveIncident.anomalyResult.explanation}
          </p>
        </div>

        {/* Card 3: XGBoost Attack Probability */}
        <div className="glass-panel p-5 rounded-2xl">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>XGBoost Attack Probability</span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
              SUPERVISED GBDT
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-3xl font-black font-mono ${
                liveIncident.xgboostResult.attackProbabilityPct >= 80
                  ? 'text-red-400'
                  : liveIncident.xgboostResult.attackProbabilityPct >= 50
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {liveIncident.xgboostResult.attackProbabilityPct}%
            </span>
            <span className="text-xs font-bold text-slate-300">
              {liveIncident.xgboostResult.predictedClass}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 line-clamp-2 leading-relaxed">
            {liveIncident.xgboostResult.topFeatures.length > 0
              ? `Top feature: ${liveIncident.xgboostResult.topFeatures[0].displayName} (+${liveIncident.xgboostResult.topFeatures[0].contribution})`
              : 'Features within baseline normal tolerances.'}
          </p>
        </div>

        {/* Card 4: Rule Engine Baseline */}
        <div className="glass-panel p-5 rounded-2xl">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Rule Engine Baseline</span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              DETERMINISTIC
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-black font-mono text-indigo-300">
              {liveIncident.ruleScore}
            </span>
            <span className="text-xs font-mono text-slate-500">/ 100</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-2 space-y-0.5">
            <div>Formula: (Rule×0.4) + (IF×0.25) + (XGB×0.35)</div>
            <div className="font-mono text-slate-500">
              = {liveIncident.combinedScore.breakdown.ruleContribution} +{' '}
              {liveIncident.combinedScore.breakdown.anomalyContribution} +{' '}
              {liveIncident.combinedScore.breakdown.xgbContribution}
            </div>
          </div>
        </div>
      </div>

      {/* Main Split: Live Event Stream + Dynamic Entity Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Live Event Telemetry Stream (7 cols) */}
        <div className="lg:col-span-7 glass-panel p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white">Live Ingested Telemetry Feed</h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Showing {currentStreamEvents.length} events
            </span>
          </div>

          <div className="space-y-2 max-h-[460px] overflow-y-auto pr-2">
            {currentStreamEvents.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-sm">
                Click <span className="text-indigo-400 font-bold">Start Stream</span> to begin real-time event playback.
              </div>
            ) : (
              currentStreamEvents
                .slice()
                .reverse()
                .map((evt, idx) => {
                  const isLatest = idx === 0;
                  return (
                    <div
                      key={evt.event_id + idx}
                      className={`p-3.5 rounded-xl border text-xs transition-all ${
                        isLatest
                          ? 'bg-indigo-950/50 border-indigo-500/80 shadow-md shadow-indigo-950 ring-1 ring-indigo-500/50'
                          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                              evt.severity === 'critical'
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                : evt.severity === 'high'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            }`}
                          >
                            {evt.event_type}
                          </span>
                          <span className="font-mono text-slate-300 font-semibold">{evt.event_id}</span>
                          <span className="text-slate-500 font-mono text-[11px]">{evt.timestamp}</span>
                        </div>
                        {isLatest && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-500 text-white font-bold animate-pulse">
                            JUST ARRIVED
                          </span>
                        )}
                      </div>

                      <p className="text-slate-200 mt-1.5 font-medium">{evt.description}</p>

                      <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 mt-2 font-mono">
                        <span>User: <span className="text-slate-300">{evt.user_id}</span></span>
                        <span>Device: <span className="text-slate-300">{evt.device_id}</span></span>
                        <span>IP: <span className="text-slate-300">{evt.ip_address}</span></span>
                        {evt.server_id && <span>Server: <span className="text-indigo-300">{evt.server_id}</span></span>}
                        {evt.destination_ip && <span>Dest: <span className="text-red-400">{evt.destination_ip}</span></span>}
                      </div>
                    </div>
                  );
                })
            )}
          </div>
        </div>

        {/* Right: Live Evolving Attack Graph & Entity Topology (5 cols) */}
        <div className="lg:col-span-5 glass-panel p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white">Dynamic Attack Graph Evolution</h2>
            </div>
            <span className="text-xs font-mono text-indigo-400">
              {liveIncident.graphNodes.length} Active Nodes
            </span>
          </div>

          <div className="space-y-3">
            {liveIncident.graphNodes.map((node) => (
              <div
                key={node.id}
                className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between gap-3"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        node.type === 'USER'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                          : node.type === 'DEVICE'
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : node.type === 'SERVER'
                          ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                          : node.type === 'EXTERNAL_IP'
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {node.type}
                    </span>
                    <span className="text-xs font-bold text-white">{node.label}</span>
                  </div>
                  {node.subtext && <div className="text-[11px] text-slate-400 mt-0.5">{node.subtext}</div>}
                </div>

                <span
                  className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                    node.risk === 'critical'
                      ? 'bg-red-500/20 text-red-400'
                      : node.risk === 'high'
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-emerald-500/20 text-emerald-400'
                  }`}
                >
                  {node.risk}
                </span>
              </div>
            ))}
          </div>

          {/* Quick Deep Dive Button */}
          <button
            onClick={() => onInvestigateIncident(liveIncident)}
            className="w-full mt-4 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-bold text-xs shadow-lg shadow-indigo-950 flex items-center justify-center gap-2 cursor-pointer transition-transform hover:scale-102"
          >
            <span>Open AI Forensic Investigation</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
