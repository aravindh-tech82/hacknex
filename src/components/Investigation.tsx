import React, { useState, useMemo, useRef } from 'react';
import {
  ShieldAlert,
  User,
  Monitor,
  Network,
  Server,
  AlertTriangle,
  Clock,
  Send,
  CheckCircle2,
  Shield,
  ShieldCheck,
  Layers,
  ArrowUpRight,
  ChevronDown,
  Lock,
  Unlock,
  Sparkles,
  Bot,
  Info,
  HelpCircle,
  ExternalLink,
} from 'lucide-react';
import {
  ReactFlow,
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  MarkerType,
} from '@xyflow/react';
import type { Node, Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import type { ThreatIncident, SecurityEvent, GraphNodeData } from '../types/security';
import { llmInvestigatorService, SUGGESTED_INVESTIGATION_QUESTIONS } from '../services/llmService';
import { AttackGraphNode } from './AttackGraphNode';
import { THREAT_THRESHOLDS } from '../config/threatScoringConfig';

const nodeTypes = {
  customNode: AttackGraphNode,
};

interface InvestigationProps {
  allIncidents: ThreatIncident[];
  onOpenFullGraph: () => void;
}

export const Investigation: React.FC<InvestigationProps> = ({ allIncidents, onOpenFullGraph }) => {
  // References for navigation jumping
  const evidenceSectionRef = useRef<HTMLDivElement>(null);
  const timelineSectionRef = useRef<HTMLDivElement>(null);
  const graphSectionRef = useRef<HTMLDivElement>(null);

  // Currently selected incident ID
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    allIncidents[0]?.id || 'INC-USR101'
  );

  const incident = useMemo(() => {
    return allIncidents.find((inc) => inc.id === selectedIncidentId) || allIncidents[0];
  }, [allIncidents, selectedIncidentId]);

  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(incident.timelineEvents[0] || null);
  const [selectedNodeData, setSelectedNodeData] = useState<GraphNodeData | null>(incident.graphNodes[0] || null);
  const [actionStates, setActionStates] = useState<Record<number, boolean>>({});
  const [isRecovered, setIsRecovered] = useState(false);

  // AI Assistant State
  const [chatQuestion, setChatQuestion] = useState('');
  const [isThinking, setIsThinking] = useState(false);
  const [chatHistory, setChatHistory] = useState<
    Array<{ sender: 'user' | 'ai'; text: string; category?: string }>
  >([
    {
      sender: 'ai',
      text: incident.llmAssessment?.aiAssessment || incident.summary,
      category: 'Initial Assessment',
    },
  ]);

  // Convert graph data to React Flow format
  const initialNodes: Node[] = useMemo(() => {
    return incident.graphNodes.map((n, idx) => ({
      id: n.id,
      type: 'customNode',
      position: { x: 50 + idx * 220, y: idx % 2 === 0 ? 120 : 200 },
      data: n as any,
    }));
  }, [incident]);

  const initialEdges: Edge[] = useMemo(() => {
    return incident.graphEdges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: true,
      style: { stroke: '#6366f1', strokeWidth: 2 },
      labelStyle: { fill: '#94a3b8', fontSize: 10, fontWeight: 600 },
      labelBgStyle: { fill: '#0f172a', fillOpacity: 0.8 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#6366f1',
      },
    }));
  }, [incident]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  const handleAskQuestion = async (qText: string) => {
    if (!qText.trim()) return;

    setChatHistory((prev) => [...prev, { sender: 'user', text: qText }]);
    setChatQuestion('');
    setIsThinking(true);

    try {
      const answer = await llmInvestigatorService.answerQuestion(qText, incident);
      setChatHistory((prev) => [...prev, { sender: 'ai', text: answer }]);
    } catch {
      setChatHistory((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: 'Unable to analyze question against structured evidence. Insufficient evidence.',
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  };

  const toggleAction = (id: number) => {
    setActionStates((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const scrollToEvidence = () => {
    evidenceSectionRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const scrollToTimeline = () => {
    timelineSectionRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const scrollToGraph = () => {
    graphSectionRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const isCriticalThreat = incident.threatScore >= THREAT_THRESHOLDS.CONTAINMENT_TRIGGER;
  const isFalsePositiveCandidate = incident.threatScore <= 40 || incident.user.id === 'USR102';

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Top Incident Selector & Breadcrumbs Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
            <span>Threat Intelligence</span>
            <span>/</span>
            <span>Investigations</span>
            <span>/</span>
            <span className="text-indigo-400 font-bold">{incident.id}</span>
          </div>

          <div className="flex items-center gap-3 mt-1.5">
            <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
              <span>{incident.title}</span>
            </h1>

            <span
              className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase border ${
                incident.threatScore >= 90
                  ? 'bg-red-500/20 text-red-400 border-red-500/30'
                  : incident.threatScore >= 70
                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                  : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
              }`}
            >
              {incident.severity} Risk
            </span>
          </div>
        </div>

        {/* Multi-Incident Switcher Dropdown */}
        <div className="flex items-center gap-3">
          <label className="text-xs text-slate-400 font-medium">Switch Target Incident:</label>
          <div className="relative">
            <select
              value={selectedIncidentId}
              onChange={(e) => {
                setSelectedIncidentId(e.target.value);
                setIsRecovered(false);
              }}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-xl px-4 py-2.5 pr-8 font-medium focus:outline-none focus:border-indigo-500 cursor-pointer appearance-none shadow-md"
            >
              {allIncidents.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  {inc.id}: {inc.user.name} — {inc.title} ({inc.threatScore}/100)
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Quick Navigation Anchor Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-2xl bg-slate-900/60 border border-slate-800 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-medium">Quick Jump:</span>
          <button
            onClick={scrollToEvidence}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition-colors cursor-pointer"
          >
            Show Evidence
          </button>
          <button
            onClick={scrollToTimeline}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition-colors cursor-pointer"
          >
            Show Timeline
          </button>
          <button
            onClick={scrollToGraph}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition-colors cursor-pointer"
          >
            Show Attack Graph
          </button>
        </div>

        <button
          onClick={onOpenFullGraph}
          className="px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 font-semibold border border-indigo-500/40 flex items-center gap-1.5 transition-colors cursor-pointer"
        >
          <span>Open Fullscreen Topology</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Controlled Containment Banner (Triggered when Score >= 91) */}
      {isCriticalThreat && !isRecovered && (
        <div className="glass-panel-critical p-6 rounded-2xl space-y-4 animate-red-glow">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center space-x-3.5">
              <div className="w-12 h-12 rounded-xl bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0">
                <Lock className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-red-400 uppercase tracking-wider">
                    CRITICAL THREAT — AUTO-CONTAINMENT TRIGGERED
                  </span>
                  <span className="text-xs font-mono font-bold text-white bg-red-600/40 px-2 py-0.5 rounded border border-red-500/50">
                    Score: {incident.threatScore}/100
                  </span>
                </div>
                <h3 className="text-lg font-black text-white">Recommended: Temporary Account Containment</h3>
                <p className="text-xs text-slate-300 mt-0.5">
                  Simulated Response: Active session terminated, EDR endpoint quarantine active, credential rotation required.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2.5 shrink-0">
              <button
                onClick={() => setIsRecovered(true)}
                className="px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg shadow-emerald-950 flex items-center gap-2 transition-colors cursor-pointer"
              >
                <Unlock className="w-4 h-4" />
                <span>Approve Recovery</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono text-slate-300 pt-2 border-t border-red-500/20">
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30">
              Identity Status: <strong className="text-amber-400">CONTAINED (Session Revoked)</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30">
              Endpoint Policy: <strong className="text-slate-200">EDR Network Isolation Active</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30">
              Admin Action: <strong className="text-red-400">Credential Rotation Required</strong>
            </div>
          </div>
        </div>
      )}

      {/* Admin Recovered State Banner */}
      {isRecovered && (
        <div className="p-5 rounded-2xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-300 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            <div>
              <div className="font-bold text-sm">Account Access Recovered by SOC Administrator</div>
              <div className="text-xs text-slate-400">
                Credential rotation verified; endpoint isolation released. Account status restored to ACTIVE.
              </div>
            </div>
          </div>

          <button
            onClick={() => setIsRecovered(false)}
            className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs font-mono border border-slate-700 cursor-pointer"
          >
            Re-engage Containment
          </button>
        </div>
      )}

      {/* ======================================================== */}
      {/* SECTION 7: AI INVESTIGATOR PANEL                          */}
      {/* ======================================================== */}
      <div className="glass-panel p-8 rounded-2xl border border-indigo-500/40 shadow-2xl shadow-indigo-950/40 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 flex items-center gap-1.5">
                <Bot className="w-3.5 h-3.5 text-indigo-400" /> AI INVESTIGATOR
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Provider: {llmInvestigatorService.getStatus() === 'CONNECTED' ? 'LLM API Connected' : 'Local Forensic Engine (Offline-Ready)'}
              </span>
            </div>
            <h2 className="text-2xl font-black text-white mt-1.5">
              Threat Intelligence Assessment: {incident.title}
            </h2>
          </div>

          {/* Model Signals Summary Strip */}
          <div className="flex items-center gap-3 bg-slate-950/90 p-3 rounded-xl border border-slate-800">
            <div className="text-center px-3 border-r border-slate-800">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Final Threat Score</div>
              <div className="text-xl font-black font-mono text-red-400">{incident.threatScore}/100</div>
            </div>

            <div className="text-center px-3 border-r border-slate-800">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Rule Score</div>
              <div className="text-lg font-bold font-mono text-indigo-300">{incident.ruleScore}</div>
            </div>

            <div className="text-center px-3 border-r border-slate-800">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Isolation Forest</div>
              <div className={`text-xs font-black font-mono px-2 py-0.5 rounded ${
                incident.anomalyResult.label === 'ANOMALOUS' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}>
                {incident.anomalyResult.label} ({incident.anomalyResult.anomalyScorePct}%)
              </div>
            </div>

            <div className="text-center px-3">
              <div className="text-[10px] font-mono text-slate-400 uppercase">XGBoost Attack Prob</div>
              <div className="text-xs font-black font-mono text-amber-400">
                {incident.xgboostResult.attackProbabilityPct}% ({incident.xgboostResult.predictedClass})
              </div>
            </div>
          </div>
        </div>

        {/* Why this is suspicious */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" /> WHY THIS IS SUSPICIOUS
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {incident.llmAssessment?.whySuspicious.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-200 flex items-start gap-2.5"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0 mt-1.5"></span>
                <span className="leading-relaxed">{item}</span>
              </div>
            ))}
          </div>
        </div>

        {/* AI Assessment */}
        <div className="p-5 rounded-2xl bg-indigo-950/20 border border-indigo-500/30 space-y-2">
          <h3 className="text-xs font-bold text-indigo-300 uppercase tracking-wider flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-400" /> AI ASSESSMENT
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            {incident.llmAssessment?.aiAssessment}
          </p>
        </div>

        {/* Recommended Actions */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" /> RECOMMENDED ACTIONS
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {incident.llmAssessment?.recommendedActions.map((action, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-200 flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-md bg-slate-800 text-slate-400 flex items-center justify-center font-mono text-[10px]">
                    {idx + 1}
                  </span>
                  <span>{action}</span>
                </div>
                <button
                  onClick={() => toggleAction(idx + 100)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold cursor-pointer transition-all ${
                    actionStates[idx + 100]
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      : 'bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/30'
                  }`}
                >
                  {actionStates[idx + 100] ? 'Executed ✓' : 'Execute'}
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* False Positive Explanation Card if applicable */}
        {isFalsePositiveCandidate && (
          <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-500/40 flex items-start gap-3 text-xs text-blue-200">
            <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-white">Why was this not classified as a critical threat?</div>
              <div className="text-slate-300 leading-relaxed">
                User activity conforms to authorized operational procedures (valid MFA authentication push and pre-approved Change Ticket CHG-8821). Isolation Forest path analysis and XGBoost classification evaluate this pattern below threat triage thresholds, suppressing false alarms and preventing SOC alert fatigue.
              </div>
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* SECTION 8: CLICKABLE INVESTIGATION QUESTIONS CHAT        */}
        {/* ======================================================== */}
        <div className="pt-4 border-t border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-indigo-400" />
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Interactive Forensic Inquiries (Structured Evidence Q&A)
              </h3>
            </div>
            <span className="text-[11px] text-slate-500">Click any question to query the model</span>
          </div>

          {/* Clickable suggested questions */}
          <div className="flex flex-wrap gap-2">
            {SUGGESTED_INVESTIGATION_QUESTIONS.map((q) => (
              <button
                key={q.id}
                onClick={() => handleAskQuestion(q.question)}
                className="text-xs px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-300 hover:text-white transition-all cursor-pointer shadow-sm"
              >
                {q.question}
              </button>
            ))}
          </div>

          {/* Chat conversation history */}
          <div className="max-h-72 overflow-y-auto space-y-3 p-3 bg-slate-950/80 rounded-2xl border border-slate-800">
            {chatHistory.map((item, idx) => (
              <div
                key={idx}
                className={`p-3.5 rounded-xl text-xs space-y-2 ${
                  item.sender === 'user'
                    ? 'bg-indigo-600/20 border border-indigo-500/30 ml-8 text-indigo-100'
                    : 'bg-slate-900/90 border border-slate-800 mr-4 text-slate-200'
                }`}
              >
                <div className="font-bold text-[11px] flex items-center justify-between text-slate-400">
                  <span className="flex items-center gap-1.5">
                    {item.sender === 'user' ? (
                      <User className="w-3.5 h-3.5 text-indigo-400" />
                    ) : (
                      <Bot className="w-3.5 h-3.5 text-emerald-400" />
                    )}
                    {item.sender === 'user' ? 'Analyst' : 'AI Investigator Engine'}
                  </span>
                  {item.category && <span className="font-mono text-[10px] text-slate-500">{item.category}</span>}
                </div>
                <div className="leading-relaxed whitespace-pre-line text-slate-200 font-sans">
                  {item.text}
                </div>
              </div>
            ))}

            {isThinking && (
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 mr-4 text-xs text-indigo-300 flex items-center gap-2">
                <div className="w-3.5 h-3.5 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin"></div>
                <span>Analyzing structured evidence with cyber reasoning engine...</span>
              </div>
            )}
          </div>

          {/* Custom query input */}
          <div className="flex gap-2">
            <input
              type="text"
              value={chatQuestion}
              onChange={(e) => setChatQuestion(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAskQuestion(chatQuestion)}
              placeholder="Ask custom question (e.g. 'Which entity is most suspicious?', 'Explain XGBoost features')..."
              className="flex-1 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 shadow-inner"
            />
            <button
              onClick={() => handleAskQuestion(chatQuestion)}
              className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs flex items-center justify-center transition-colors cursor-pointer shadow-md shadow-indigo-950"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Grid: Threat Summary & Why Flagged Evidence Cards */}
      <div ref={evidenceSectionRef} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Section: Target Entity Profiles */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 lg:col-span-1 space-y-4">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" /> Target Entity Profiles
          </h2>

          <div className="space-y-3 font-sans text-sm">
            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2 text-xs">
                <User className="w-4 h-4 text-indigo-400" /> User
              </span>
              <span className="font-bold text-slate-100">{incident.user.name} ({incident.user.id})</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2 text-xs">
                <Monitor className="w-4 h-4 text-blue-400" /> Device
              </span>
              <span className="font-bold text-slate-100">{incident.device.name}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2 text-xs">
                <Network className="w-4 h-4 text-amber-400" /> Source IP
              </span>
              <span className="font-mono font-bold text-amber-400 text-xs">{incident.sourceIp}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2 text-xs">
                <Server className="w-4 h-4 text-red-400" /> Target Server
              </span>
              <span className="font-bold text-slate-100">{incident.targetServer}</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2 text-xs">
                <ShieldAlert className="w-4 h-4 text-purple-400" /> Pattern
              </span>
              <span className="font-bold text-red-400 text-xs">{incident.attackPattern}</span>
            </div>
          </div>
        </div>

        {/* Right Section: Correlated Telemetry Evidences */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> Correlated Telemetry Evidences
            </h2>
            <span className="text-xs text-slate-400 font-mono">{incident.evidenceList.length} Evidences Correlated</span>
          </div>

          <div className="space-y-3">
            {incident.evidenceList.map((ev) => (
              <div
                key={ev.id}
                className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 hover:border-slate-700 transition-colors flex items-start justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        ev.severity === 'critical'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : ev.severity === 'high'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }`}
                    >
                      {ev.severity}
                    </span>
                    <span className="text-xs font-bold text-white">{ev.title}</span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{ev.description}</p>
                </div>

                <div className="text-right shrink-0">
                  <span className="text-xs font-mono text-slate-400">{ev.timestamp}</span>
                  <div className="text-[10px] font-mono text-indigo-400 mt-1">{ev.eventId}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ======================================================== */}
      {/* SECTION 9: ATTACK GRAPH INTEGRATION                      */}
      {/* ======================================================== */}
      <div ref={graphSectionRef} className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" /> Reconstructed Attack Graph Topology
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Interactive node-link relationship topology generated from correlated telemetry
            </p>
          </div>

          <button
            onClick={onOpenFullGraph}
            className="px-4 py-2 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 font-semibold text-xs border border-indigo-500/40 flex items-center gap-2 transition-colors cursor-pointer"
          >
            <span>Open Graph Explorer</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>

        {/* ReactFlow graph viewport */}
        <div className="h-96 w-full rounded-xl bg-slate-950 border border-slate-800/80 overflow-hidden relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => {
              const matchedNode = incident.graphNodes.find((n) => n.id === node.id);
              if (matchedNode) setSelectedNodeData(matchedNode);
            }}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#334155" gap={20} size={1} />
            <Controls className="bg-slate-900 border border-slate-800 rounded-lg text-white" />
          </ReactFlow>
        </div>

        {/* Selected Graph Node Inspector */}
        {selectedNodeData && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <span className="font-bold text-white">{selectedNodeData.label}</span>
              <span className="font-mono text-slate-400">Type: {selectedNodeData.type}</span>
              <span className="font-mono text-indigo-400">Risk: {selectedNodeData.risk.toUpperCase()}</span>
            </div>
            <button
              onClick={() => handleAskQuestion(`Tell me about entity ${selectedNodeData.label}`)}
              className="text-indigo-400 hover:text-indigo-300 font-semibold cursor-pointer"
            >
              Ask AI About Node →
            </button>
          </div>
        )}
      </div>

      {/* ======================================================== */}
      {/* SECTION 9 (CONTINUED): ATTACK TIMELINE                   */}
      {/* ======================================================== */}
      <div ref={timelineSectionRef} className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-5 h-5 text-indigo-400" /> Chronological Attack Timeline
          </h2>
          <span className="text-xs font-mono text-slate-400">{incident.timelineEvents.length} Sequential Events</span>
        </div>

        <div className="space-y-3">
          {incident.timelineEvents.map((evt, idx) => (
            <div
              key={evt.event_id || idx}
              onClick={() => setSelectedEvent(evt)}
              className={`p-4 rounded-xl border transition-all cursor-pointer ${
                selectedEvent?.event_id === evt.event_id
                  ? 'bg-indigo-950/40 border-indigo-500/80 ring-1 ring-indigo-500/40'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center space-x-3">
                  <span className="font-mono text-slate-400">{evt.timestamp}</span>
                  <span className="font-bold text-white">{evt.event_type}</span>
                  <span className="text-slate-400">{evt.description}</span>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                    evt.severity === 'critical'
                      ? 'bg-red-500/20 text-red-400'
                      : evt.severity === 'high'
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-emerald-500/20 text-emerald-400'
                  }`}
                >
                  {evt.severity}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
