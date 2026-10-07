import React, { useState, useMemo } from 'react';
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
  Terminal,
  FileText,
  Shield,
  Layers,
  ArrowUpRight,
  ChevronDown,
  Lock,
  UserCheck,
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
import { getAIAnswer } from '../utils/threatEngine';
import { AttackGraphNode } from './AttackGraphNode';

const nodeTypes = {
  customNode: AttackGraphNode,
};

interface InvestigationProps {
  allIncidents: ThreatIncident[];
  onOpenFullGraph: () => void;
}

export const Investigation: React.FC<InvestigationProps> = ({ allIncidents, onOpenFullGraph }) => {
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
  const [chatHistory, setChatHistory] = useState<
    Array<{ sender: 'user' | 'ai'; text: string; evidenceIds?: string[] }>
  >([
    {
      sender: 'ai',
      text: incident.summary,
      evidenceIds: incident.evidenceList.map((e) => e.eventId),
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

  const handleAskQuestion = (qText: string) => {
    if (!qText.trim()) return;
    const { answer, evidenceIds } = getAIAnswer(qText, incident);
    setChatHistory((prev) => [
      ...prev,
      { sender: 'user', text: qText },
      { sender: 'ai', text: answer, evidenceIds },
    ]);
    setChatQuestion('');
  };

  const toggleAction = (id: number) => {
    setActionStates((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const isContained = incident.threatScore > 90 && !isRecovered;

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Incident Switcher Bar */}
      <div className="glass-panel p-4 rounded-2xl border border-indigo-500/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <ShieldAlert className="w-5 h-5 text-indigo-400 shrink-0" />
          <div>
            <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Select Active Incident to Investigate:</span>
            <div className="text-xs text-slate-300">
              Found <strong className="text-emerald-400 font-bold">{allIncidents.length}</strong> correlated user threat profiles in dataset.
            </div>
          </div>
        </div>

        <div className="relative w-full md:w-96">
          <select
            value={selectedIncidentId}
            onChange={(e) => {
              setSelectedIncidentId(e.target.value);
              setIsRecovered(false);
            }}
            className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-indigo-500/50 text-slate-100 font-bold text-xs focus:outline-none focus:border-indigo-400 appearance-none cursor-pointer pr-10"
          >
            {allIncidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                [{inc.id}] {inc.user.name} ({inc.user.id}) — Score: {inc.threatScore}/100 ({inc.severity.toUpperCase()})
              </option>
            ))}
          </select>
          <ChevronDown className="w-4 h-4 text-indigo-400 absolute right-3.5 top-3 pointer-events-none" />
        </div>
      </div>

      {/* Main Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30">
              #{incident.id}
            </span>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">{incident.title}</h1>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Automated multi-stage threat intelligence analysis results for <strong className="text-white">{incident.user.name}</strong>.
          </p>
        </div>

        {/* Header Badges */}
        <div className="flex items-center space-x-4">
          <div className="px-4 py-2 rounded-xl bg-slate-900/90 border border-slate-700/60 flex items-center space-x-3">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Status</span>
            <span className={`text-xs font-extrabold uppercase tracking-wide flex items-center gap-1.5 ${isContained ? 'text-red-400' : 'text-emerald-400'}`}>
              <span className={`w-2 h-2 rounded-full ${isContained ? 'bg-red-500 animate-ping' : 'bg-emerald-500'}`}></span>
              {isContained ? 'CONTAINED' : 'MONITORED'}
            </span>
          </div>

          <div className="px-4 py-2 rounded-xl bg-slate-900/90 border border-red-500/30 flex items-center space-x-3">
            <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Threat Score</span>
            <span className="text-xl font-black text-red-500 font-mono">{incident.threatScore} / 100</span>
          </div>
        </div>
      </div>

      {/* Automatic Containment & Admin Recovery Banner */}
      {isContained && (
        <div className="glass-panel-critical p-6 rounded-2xl border border-red-500/40 space-y-4 animate-red-glow">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-red-500/30 pb-4">
            <div className="flex items-center space-x-3">
              <div className="p-3 rounded-xl bg-red-500/20 text-red-400 border border-red-500/40">
                <Lock className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded bg-red-500/30 text-red-300 text-xs font-mono font-bold uppercase tracking-wider">
                    STATUS: CONTAINED
                  </span>
                  <span className="text-xs text-red-400 font-bold">Threat Score &gt; 90 ({incident.threatScore}/100)</span>
                </div>
                <h3 className="text-lg font-bold text-white mt-1">Automatic Account Containment Initiated</h3>
                <p className="text-xs text-slate-300 mt-0.5">
                  Target User <strong className="text-white">{incident.user.name} ({incident.user.id})</strong> active session terminated, EDR endpoint isolated.
                </p>
              </div>
            </div>

            <button
              onClick={() => setIsRecovered(true)}
              className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg shadow-emerald-950 flex items-center gap-2 transition-colors shrink-0 cursor-pointer"
            >
              <UserCheck className="w-4 h-4" />
              <span>Approve Account Recovery</span>
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono text-slate-300">
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30">
              Credential Security: <strong className="text-amber-400">Credential Rotation Required</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30">
              Recovery Policy: <strong className="text-slate-200">Admin approval required for account recovery</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950/80 border border-red-500/30">
              Containment Reason: <strong className="text-red-400">{incident.attackPattern}</strong>
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
              <div className="font-bold text-sm">Account Access Recovered by Admin</div>
              <div className="text-xs text-slate-400">Credential rotation token issued; account status restored to ACTIVE.</div>
            </div>
          </div>

          <button
            onClick={() => setIsRecovered(false)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-slate-200 text-xs font-mono cursor-pointer"
          >
            Re-trigger Containment
          </button>
        </div>
      )}

      {/* Grid: Threat Summary & Why Flagged */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Section: Threat Summary */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 lg:col-span-1 space-y-5">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" /> Threat Summary
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

        {/* Right Section: Why was this threat flagged? Evidence Cards */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> Why was this threat flagged?
            </h2>
            <span className="text-xs text-slate-400 font-mono">{incident.evidenceList.length} Correlated Evidences</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {incident.evidenceList.map((ev) => {
              const borderSev =
                ev.severity === 'critical'
                  ? 'border-red-500/40 bg-red-950/20 text-red-300'
                  : ev.severity === 'high'
                  ? 'border-amber-500/40 bg-amber-950/20 text-amber-300'
                  : 'border-blue-500/40 bg-blue-950/20 text-blue-300';

              return (
                <div key={ev.id} className={`p-3.5 rounded-xl border ${borderSev} space-y-2 relative group`}>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-xs font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> {ev.title}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700">
                      {ev.eventId}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-2">{ev.description}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-slate-800/60 font-mono">
                    <span>Severity: <strong className="uppercase">{ev.severity}</strong></span>
                    <span>Time: {ev.timestamp}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Interactive Attack Graph Component */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" /> Attack Relationship Graph
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Interactive topology reconstruction connecting user, endpoint, IP, application, server, and C2 nodes.
            </p>
          </div>

          <button
            onClick={onOpenFullGraph}
            className="px-3.5 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <span>Full Canvas View</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* React Flow Container */}
        <div className="h-80 w-full rounded-xl border border-slate-800 bg-slate-950 overflow-hidden relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => setSelectedNodeData(node.data as any)}
            fitView
          >
            <Background color="#1e293b" gap={20} size={1} />
            <Controls />
          </ReactFlow>

          {/* Node detail drawer overlay */}
          {selectedNodeData && (
            <div className="absolute top-3 right-3 w-64 p-4 rounded-xl glass-panel border border-indigo-500/40 text-xs space-y-2 shadow-2xl z-20">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-bold text-slate-100">{selectedNodeData.label}</span>
                <button onClick={() => setSelectedNodeData(null)} className="text-slate-400 hover:text-slate-200">
                  ✕
                </button>
              </div>
              <div className="space-y-1 font-mono text-[11px] text-slate-300">
                <div>Type: <span className="text-indigo-400">{selectedNodeData.type}</span></div>
                <div>Risk Level: <span className="text-red-400 uppercase font-bold">{selectedNodeData.risk}</span></div>
                {selectedNodeData.relatedEventCount && (
                  <div>Correlated Events: <span className="text-slate-100 font-bold">{selectedNodeData.relatedEventCount}</span></div>
                )}
                {selectedNodeData.details &&
                  Object.entries(selectedNodeData.details).map(([k, v]) => (
                    <div key={k} className="text-slate-400">
                      {k}: <span className="text-slate-200 font-semibold">{v}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Grid: Attack Timeline & AI Investigator */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Timeline */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Clock className="w-5 h-5 text-indigo-400" /> Attack Timeline
            </h2>
            <span className="text-xs text-slate-400 font-mono">Chronological Progression</span>
          </div>

          <div className="space-y-3 relative before:absolute before:left-3.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {incident.timelineEvents.map((evt) => {
              const isSelected = selectedEvent?.event_id === evt.event_id;
              const sevBadge =
                evt.severity === 'critical'
                  ? 'bg-red-500/20 text-red-400 border-red-500/40'
                  : evt.severity === 'high'
                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                  : 'bg-blue-500/20 text-blue-400 border-blue-500/40';

              return (
                <div
                  key={evt.event_id}
                  onClick={() => setSelectedEvent(evt)}
                  className={`pl-8 relative cursor-pointer group transition-all p-3 rounded-xl border ${
                    isSelected
                      ? 'bg-slate-900 border-indigo-500/80 shadow-md shadow-indigo-950'
                      : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div
                    className={`absolute left-2.5 top-4 -translate-x-1/2 w-3.5 h-3.5 rounded-full border-2 ${
                      evt.severity === 'critical' ? 'bg-red-500 border-slate-900' : 'bg-indigo-500 border-slate-900'
                    }`}
                  ></div>

                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-indigo-400">{evt.timestamp.substring(11, 16)}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border uppercase ${sevBadge}`}>
                      {evt.severity}
                    </span>
                  </div>

                  <div className="text-sm font-bold text-slate-100 mt-1">{evt.description}</div>
                  <div className="text-xs text-slate-400 flex items-center gap-3 mt-1 font-mono">
                    <span>ID: {evt.event_id}</span>
                    <span>App: {evt.application}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Expanded timeline event detail card */}
          {selectedEvent && (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-2">
              <div className="font-bold text-indigo-300 flex items-center gap-2">
                <FileText className="w-4 h-4" /> Event Inspector #{selectedEvent.event_id}
              </div>
              <div className="grid grid-cols-2 gap-2 font-mono text-slate-300 text-[11px]">
                <div>Time: {selectedEvent.timestamp}</div>
                <div>Type: {selectedEvent.event_type}</div>
                <div>User: {selectedEvent.user_name || selectedEvent.user_id}</div>
                <div>Device: {selectedEvent.device_name || selectedEvent.device_id}</div>
                <div>Source IP: {selectedEvent.ip_address}</div>
                {selectedEvent.destination_ip && <div>Dest IP: {selectedEvent.destination_ip}</div>}
              </div>
            </div>
          )}
        </div>

        {/* AI Investigator Panel */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-indigo-400" /> AI Investigator
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">Ask questions about evidence & threat mechanics</p>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                LLM SOC Agent
              </span>
            </div>

            {/* Quick suggested questions */}
            <div className="pt-3 space-y-1.5">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Suggested Questions</div>
              <div className="flex flex-wrap gap-1.5">
                {[
                  `Why is ${incident.user.name} suspicious?`,
                  'What happened first?',
                  'Which systems are affected?',
                  'What evidence connects these events?',
                  'What should the security team investigate next?',
                ].map((q) => (
                  <button
                    key={q}
                    onClick={() => handleAskQuestion(q)}
                    className="text-[11px] px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors text-left cursor-pointer"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>

            {/* Chat conversation history */}
            <div className="mt-4 max-h-64 overflow-y-auto space-y-3 pr-1">
              {chatHistory.map((item, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded-xl text-xs space-y-2 ${
                    item.sender === 'user'
                      ? 'bg-indigo-600/20 border border-indigo-500/30 ml-6 text-indigo-100'
                      : 'bg-slate-900/90 border border-slate-800 mr-2 text-slate-200'
                  }`}
                >
                  <div className="font-bold text-[11px] flex items-center gap-1.5 text-slate-400">
                    {item.sender === 'user' ? (
                      <User className="w-3.5 h-3.5 text-indigo-400" />
                    ) : (
                      <Shield className="w-3.5 h-3.5 text-emerald-400" />
                    )}
                    {item.sender === 'user' ? 'Analyst' : 'AI Detective Engine'}
                  </div>
                  <p className="leading-relaxed">{item.text}</p>

                  {item.evidenceIds && (
                    <div className="pt-1.5 border-t border-slate-800 flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] text-slate-400 font-mono">Evidence Citations:</span>
                      {item.evidenceIds.map((eid) => (
                        <span key={eid} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                          {eid}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Ask question input */}
          <div className="flex gap-2 pt-2 border-t border-slate-800">
            <input
              type="text"
              value={chatQuestion}
              onChange={(e) => setChatQuestion(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAskQuestion(chatQuestion)}
              placeholder="Ask AI Investigator about this threat..."
              className="flex-1 px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
            />
            <button
              onClick={() => handleAskQuestion(chatQuestion)}
              className="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center justify-center transition-colors cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recommended Investigation Actions Card */}
      <div className="glass-panel p-6 rounded-2xl border border-indigo-500/30 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" /> Recommended Investigation Actions
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Standard operating procedures suggested for analyst review and execution containment.
            </p>
          </div>

          <span className="text-xs font-mono text-emerald-400">SOC Advisory: High Precaution</span>
        </div>

        <div className="space-y-2.5">
          {incident.recommendedActions.map((action) => {
            const isExecuted = actionStates[action.id];
            return (
              <div
                key={action.id}
                className={`p-3.5 rounded-xl border flex items-center justify-between transition-all ${
                  isExecuted
                    ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                    : 'bg-slate-900/60 border-slate-800 text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center space-x-3 text-xs font-semibold">
                  <span className="w-6 h-6 rounded-lg bg-slate-800 text-slate-300 flex items-center justify-center font-mono text-[11px] border border-slate-700">
                    {action.id}
                  </span>
                  <span>{action.text}</span>
                </div>

                <button
                  onClick={() => toggleAction(action.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    isExecuted
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      : 'bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 border border-indigo-500/40'
                  }`}
                >
                  {isExecuted ? 'Action Initiated ✓' : 'Execute Action'}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
