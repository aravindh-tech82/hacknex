import React, { useState } from 'react';
import {
  FlaskConical,
  Play,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Lock,
  UserCheck,
  RefreshCw,
  Layers,
  ShieldCheck,
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

import type { SecurityEvent } from '../types/security';
import { analyzeSecurityEvents } from '../utils/threatEngine';
import { AttackGraphNode } from './AttackGraphNode';

const nodeTypes = {
  customNode: AttackGraphNode,
};

interface TestLabProps {
  events: SecurityEvent[];
}

export const TestLab: React.FC<TestLabProps> = ({ events }) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('scenario-1');
  const [targetUserId, setTargetUserId] = useState<string>('USR101');
  const [isSimulating, setIsSimulating] = useState(false);

  // Analyze selected user's scenario
  const incident = analyzeSecurityEvents(events, targetUserId);

  // Interactive Containment & Admin Recovery state
  const [isRecovered, setIsRecovered] = useState(false);

  const scenarios = [
    {
      id: 'scenario-1',
      user: 'USR101',
      name: 'Scenario 1: Account Compromise',
      desc: 'Rahul (USR101): 5 failed logins, new device DEV099, sensitive SRV012 access, PowerShell & C2 outbound stream.',
      badge: 'Critical Attack',
      color: 'border-red-500/40 text-red-400 bg-red-950/20',
    },
    {
      id: 'scenario-2',
      user: 'USR205',
      name: 'Scenario 2: Lateral Movement',
      desc: 'Priya (USR205): Multi-hop lateral pivot USR205 -> DEV020 -> SRV003 -> SRV008 -> SRV014.',
      badge: 'Lateral Movement',
      color: 'border-indigo-500/40 text-indigo-300 bg-indigo-950/20',
    },
    {
      id: 'scenario-3',
      user: 'USR310',
      name: 'Scenario 3: Suspicious Exfiltration',
      desc: 'Vikram (USR310): Late-night mass file reads on SRV004, staging command, and outbound data stream to 91.22.18.4.',
      badge: 'High Exfiltration',
      color: 'border-amber-500/40 text-amber-300 bg-amber-950/20',
    },
    {
      id: 'scenario-4',
      user: 'USR001',
      name: 'Scenario 4: Normal User',
      desc: 'Ananya (USR001): Standard daytime employee baseline operations using primary laptop DEV002.',
      badge: 'Normal Baseline',
      color: 'border-emerald-500/40 text-emerald-300 bg-emerald-950/20',
    },
    {
      id: 'scenario-5',
      user: 'USR102',
      name: 'Scenario 5: False Positive Test',
      desc: 'Amit (USR102): Finance Manager audit access to SRV012 verified via hardware token MFA & change ticket CHG-8821.',
      badge: 'False Positive Pass',
      color: 'border-blue-500/40 text-blue-300 bg-blue-950/20',
    },
    {
      id: 'scenario-6',
      user: 'USR104',
      name: 'Scenario 6: Ransomware Staging',
      desc: 'Siddharth (USR104): Phishing payload, vssadmin delete shadows /all, rapid backup server connection, and file encryption staging.',
      badge: 'Critical Attack',
      color: 'border-red-500/40 text-red-400 bg-red-950/20',
    },
    {
      id: 'scenario-7',
      user: 'USR105',
      name: 'Scenario 7: Insider Data Theft',
      desc: 'Rohan (USR105): Midnight CRM leads dump from Customer-DB-11 (SRV011) and personal cloud exfiltration sync.',
      badge: 'High Exfiltration',
      color: 'border-amber-500/40 text-amber-300 bg-amber-950/20',
    },
    {
      id: 'scenario-8',
      user: 'USR106',
      name: 'Scenario 8: Cloud API Key Abuse',
      desc: 'Deepa (USR106): Leaked AWS access key used from 194.26.29.112, AdministratorAccess IAM attached, S3 bucket dump.',
      badge: 'Critical Attack',
      color: 'border-red-500/40 text-red-400 bg-red-950/20',
    },
    {
      id: 'scenario-9',
      user: 'USR107',
      name: 'Scenario 9: Tor Password Spray',
      desc: 'Karan (USR107): High-velocity password spraying bursts from Tor Exit node 185.220.101.5 and SUID privilege exploration.',
      badge: 'High Threat',
      color: 'border-amber-500/40 text-amber-300 bg-amber-950/20',
    },
    {
      id: 'scenario-10',
      user: 'USR108',
      name: 'Scenario 10: Supply Chain & C2',
      desc: 'Neha (USR108): Poisoned npm package executing reverse shell to 45.154.255.89 with continuous C2 beaconing.',
      badge: 'Critical Attack',
      color: 'border-red-500/40 text-red-400 bg-red-950/20',
    },
    {
      id: 'scenario-11',
      user: 'USR109',
      name: 'Scenario 11: GPU Cryptojacking',
      desc: 'Arjun (USR109): Unauthorized xmrig binary running on GPU cluster SRV016 masquerading as systemd service with stratum pool telemetry.',
      badge: 'High Threat',
      color: 'border-amber-500/40 text-amber-300 bg-amber-950/20',
    },
    {
      id: 'scenario-12',
      user: 'USR110',
      name: 'Scenario 12: Privilege Escalation',
      desc: 'Meera (USR110): Local sudoers exploit on SRV013, unauthorized Enterprise Admin promotion, ntdsutil credential dumping.',
      badge: 'Critical Attack',
      color: 'border-red-500/40 text-red-400 bg-red-950/20',
    },
  ];

  const handleSelectScenario = (sc: (typeof scenarios)[0]) => {
    setSelectedScenarioId(sc.id);
    setTargetUserId(sc.user);
    setIsRecovered(false);
  };

  const handleRunSimulation = () => {
    setIsSimulating(true);
    setIsRecovered(false);
    setTimeout(() => {
      setIsSimulating(false);
    }, 500);
  };

  // Convert graph data to React Flow format
  const initialNodes: Node[] = incident.graphNodes.map((n, idx) => ({
    id: n.id,
    type: 'customNode',
    position: { x: 50 + idx * 220, y: idx % 2 === 0 ? 120 : 200 },
    data: n as any,
  }));

  const initialEdges: Edge[] = incident.graphEdges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: true,
    style: { stroke: '#6366f1', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' },
  }));

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  const isContained = incident.threatScore > 90 && !isRecovered;

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <FlaskConical className="w-8 h-8 text-indigo-400" /> Threat Detection Test Lab
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Simulate threat scenarios across attack patterns, lateral movements, baseline users, and false positive tests.
          </p>
        </div>

        <button
          onClick={handleRunSimulation}
          className="px-6 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-bold text-sm shadow-lg shadow-indigo-950 flex items-center gap-2 cursor-pointer shrink-0"
        >
          <Play className="w-4 h-4 fill-white" />
          <span>Run Simulation</span>
        </button>
      </div>

      {/* Scenario Selector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {scenarios.map((sc) => {
          const isSelected = selectedScenarioId === sc.id;
          return (
            <button
              key={sc.id}
              onClick={() => handleSelectScenario(sc)}
              className={`p-4 rounded-xl border text-left flex flex-col justify-between space-y-3 transition-all ${
                isSelected
                  ? 'bg-slate-900 border-indigo-500/80 ring-2 ring-indigo-500/40 shadow-lg shadow-indigo-950 scale-102'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${sc.color}`}>
                  {sc.badge}
                </span>
                <h3 className="font-bold text-slate-100 text-xs mt-2">{sc.name}</h3>
                <p className="text-[11px] text-slate-400 mt-1 line-clamp-3 leading-snug">{sc.desc}</p>
              </div>

              <div className="text-[10px] font-mono text-slate-500 font-semibold border-t border-slate-800/80 pt-2">
                Target: {sc.user}
              </div>
            </button>
          );
        })}
      </div>

      {/* Simulation Loader */}
      {isSimulating ? (
        <div className="glass-panel p-12 rounded-2xl text-center space-y-3 border border-indigo-500/40">
          <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
          <h3 className="text-base font-bold text-indigo-300">Evaluating multi-signal Threat Engine rules...</h3>
        </div>
      ) : (
        <>
          {/* Automatic Containment Banner & Admin Recovery Flow */}
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
                      Target User <strong className="text-white">{incident.user.name} ({incident.user.id})</strong> active session terminated, EDR agent endpoint isolated.
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => setIsRecovered(true)}
                  className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg shadow-emerald-950 flex items-center gap-2 transition-colors shrink-0"
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
                <ShieldCheck className="w-6 h-6 text-emerald-400" />
                <div>
                  <div className="font-bold text-sm">Account Access Recovered by Admin</div>
                  <div className="text-xs text-slate-400">Credential rotation token issued; account status restored to ACTIVE.</div>
                </div>
              </div>

              <button
                onClick={() => setIsRecovered(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-slate-200 text-xs font-mono"
              >
                Re-trigger Containment
              </button>
            </div>
          )}

          {/* Threat Engine Evaluation Output */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Score & Pattern */}
            <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-indigo-400" /> Threat Score & Risk Assessment
              </h3>

              <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 text-center space-y-2">
                <div className="text-5xl font-black font-mono text-indigo-400">{incident.threatScore} / 100</div>
                <div className="flex items-center justify-center gap-2 pt-1">
                  <span
                    className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider ${
                      incident.severity === 'critical'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                        : incident.severity === 'high'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    }`}
                  >
                    Risk Level: {incident.severity}
                  </span>
                </div>
              </div>

              <div className="space-y-2 text-xs font-sans">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Detected Pattern:</span>
                  <span className="font-bold text-slate-100">{incident.attackPattern}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">User Identity:</span>
                  <span className="font-bold text-slate-100">{incident.user.name} ({incident.user.id})</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Endpoint Device:</span>
                  <span className="font-bold text-slate-100">{incident.device.name}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Target Server:</span>
                  <span className="font-bold text-slate-100">{incident.targetServer}</span>
                </div>
              </div>
            </div>

            {/* Evidence Cards */}
            <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 lg:col-span-2 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" /> Correlated Threat Evidence
                </h3>
                <span className="text-xs text-slate-400 font-mono">{incident.evidenceList.length} Signals Derived</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {incident.evidenceList.map((ev) => (
                  <div key={ev.id} className="p-3.5 rounded-xl border border-slate-800 bg-slate-950 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" /> {ev.title}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                        {ev.eventId}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{ev.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Attack Graph for Scenario */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" /> Scenario Relationship Topology
            </h3>

            <div className="h-64 w-full rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={nodeTypes}
                fitView
              >
                <Background color="#1e293b" gap={20} size={1} />
                <Controls />
              </ReactFlow>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
