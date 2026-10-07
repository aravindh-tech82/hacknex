import React, { useState, useMemo } from 'react';
import { Network, Filter, Info, Shield, User, Monitor, Server, Terminal, Globe, ShieldAlert } from 'lucide-react';
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

import type { ThreatIncident, GraphNodeData } from '../types/security';
import { AttackGraphNode } from './AttackGraphNode';

const nodeTypes = {
  customNode: AttackGraphNode,
};

interface AttackGraphViewProps {
  incident: ThreatIncident;
}

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({ incident }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(incident.graphNodes[0]);
  const [filterRisk, setFilterRisk] = useState<string>('ALL');

  const initialNodes: Node[] = useMemo(() => {
    const layoutPositions: Record<string, { x: number; y: number }> = {
      'node-user': { x: 50, y: 180 },
      'node-device': { x: 300, y: 180 },
      'node-ip': { x: 550, y: 80 },
      'node-app': { x: 550, y: 280 },
      'node-server': { x: 800, y: 180 },
      'node-event': { x: 1050, y: 180 },
      'node-ext-ip': { x: 1300, y: 180 },
    };

    return incident.graphNodes
      .filter((n) => filterRisk === 'ALL' || n.risk.toUpperCase() === filterRisk)
      .map((n) => ({
        id: n.id,
        type: 'customNode',
        position: layoutPositions[n.id] || { x: 100, y: 100 },
        data: n as any,
      }));
  }, [incident, filterRisk]);

  const initialEdges: Edge[] = useMemo(() => {
    return incident.graphEdges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: true,
      style: { stroke: '#6366f1', strokeWidth: 2 },
      labelStyle: { fill: '#94a3b8', fontSize: 11, fontWeight: 600 },
      labelBgStyle: { fill: '#0f172a', fillOpacity: 0.85 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#6366f1',
      },
    }));
  }, [incident]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto h-[calc(100vh-2rem)] flex flex-col">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4 shrink-0">
        <div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <Network className="w-8 h-8 text-indigo-400" /> Attack Relationship Graph
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Visual topology map correlating entity pivots, access vectors, and external network traffic streams.
          </p>
        </div>

        {/* Risk filter */}
        <div className="flex items-center space-x-2 bg-slate-900 p-1.5 rounded-xl border border-slate-800">
          <Filter className="w-4 h-4 text-slate-400 ml-2" />
          <span className="text-xs text-slate-400 font-semibold">Filter:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((r) => (
            <button
              key={r}
              onClick={() => setFilterRisk(r)}
              className={`px-3 py-1 rounded-lg text-xs font-bold transition-all ${
                filterRisk === r
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-950'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Legend Bar */}
      <div className="flex flex-wrap items-center gap-4 px-4 py-2.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs shrink-0">
        <span className="font-bold text-slate-400 flex items-center gap-1.5 uppercase text-[10px] tracking-wider">
          <Info className="w-3.5 h-3.5 text-indigo-400" /> Entity Legend:
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <User className="w-3.5 h-3.5 text-indigo-400" /> User
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <Monitor className="w-3.5 h-3.5 text-blue-400" /> Device
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <Network className="w-3.5 h-3.5 text-amber-400" /> IP
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <ShieldAlert className="w-3.5 h-3.5 text-purple-400" /> App
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <Server className="w-3.5 h-3.5 text-red-400" /> Server
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <Terminal className="w-3.5 h-3.5 text-emerald-400" /> Process
        </span>
        <span className="flex items-center gap-1.5 text-slate-300">
          <Globe className="w-3.5 h-3.5 text-pink-400" /> External IP
        </span>
      </div>

      {/* Main Canvas View */}
      <div className="flex-1 w-full rounded-2xl border border-slate-800 bg-slate-950 overflow-hidden relative shadow-2xl">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => setSelectedNode(node.data as any)}
          fitView
        >
          <Background color="#1e293b" gap={24} size={1} />
          <Controls />
        </ReactFlow>

        {/* Node detail side drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 p-5 rounded-2xl glass-panel border border-indigo-500/40 text-xs space-y-4 shadow-2xl z-20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="w-4 h-4 text-indigo-400" />
                <h3 className="font-bold text-slate-100 text-sm">{selectedNode.label}</h3>
              </div>
              <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-200">
                ✕
              </button>
            </div>

            <div className="space-y-2 font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Entity Type:</span>
                <span className="text-indigo-400 font-bold">{selectedNode.type}</span>
              </div>

              <div className="flex justify-between">
                <span className="text-slate-400">Threat Rating:</span>
                <span className="text-red-400 uppercase font-black">{selectedNode.risk}</span>
              </div>

              {selectedNode.relatedEventCount && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Linked Events:</span>
                  <span className="text-slate-100 font-bold">{selectedNode.relatedEventCount} events</span>
                </div>
              )}
            </div>

            {selectedNode.details && (
              <div className="pt-2 border-t border-slate-800 space-y-1.5">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Node Metadata</div>
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between text-[11px]">
                    <span className="text-slate-400">{k}</span>
                    <span className="text-slate-100 font-semibold">{v}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
