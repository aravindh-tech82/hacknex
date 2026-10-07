import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import { User, Monitor, Network, ShieldAlert, Server, Terminal, Globe } from 'lucide-react';
import type { GraphNodeData } from '../types/security';

interface NodeProps {
  data: GraphNodeData;
  selected?: boolean;
}

const nodeIcons = {
  USER: User,
  DEVICE: Monitor,
  IP: Network,
  APPLICATION: ShieldAlert,
  SERVER: Server,
  EVENT: Terminal,
  EXTERNAL_IP: Globe,
};

const borderColors = {
  critical: 'border-red-500/80 shadow-red-500/20 text-red-400',
  high: 'border-amber-500/80 shadow-amber-500/20 text-amber-400',
  medium: 'border-blue-500/80 shadow-blue-500/20 text-blue-400',
  low: 'border-slate-500/80 shadow-slate-500/20 text-slate-400',
};

const badgeColors = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
  high: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  medium: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  low: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
};

export const AttackGraphNode = memo(({ data, selected }: NodeProps) => {
  const IconComponent = nodeIcons[data.type] || Network;

  return (
    <div
      className={`px-4 py-3 rounded-xl glass-panel min-w-[200px] border transition-all duration-200 ${
        selected ? 'ring-2 ring-indigo-500 border-indigo-400 shadow-indigo-500/30 scale-105' : borderColors[data.risk]
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-indigo-500 !w-3 !h-3 !border-2 !border-slate-900" />

      <div className="flex items-center space-x-3">
        <div className={`p-2 rounded-lg bg-slate-900/80 border border-slate-700/60 ${borderColors[data.risk]}`}>
          <IconComponent className="w-5 h-5" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{data.type}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono uppercase border ${badgeColors[data.risk]}`}>
              {data.risk}
            </span>
          </div>
          <div className="text-sm font-bold text-slate-100 truncate mt-0.5">{data.label}</div>
          {data.subtext && <div className="text-xs text-slate-400 truncate mt-0.5">{data.subtext}</div>}
        </div>
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-indigo-500 !w-3 !h-3 !border-2 !border-slate-900" />
    </div>
  );
});

AttackGraphNode.displayName = 'AttackGraphNode';
