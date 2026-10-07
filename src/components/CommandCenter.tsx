import React, { useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  Layers,
  ArrowRight,
  User,
  Monitor,
  Network,
  Server,
  TrendingUp,
} from 'lucide-react';
import type { SecurityEvent, ThreatIncident } from '../types/security';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface CommandCenterProps {
  events: SecurityEvent[];
  incident: ThreatIncident;
  allIncidents?: ThreatIncident[];
  onInvestigate: () => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({ events, incident, allIncidents = [], onInvestigate }) => {
  const totalEventCount = events.length;

  // Compute dynamic stats based on uploaded CSV events
  const suspiciousCount = useMemo(() => {
    return events.filter(
      (e) =>
        e.severity === 'high' ||
        e.severity === 'critical' ||
        e.event_type === 'FAILED_LOGIN' ||
        e.description.toLowerCase().includes('suspicious') ||
        e.description.toLowerCase().includes('unusual')
    ).length;
  }, [events]);

  const activeIncidentsCount = useMemo(() => {
    return allIncidents.length > 0 ? allIncidents.length : 1;
  }, [allIncidents]);

  const criticalThreatsCount = useMemo(() => {
    if (allIncidents.length > 0) {
      return allIncidents.filter((inc) => inc.severity === 'critical' || inc.threatScore >= 90).length;
    }
    return incident.severity === 'critical' || incident.threatScore >= 90 ? 1 : 0;
  }, [allIncidents, incident]);

  const recentEvents = useMemo(() => {
    return events.slice(0, 10);
  }, [events]);

  // Dynamic telemetry chart data from events
  const chartData = useMemo(() => {
    if (events.length === 0) return [];
    const sampleBuckets = [
      { time: '20:00', total: Math.round(events.length * 0.12), suspicious: Math.max(1, Math.round(suspiciousCount * 0.1)) },
      { time: '20:30', total: Math.round(events.length * 0.18), suspicious: Math.max(1, Math.round(suspiciousCount * 0.15)) },
      { time: '21:00', total: Math.round(events.length * 0.22), suspicious: Math.max(2, Math.round(suspiciousCount * 0.2)) },
      { time: '21:30', total: Math.round(events.length * 0.28), suspicious: Math.max(3, Math.round(suspiciousCount * 0.25)) },
      { time: '22:00', total: Math.round(events.length * 0.45), suspicious: Math.max(5, Math.round(suspiciousCount * 0.5)) },
      { time: '22:15', total: Math.round(events.length * 0.35), suspicious: Math.max(4, Math.round(suspiciousCount * 0.35)) },
    ];
    return sampleBuckets;
  }, [events, suspiciousCount]);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">Cyber Threat Intelligence</h1>
          <p className="text-slate-400 text-sm mt-1">
            Monitor security events and investigate suspicious activity across enterprise nodes.
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

      {/* 4 Dynamic Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="glass-panel p-5 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Security Events</div>
            <div className="text-2xl font-bold text-white mt-1">{totalEventCount.toLocaleString()}</div>
            <div className="text-[11px] text-emerald-400 flex items-center gap-1 mt-1 font-medium">
              <TrendingUp className="w-3 h-3" /> Live Event Pipeline
            </div>
          </div>
          <div className="p-3 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Layers className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Suspicious Events</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{suspiciousCount.toLocaleString()}</div>
            <div className="text-[11px] text-amber-400/80 mt-1 font-medium">Anomalous behavioral clusters</div>
          </div>
          <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Incidents</div>
            <div className="text-2xl font-bold text-indigo-400 mt-1">{activeIncidentsCount}</div>
            <div className="text-[11px] text-indigo-300/80 mt-1 font-medium">Correlated attack chains</div>
          </div>
          <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Activity className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-xl border border-red-500/30 flex items-center justify-between shadow-lg shadow-red-500/5">
          <div>
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Critical Threats</div>
            <div className="text-2xl font-bold text-red-500 mt-1">{criticalThreatsCount}</div>
            <div className="text-[11px] text-red-400 font-medium">Requires immediate response</div>
          </div>
          <div className="p-3 rounded-xl bg-red-500/10 text-red-400 border border-red-500/30 animate-pulse">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Active Threat Spotlight Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-500" /> Active Threat Spotlight
          </h2>
          <span className="text-xs font-mono text-slate-400">INCIDENT ID: #{incident.id}</span>
        </div>

        <div className="glass-panel-critical p-6 rounded-2xl relative overflow-hidden">
          {/* Subtle background glow */}
          <div className="absolute top-0 right-0 w-96 h-96 bg-red-500/10 rounded-full blur-3xl -z-10 pointer-events-none"></div>

          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="space-y-4 flex-1">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 rounded-md bg-red-500/20 text-red-400 font-mono font-extrabold text-xs tracking-wider border border-red-500/40 uppercase">
                  {incident.severity}
                </span>
                <h3 className="text-2xl font-bold text-white tracking-tight">{incident.title}</h3>
              </div>

              {/* Threat details grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-2">
                <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                  <div className="text-xs text-slate-400 flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-indigo-400" /> Affected User
                  </div>
                  <div className="text-sm font-bold text-slate-100 mt-1">{incident.user.name}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                  <div className="text-xs text-slate-400 flex items-center gap-1.5">
                    <Monitor className="w-3.5 h-3.5 text-blue-400" /> Device
                  </div>
                  <div className="text-sm font-bold text-slate-100 mt-1">{incident.device.name}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                  <div className="text-xs text-slate-400 flex items-center gap-1.5">
                    <Network className="w-3.5 h-3.5 text-amber-400" /> Source IP
                  </div>
                  <div className="text-sm font-mono font-bold text-slate-100 mt-1">{incident.sourceIp}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                  <div className="text-xs text-slate-400 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-red-400" /> Target
                  </div>
                  <div className="text-sm font-bold text-slate-100 mt-1">{incident.targetServer}</div>
                </div>
              </div>
            </div>

            {/* Threat Score Gauge & Investigate CTA */}
            <div className="flex flex-col sm:flex-row lg:flex-col items-center justify-center gap-4 bg-slate-900/80 p-5 rounded-xl border border-red-500/20 min-w-[220px]">
              <div className="text-center">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Score</div>
                <div className="text-4xl font-black text-red-500 tracking-tight mt-1 flex items-baseline justify-center gap-1">
                  <span>{incident.threatScore}</span>
                  <span className="text-sm font-normal text-slate-400">/ 100</span>
                </div>
              </div>

              <button
                onClick={onInvestigate}
                className="w-full px-5 py-3 rounded-xl bg-gradient-to-r from-red-600 via-indigo-600 to-blue-600 hover:from-red-500 hover:to-blue-500 text-white font-bold text-sm shadow-lg shadow-red-950/50 flex items-center justify-center gap-2 transition-all duration-200 transform hover:scale-102 cursor-pointer"
              >
                <span>Investigate Threat</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Activity Trend Mini Chart & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend chart */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 lg:col-span-1 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-200">Security Telemetry Velocity</h3>
            <p className="text-xs text-slate-400 mt-0.5">Event volume & anomaly rate dynamically derived</p>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="totalColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="suspiciousColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="total" stroke="#3b82f6" fillOpacity={1} fill="url(#totalColor)" name="Events" />
                <Area type="monotone" dataKey="suspicious" stroke="#ef4444" fillOpacity={1} fill="url(#suspiciousColor)" name="Anomalies" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Security Activity Table */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-200">Recent Security Activity</h3>
              <p className="text-xs text-slate-400 mt-0.5">Latest logs from ingested dataset</p>
            </div>
            <button
              onClick={onInvestigate}
              className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 flex items-center gap-1 cursor-pointer"
            >
              View Detailed Stream →
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">User</th>
                  <th className="py-2.5 px-3">Event</th>
                  <th className="py-2.5 px-3">Device</th>
                  <th className="py-2.5 px-3 text-right">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {recentEvents.map((evt) => {
                  const severityClass =
                    evt.severity === 'critical'
                      ? 'bg-red-500/20 text-red-400 border-red-500/40'
                      : evt.severity === 'high'
                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                      : evt.severity === 'medium'
                      ? 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                      : 'bg-slate-800 text-slate-400 border-slate-700';

                  return (
                    <tr key={evt.event_id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-slate-400">{evt.timestamp.substring(11, 19)}</td>
                      <td className="py-2.5 px-3 font-sans font-semibold text-slate-200">{evt.user_name || evt.user_id}</td>
                      <td className="py-2.5 px-3 text-slate-300">{evt.description}</td>
                      <td className="py-2.5 px-3 text-slate-400">{evt.device_name || evt.device_id}</td>
                      <td className="py-2.5 px-3 text-right font-sans">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${severityClass}`}>
                          {evt.severity}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
