import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Network,
  UploadCloud,
  Settings,
  Shield,
  Zap,
  CheckCircle2,
  FlaskConical,
} from 'lucide-react';

export type NavTab = 'command-center' | 'events' | 'investigations' | 'attack-graph' | 'test-lab' | 'import-csv';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  activeIncidentCount: number;
  demoMode: boolean;
  setDemoMode: (enabled: boolean) => void;
  onLoadDemoData: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  activeIncidentCount,
  demoMode,
  setDemoMode,
  onLoadDemoData,
}) => {
  const navItems = [
    { id: 'command-center' as NavTab, label: 'Command Center', icon: LayoutDashboard },
    { id: 'events' as NavTab, label: 'Security Events', icon: Search },
    {
      id: 'investigations' as NavTab,
      label: 'Investigations',
      icon: ShieldAlert,
      badge: activeIncidentCount > 0 ? activeIncidentCount : undefined,
    },
    { id: 'attack-graph' as NavTab, label: 'Attack Graph', icon: Network },
    { id: 'test-lab' as NavTab, label: 'Threat Test Lab', icon: FlaskConical },
    { id: 'import-csv' as NavTab, label: 'Import CSV', icon: UploadCloud },
  ];

  return (
    <aside className="w-64 bg-slate-950/90 border-r border-slate-800/80 flex flex-col justify-between h-screen sticky top-0 z-30 select-none backdrop-blur-xl">
      <div>
        {/* Brand / Logo */}
        <div className="p-5 border-b border-slate-800/80 flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 via-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-indigo-500/25 ring-1 ring-white/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="font-bold text-slate-100 text-base tracking-tight flex items-center gap-1.5">
              ThreatLens <span className="text-xs px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 font-mono">AI</span>
            </div>
            <div className="text-[11px] text-slate-400 font-medium">Attack Intelligence</div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1.5">
          <div className="px-3 py-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
            SOC Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 cursor-pointer ${
                  isActive
                    ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm shadow-indigo-950'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-indigo-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Footer Controls */}
      <div className="p-3 border-t border-slate-800/80 space-y-2">
        {/* Quick Demo Mode Bar */}
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90 text-xs space-y-2">
          <div className="flex items-center justify-between text-slate-300 font-medium">
            <span className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400 fill-amber-400/20" /> Demo Datasets
            </span>
            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${demoMode ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
              {demoMode ? 'ACTIVE' : 'READY'}
            </span>
          </div>

          <button
            onClick={() => {
              setDemoMode(true);
              onLoadDemoData();
            }}
            className="w-full text-center py-1.5 rounded bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
          >
            <CheckCircle2 className="w-3.5 h-3.5" /> Load 5,000 Events
          </button>
        </div>

        {/* Settings button */}
        <button
          onClick={() => alert('ThreatLens AI Enterprise v2.4 (SOC Edition)\nDataset Schema: 6 Connected CSV Tables Loaded.')}
          className="w-full flex items-center space-x-3 px-3.5 py-2 rounded-lg text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 transition-colors cursor-pointer"
        >
          <Settings className="w-4 h-4 text-slate-400" />
          <span>Settings</span>
        </button>
      </div>
    </aside>
  );
};
