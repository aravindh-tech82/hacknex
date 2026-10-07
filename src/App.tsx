import { useState, useMemo } from 'react';
import { Sidebar } from './components/Sidebar';
import type { NavTab } from './components/Sidebar';
import { CommandCenter } from './components/CommandCenter';
import { LiveMonitor } from './components/LiveMonitor';
import { CsvImport } from './components/CsvImport';
import { Investigation } from './components/Investigation';
import { AttackGraphView } from './components/AttackGraphView';
import { SecurityEvents } from './components/SecurityEvents';
import { TestLab } from './components/TestLab';
import { generate5000DemoEvents } from './data/demoData';
import { analyzeAllIncidents } from './utils/threatEngine';
import type { SecurityEvent } from './types/security';

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('command-center');
  const [demoMode, setDemoMode] = useState<boolean>(true);

  // Loaded security events dataset
  const [events, setEvents] = useState<SecurityEvent[]>(() => generate5000DemoEvents());

  // Analyze all incidents dynamically from current dataset
  const allIncidents = useMemo(() => {
    return analyzeAllIncidents(events);
  }, [events]);

  const primaryIncident = allIncidents[0];

  const handleLoadDemoData = () => {
    setEvents(generate5000DemoEvents());
  };

  const handleCustomDatasetLoaded = (newEvents: SecurityEvent[]) => {
    setEvents(newEvents);
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex font-sans selection:bg-indigo-500 selection:text-white">
      {/* Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        activeIncidentCount={allIncidents.length}
        demoMode={demoMode}
        setDemoMode={setDemoMode}
        onLoadDemoData={handleLoadDemoData}
      />

      {/* Main Content Area */}
      <main className="flex-1 min-w-0 overflow-y-auto">
        {activeTab === 'command-center' && (
          <CommandCenter
            events={events}
            incident={primaryIncident}
            allIncidents={allIncidents}
            onInvestigate={() => setActiveTab('investigations')}
          />
        )}

        {activeTab === 'live-monitor' && (
          <LiveMonitor
            events={events}
            onInvestigateIncident={() => setActiveTab('investigations')}
          />
        )}

        {activeTab === 'import-csv' && (
          <CsvImport
            onLoadDemoDataset={handleLoadDemoData}
            onCustomDatasetLoaded={handleCustomDatasetLoaded}
            onAnalysisComplete={() => setActiveTab('investigations')}
            loadedEventCount={events.length}
            allIncidents={allIncidents}
          />
        )}

        {activeTab === 'investigations' && (
          <Investigation
            allIncidents={allIncidents}
            onOpenFullGraph={() => setActiveTab('attack-graph')}
          />
        )}

        {activeTab === 'attack-graph' && <AttackGraphView incident={primaryIncident} />}

        {activeTab === 'test-lab' && <TestLab events={events} />}

        {activeTab === 'events' && <SecurityEvents events={events} />}
      </main>
    </div>
  );
}

export default App;
