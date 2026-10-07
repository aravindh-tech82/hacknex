import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  CheckCircle2,
  FileText,
  ArrowRight,
  ShieldCheck,
  Database,
  Zap,
  Cpu,
  Download,
  AlertTriangle,
  FolderDown,
  Layers,
  Sparkles,
} from 'lucide-react';
import Papa from 'papaparse';
import type { SecurityEvent, ThreatIncident } from '../types/security';

interface CsvImportProps {
  onLoadDemoDataset: () => void;
  onCustomDatasetLoaded: (events: SecurityEvent[]) => void;
  onAnalysisComplete: () => void;
  loadedEventCount: number;
  allIncidents?: ThreatIncident[];
}

interface ScenarioMeta {
  fileName: string;
  userName: string;
  role: string;
  attackType: string;
  risk: 'CRITICAL' | 'HIGH' | 'LOW' | 'AUDIT PASS' | 'MULTI-THREAT';
  score: number;
  badgeColor: string;
  description: string;
}

const TEST_SCENARIOS: ScenarioMeta[] = [
  {
    fileName: 'threat_1_account_compromise_rahul.csv',
    userName: 'Rahul Sharma (USR101)',
    role: 'Cloud DevOps Engineer',
    attackType: 'Account Compromise & Mimikatz',
    risk: 'CRITICAL',
    score: 94,
    badgeColor: 'border-red-500/40 bg-red-500/10 text-red-400',
    description: 'Impossible travel login from 185.44.21.8, 5 failed attempts, Mimikatz PowerShell, SYSTEM token theft, DB exfiltration.',
  },
  {
    fileName: 'threat_2_lateral_movement_priya.csv',
    userName: 'Priya Verma (USR205)',
    role: 'Senior SysAdmin',
    attackType: 'Lateral Movement & Kerberoasting',
    risk: 'CRITICAL',
    score: 91,
    badgeColor: 'border-red-500/40 bg-red-500/10 text-red-400',
    description: 'Internal pivoting across hosts: SRV003 -> SRV008 -> SRV014 with WMI credential harvesting and Kerberoasting.',
  },
  {
    fileName: 'threat_3_data_exfiltration_vikram.csv',
    userName: 'Vikram Patel (USR310)',
    role: 'Finance Controller',
    attackType: 'Mass File Read & C2 Exfiltration',
    risk: 'HIGH',
    score: 88,
    badgeColor: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
    description: 'Unrecognized device DEV088, 1,400 confidential file reads, tar archive compression, outbound stream to 91.22.18.4.',
  },
  {
    fileName: 'threat_4_ransomware_staging_siddharth.csv',
    userName: 'Siddharth Rao (USR104)',
    role: 'Lead Architect',
    attackType: 'Ransomware Prep & Shadow Deletion',
    risk: 'CRITICAL',
    score: 95,
    badgeColor: 'border-red-500/40 bg-red-500/10 text-red-400',
    description: 'Phishing VBS script execution, vssadmin delete shadows /all, rapid backup storage connection, file encryption staging.',
  },
  {
    fileName: 'threat_5_insider_threat_rohan.csv',
    userName: 'Rohan Mehta (USR105)',
    role: 'Account Executive',
    attackType: 'Insider Data Theft & CRM Dump',
    risk: 'HIGH',
    score: 82,
    badgeColor: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
    description: 'Midnight off-hours login, bulk dump of 25,000 CRM leads from Customer-DB-11 (SRV011), personal cloud upload.',
  },
  {
    fileName: 'threat_6_api_token_leak_deepa.csv',
    userName: 'Deepa Nair (USR106)',
    role: 'Cloud Infrastructure Engineer',
    attackType: 'AWS API Key Leak & IAM Abuse',
    risk: 'CRITICAL',
    score: 90,
    badgeColor: 'border-red-500/40 bg-red-500/10 text-red-400',
    description: 'Leaked long-term access key used from foreign IP 194.26.29.112, AdministratorAccess IAM attached, S3 secret bucket dump.',
  },
  {
    fileName: 'threat_7_brute_force_spray_karan.csv',
    userName: 'Karan Malhotra (USR107)',
    role: 'Product Manager',
    attackType: 'Tor Password Spray & SUID Enum',
    risk: 'HIGH',
    score: 85,
    badgeColor: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
    description: 'High-velocity spray from Tor Exit Node 185.220.101.5, compromised authorization, SUID discovery binary executed.',
  },
  {
    fileName: 'threat_8_supply_chain_poison_neha.csv',
    userName: 'Neha Gupta (USR108)',
    role: 'Fullstack Developer',
    attackType: 'Supply Chain Poisoning & C2 Shell',
    risk: 'CRITICAL',
    score: 93,
    badgeColor: 'border-red-500/40 bg-red-500/10 text-red-400',
    description: 'Malicious npm postinstall script, reverse bash shell to 45.154.255.89, continuous C2 beaconing, CI/CD pipeline tampering.',
  },
  {
    fileName: 'threat_9_crypto_mining_arjun.csv',
    userName: 'Arjun Kapoor (USR109)',
    role: 'AI/ML Engineer',
    attackType: 'GPU Cryptojacking & Masquerade',
    risk: 'HIGH',
    score: 87,
    badgeColor: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
    description: 'xmrig miner deployed on GPU node SRV016 masquerading as systemd service, continuous stratum pool telemetry.',
  },
  {
    fileName: 'threat_10_privilege_escalation_meera.csv',
    userName: 'Meera Joshi (USR110)',
    role: 'Database Administrator',
    attackType: 'Sudoers Exploit & NTDS Dump',
    risk: 'CRITICAL',
    score: 92,
    badgeColor: 'border-red-500/40 bg-red-500/10 text-red-400',
    description: 'Local sudoers privilege escalation on SRV013, unauthorized Enterprise Admin promotion, ntdsutil credential dumping.',
  },
  {
    fileName: 'normal_user_ananya.csv',
    userName: 'Ananya Roy (USR001)',
    role: 'Sales Executive',
    attackType: 'Normal Corporate Activity (Clean Baseline)',
    risk: 'LOW',
    score: 12,
    badgeColor: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
    description: 'Standard business hours activity, Okta MFA push verified, Salesforce CRM, Slack, Google Docs. Clean compliance.',
  },
  {
    fileName: 'normal_user_aditya.csv',
    userName: 'Aditya Sen (USR002)',
    role: 'Software Engineer',
    attackType: 'Normal Developer Workflow (Clean Baseline)',
    risk: 'LOW',
    score: 10,
    badgeColor: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
    description: 'FIDO2 token hardware MFA verification, Git commits, kubectl logs on staging cluster, Jira updates.',
  },
  {
    fileName: 'false_positive_audit_amit.csv',
    userName: 'Amit Kulkarni (USR102)',
    role: 'IT Systems Engineer',
    attackType: 'Legitimate Sensitive Access (Audit Pass)',
    risk: 'AUDIT PASS',
    score: 28,
    badgeColor: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
    description: 'Scheduled audit on Finance Database SRV012 under Change Ticket CHG-8821 with hardware token MFA verified.',
  },
  {
    fileName: 'multi_user_enterprise_day_shift.csv',
    userName: 'Multi-User Fleet (6 Users)',
    role: 'Enterprise Fleet',
    attackType: 'Concurrent Multi-User Shift with Active Attacks',
    risk: 'MULTI-THREAT',
    score: 94,
    badgeColor: 'border-purple-500/40 bg-purple-500/10 text-purple-400',
    description: 'Blended enterprise traffic with concurrent normal users, audit passes, and multi-stage attacks from Rahul, Priya, & Vikram.',
  },
];

export const CsvImport: React.FC<CsvImportProps> = ({
  onLoadDemoDataset,
  onCustomDatasetLoaded,
  onAnalysisComplete,
  loadedEventCount,
  allIncidents = [],
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStep, setAnalysisStep] = useState<number>(0);
  const [analysisDone, setAnalysisDone] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [activeLoadedScenario, setActiveLoadedScenario] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const primaryIncident = allIncidents[0];

  const analysisChecklist = [
    'Normalizing security event structure...',
    'Extracting entity identities (Users, Devices, IPs)...',
    'Detecting anomalous behavioral sequences...',
    'Mapping cross-domain entity relationships...',
    'Reconstructing multi-stage attack sequence graph...',
  ];

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedFileName(file.name);
      setActiveLoadedScenario(null);
      parseCSV(file);
    }
  };

  const parseCSV = (file: File) => {
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        const parsedEvents: SecurityEvent[] = results.data.map((row: any, idx: number) => ({
          event_id: row.event_id || `E${String(idx + 1).padStart(3, '0')}`,
          timestamp: row.timestamp || new Date().toISOString().replace('T', ' ').substring(0, 19),
          event_type: row.event_type || 'UNKNOWN',
          user_id: row.user_id || 'USR101',
          user_name: row.user_name || (row.user_id === 'USR101' ? 'Rahul Sharma' : row.user_id || 'User'),
          device_id: row.device_id || 'DEV099',
          device_name: row.device_name || (row.device_id === 'DEV099' ? 'Laptop-099' : row.device_id || 'Device'),
          ip_address: row.ip_address || '185.44.21.8',
          application: row.application || 'VPN Gateway',
          server_id: row.server_id || '',
          server_name: row.server_id ? (row.server_id === 'SRV012' ? 'Server-12' : row.server_id) : '',
          destination_ip: row.destination_ip || '',
          severity: (row.severity?.toLowerCase() as any) || 'medium',
          description: row.description || 'Uploaded security log entry',
        }));

        if (parsedEvents.length > 0) {
          onCustomDatasetLoaded(parsedEvents);
          setAnalysisDone(false);
        }
      },
    });
  };

  const loadScenarioFromPublic = async (fileName: string) => {
    try {
      const response = await fetch(`/demo-data/${fileName}`);
      if (!response.ok) {
        throw new Error(`Failed to load ${fileName}`);
      }
      const csvText = await response.text();
      setUploadedFileName(fileName);
      setActiveLoadedScenario(fileName);

      Papa.parse(csvText, {
        header: true,
        skipEmptyLines: true,
        complete: (results) => {
          const parsedEvents: SecurityEvent[] = results.data.map((row: any, idx: number) => ({
            event_id: row.event_id || `E${String(idx + 1).padStart(3, '0')}`,
            timestamp: row.timestamp || new Date().toISOString().replace('T', ' ').substring(0, 19),
            event_type: row.event_type || 'UNKNOWN',
            user_id: row.user_id || 'USR101',
            user_name: row.user_name || (row.user_id === 'USR101' ? 'Rahul Sharma' : row.user_id || 'User'),
            device_id: row.device_id || 'DEV099',
            device_name: row.device_name || (row.device_id === 'DEV099' ? 'Laptop-099' : row.device_id || 'Device'),
            ip_address: row.ip_address || '185.44.21.8',
            application: row.application || 'VPN Gateway',
            server_id: row.server_id || '',
            server_name: row.server_id ? (row.server_id === 'SRV012' ? 'Server-12' : row.server_id) : '',
            destination_ip: row.destination_ip || '',
            severity: (row.severity?.toLowerCase() as any) || 'medium',
            description: row.description || 'Security log entry',
          }));

          if (parsedEvents.length > 0) {
            onCustomDatasetLoaded(parsedEvents);
            setAnalysisDone(false);
          }
        },
      });
    } catch (err) {
      console.error('Error fetching demo scenario:', err);
    }
  };

  const startAnalysis = () => {
    setIsAnalyzing(true);
    setAnalysisStep(0);
    setAnalysisDone(false);

    let currentStep = 0;
    const interval = setInterval(() => {
      currentStep++;
      if (currentStep < analysisChecklist.length) {
        setAnalysisStep(currentStep);
      } else {
        clearInterval(interval);
        setIsAnalyzing(false);
        setAnalysisDone(true);
      }
    }, 450);
  };

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <UploadCloud className="w-8 h-8 text-indigo-400" /> Import Security Events CSV
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Upload real-world security logs or select from 14 pre-built scenario datasets with different users and attack types.
        </p>
      </div>

      {/* Main Drag and Drop Box */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (e.dataTransfer.files?.[0]) {
            const file = e.dataTransfer.files[0];
            setUploadedFileName(file.name);
            setActiveLoadedScenario(null);
            parseCSV(file);
          }
        }}
        className={`glass-panel p-10 rounded-2xl border-2 border-dashed text-center transition-all duration-200 ${
          dragOver ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-700/80 hover:border-slate-600'
        }`}
      >
        <input type="file" accept=".csv" ref={fileInputRef} onChange={handleFileChange} className="hidden" />

        <div className="w-16 h-16 mx-auto rounded-2xl bg-indigo-600/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 mb-4 shadow-lg shadow-indigo-950">
          <FileText className="w-8 h-8" />
        </div>

        <h3 className="text-lg font-bold text-slate-100">
          {uploadedFileName ? `File Selected: ${uploadedFileName}` : 'Drop Any Security Events CSV Here'}
        </h3>
        <p className="text-slate-400 text-xs mt-1">
          Schema: <span className="font-mono text-slate-300">event_id, timestamp, event_type, user_id, device_id, ip_address, application, server_id, destination_ip, severity, description</span>
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3 mt-6">
          <button
            onClick={() => fileInputRef.current?.click()}
            className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 font-semibold text-sm transition-colors cursor-pointer"
          >
            Browse Files on Computer
          </button>

          <span className="text-xs text-slate-500 font-medium">or</span>

          <button
            onClick={() => {
              setUploadedFileName('security_events.csv (~5,000 Master Telemetry Stream)');
              setActiveLoadedScenario(null);
              onLoadDemoDataset();
              setAnalysisDone(false);
            }}
            className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm shadow-md shadow-indigo-950 flex items-center gap-2 transition-all cursor-pointer"
          >
            <Zap className="w-4 h-4 text-amber-300" /> Load Master Telemetry (~5,000 Events)
          </button>
        </div>
      </div>

      {/* Dataset Loaded Banner */}
      {loadedEventCount > 0 && !isAnalyzing && !analysisDone && (
        <div className="glass-panel p-6 rounded-2xl border border-emerald-500/30 bg-emerald-950/20 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="text-base font-bold text-emerald-300 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" /> {loadedEventCount.toLocaleString()} events ready in memory
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                {uploadedFileName ? `Source: ${uploadedFileName}` : 'Synthetic telemetry logs loaded'}. Ready for AI correlation, scoring, and attack graph reconstruction.
              </div>
            </div>
          </div>

          <button
            onClick={startAnalysis}
            className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-bold text-sm shadow-lg shadow-indigo-950 flex items-center justify-center gap-2 cursor-pointer transition-transform hover:scale-105"
          >
            <Cpu className="w-4 h-4" />
            <span>Analyze Security Events</span>
          </button>
        </div>
      )}

      {/* Analyzing Animation Box */}
      {isAnalyzing && (
        <div className="glass-panel p-8 rounded-2xl border border-indigo-500/40 space-y-6">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded-full border-2 border-indigo-500 border-t-transparent animate-spin"></div>
            <h3 className="text-lg font-bold text-indigo-300">Analyzing security events across users & entities...</h3>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {analysisChecklist.map((stepText, idx) => {
              const isDone = idx < analysisStep;
              const isCurrent = idx === analysisStep;
              return (
                <div
                  key={idx}
                  className={`flex items-center space-x-3 p-2.5 rounded-lg border transition-all ${
                    isDone
                      ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-400'
                      : isCurrent
                      ? 'bg-indigo-950/50 border-indigo-500/40 text-indigo-200 animate-pulse'
                      : 'bg-slate-900/40 border-slate-800 text-slate-600'
                  }`}
                >
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-current shrink-0"></div>
                  )}
                  <span>{isDone ? stepText.replace('...', ' complete') : stepText}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Analysis Done Banner (Dynamic based on detected incident) */}
      {analysisDone && primaryIncident && (
        <div
          className={`p-8 rounded-2xl text-center space-y-4 ${
            primaryIncident.threatScore >= 70
              ? 'glass-panel-critical animate-red-glow'
              : primaryIncident.threatScore >= 40
              ? 'glass-panel border-amber-500/40 bg-amber-950/20'
              : 'glass-panel border-emerald-500/40 bg-emerald-950/20'
          }`}
        >
          <div
            className={`w-16 h-16 mx-auto rounded-full border flex items-center justify-center shadow-xl ${
              primaryIncident.threatScore >= 70
                ? 'bg-red-500/20 border-red-500/40 text-red-500 shadow-red-950'
                : primaryIncident.threatScore >= 40
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-400 shadow-amber-950'
                : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400 shadow-emerald-950'
            }`}
          >
            {primaryIncident.threatScore >= 70 ? (
              <AlertTriangle className="w-8 h-8" />
            ) : (
              <ShieldCheck className="w-8 h-8" />
            )}
          </div>

          <div>
            <h3 className="text-2xl font-black text-white tracking-tight">
              {primaryIncident.threatScore >= 70
                ? `${allIncidents.length > 1 ? `${allIncidents.length} Threats Detected` : '1 Critical Threat Detected'}`
                : primaryIncident.threatScore >= 40
                ? 'Moderate Security Alert Flagged'
                : 'Clean Security Baseline Verified'}
            </h3>
            <p className="text-slate-300 text-sm mt-1 max-w-2xl mx-auto">
              Correlated user:{' '}
              <span className="font-bold text-white">
                {primaryIncident.user.name} ({primaryIncident.user.id})
              </span>{' '}
              — Pattern:{' '}
              <span
                className={`font-bold ${
                  primaryIncident.threatScore >= 70
                    ? 'text-red-400'
                    : primaryIncident.threatScore >= 40
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {primaryIncident.attackPattern}
              </span>{' '}
              (Threat Score: <span className="font-mono">{primaryIncident.threatScore}/100</span>).
            </p>
          </div>

          <button
            onClick={onAnalysisComplete}
            className={`px-8 py-3.5 rounded-xl text-white font-extrabold text-sm shadow-xl flex items-center gap-2 mx-auto cursor-pointer transition-transform hover:scale-105 ${
              primaryIncident.threatScore >= 70
                ? 'bg-gradient-to-r from-red-600 via-indigo-600 to-blue-600 hover:from-red-500 hover:to-blue-500 shadow-red-950'
                : 'bg-gradient-to-r from-indigo-600 to-emerald-600 hover:from-indigo-500 hover:to-emerald-500 shadow-indigo-950'
            }`}
          >
            <span>Open Detailed Investigation ({primaryIncident.id})</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Pre-Built Test Scenarios Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Layers className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-bold text-slate-100">
              Ready-to-Test Threat Datasets ({TEST_SCENARIOS.length} Scenarios)
            </h2>
          </div>
          <span className="text-xs text-slate-400 bg-slate-800/80 px-3 py-1 rounded-full border border-slate-700">
            Click ⚡ Test to load directly or 📥 Download to test manual upload
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {TEST_SCENARIOS.map((scenario) => {
            const isLoaded = activeLoadedScenario === scenario.fileName;
            return (
              <div
                key={scenario.fileName}
                className={`p-5 rounded-2xl border transition-all ${
                  isLoaded
                    ? 'bg-indigo-950/40 border-indigo-500/80 shadow-lg shadow-indigo-950/40 ring-1 ring-indigo-500/40'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white">{scenario.userName}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${scenario.badgeColor}`}>
                        {scenario.risk}
                      </span>
                    </div>
                    <div className="text-xs text-indigo-300 font-medium mt-0.5">{scenario.role}</div>
                  </div>
                  <div className="text-right">
                    <span className="text-xs font-mono font-bold text-slate-300">
                      Score: <span className={scenario.score >= 80 ? 'text-red-400' : scenario.score >= 40 ? 'text-amber-400' : 'text-emerald-400'}>{scenario.score}</span>/100
                    </span>
                  </div>
                </div>

                <div className="text-xs font-semibold text-slate-200 mt-2 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <span>{scenario.attackType}</span>
                </div>

                <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                  {scenario.description}
                </p>

                <div className="flex items-center justify-between gap-2 mt-4 pt-3 border-t border-slate-800/80">
                  <span className="text-[11px] font-mono text-slate-500 truncate max-w-[180px]">
                    {scenario.fileName}
                  </span>

                  <div className="flex items-center gap-2 shrink-0">
                    <a
                      href={`/demo-data/${scenario.fileName}`}
                      download={scenario.fileName}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors"
                      title="Download CSV to test manual drag & drop"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download</span>
                    </a>

                    <button
                      onClick={() => loadScenarioFromPublic(scenario.fileName)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                        isLoaded
                          ? 'bg-emerald-600 text-white'
                          : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-md shadow-indigo-950'
                      }`}
                    >
                      <Zap className="w-3.5 h-3.5 text-amber-300" />
                      <span>{isLoaded ? 'Loaded in Memory' : 'Test Threat'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Directory location help note */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 flex items-start gap-3">
        <FolderDown className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400 space-y-1">
          <div className="font-semibold text-slate-200">Local Filesystem Location</div>
          <div>
            All CSV files are saved in <span className="font-mono text-slate-300">c:\Desktop\HACKNEX\demo-data\</span> and <span className="font-mono text-slate-300">public\demo-data\</span>. You can upload any file directly from your disk or use the 1-click test buttons above.
          </div>
        </div>
      </div>
    </div>
  );
};
