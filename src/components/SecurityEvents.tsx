import React, { useState, useMemo } from 'react';
import { Search, Eye, ChevronLeft, ChevronRight, FileText } from 'lucide-react';
import type { SecurityEvent } from '../types/security';

interface SecurityEventsProps {
  events: SecurityEvent[];
}

export const SecurityEvents: React.FC<SecurityEventsProps> = ({ events }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');
  const [selectedEventModal, setSelectedEventModal] = useState<SecurityEvent | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  // Extract unique event types for filter dropdown
  const uniqueEventTypes = useMemo(() => {
    const types = new Set(events.map((e) => e.event_type));
    return Array.from(types);
  }, [events]);

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      const matchSearch =
        evt.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        evt.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (evt.user_name || evt.user_id).toLowerCase().includes(searchTerm.toLowerCase()) ||
        (evt.device_name || evt.device_id).toLowerCase().includes(searchTerm.toLowerCase()) ||
        evt.ip_address.includes(searchTerm);

      const matchSeverity = severityFilter === 'ALL' || evt.severity.toUpperCase() === severityFilter;
      const matchType = eventTypeFilter === 'ALL' || evt.event_type === eventTypeFilter;

      return matchSearch && matchSeverity && matchType;
    });
  }, [events, searchTerm, severityFilter, eventTypeFilter]);

  // Pagination
  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, currentPage]);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <Search className="w-8 h-8 text-indigo-400" /> Security Log Stream
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Searchable, filterable audit log stream of ingested telemetry across endpoints & firewalls.
          </p>
        </div>

        <div className="text-xs font-mono px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300">
          Total Logs: <strong className="text-indigo-400">{events.length.toLocaleString()}</strong> | Filtered:{' '}
          <strong className="text-emerald-400">{filteredEvents.length.toLocaleString()}</strong>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel p-4 rounded-2xl border border-slate-800/80 flex flex-col md:flex-row items-center gap-4">
        {/* Search Input */}
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search by User, Device, IP, Event ID, or keywords..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
          />
        </div>

        {/* Severity Filter */}
        <div className="flex items-center space-x-2 w-full md:w-auto">
          <span className="text-xs text-slate-400 font-semibold shrink-0">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Event Type Filter */}
        <div className="flex items-center space-x-2 w-full md:w-auto">
          <span className="text-xs text-slate-400 font-semibold shrink-0">Event Type:</span>
          <select
            value={eventTypeFilter}
            onChange={(e) => {
              setEventTypeFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Types</option>
            {uniqueEventTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Security Events Table */}
      <div className="glass-panel rounded-2xl border border-slate-800/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Device</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Server</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginatedEvents.map((evt) => {
                const sevBadge =
                  evt.severity === 'critical'
                    ? 'bg-red-500/20 text-red-400 border-red-500/40'
                    : evt.severity === 'high'
                    ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                    : evt.severity === 'medium'
                    ? 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700';

                return (
                  <tr key={evt.event_id} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-3 px-4 font-bold text-indigo-400">{evt.event_id}</td>
                    <td className="py-3 px-4 text-slate-400">{evt.timestamp}</td>
                    <td className="py-3 px-4 text-slate-200 font-sans font-semibold">{evt.event_type}</td>
                    <td className="py-3 px-4 text-slate-300 font-sans">{evt.user_name || evt.user_id}</td>
                    <td className="py-3 px-4 text-slate-400 font-sans">{evt.device_name || evt.device_id}</td>
                    <td className="py-3 px-4 text-slate-300">{evt.ip_address}</td>
                    <td className="py-3 px-4 text-slate-400">{evt.server_name || evt.server_id || '—'}</td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${sevBadge}`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 font-sans max-w-xs truncate">{evt.description}</td>
                    <td className="py-3 px-4 text-center">
                      <button
                        onClick={() => setSelectedEventModal(evt)}
                        className="p-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 transition-colors"
                        title="View Event Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong className="text-slate-200">{paginatedEvents.length}</strong> of{' '}
            <strong className="text-slate-200">{filteredEvents.length}</strong> entries
          </div>

          <div className="flex items-center space-x-2 font-mono">
            <button
              disabled={currentPage === 1}
              onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              disabled={currentPage === totalPages}
              onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Raw Event Inspector Modal */}
      {selectedEventModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel p-6 rounded-2xl border border-indigo-500/40 max-w-lg w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-slate-100 text-base flex items-center gap-2">
                <FileText className="w-5 h-5 text-indigo-400" /> Event Inspector #{selectedEventModal.event_id}
              </h3>
              <button
                onClick={() => setSelectedEventModal(null)}
                className="text-slate-400 hover:text-slate-200 font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2 font-mono text-xs text-slate-300">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-400">Timestamp:</span>
                <span className="text-slate-100 font-bold">{selectedEventModal.timestamp}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-400">Event Type:</span>
                <span className="text-indigo-400 font-bold">{selectedEventModal.event_type}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-400">User Identity:</span>
                <span className="text-slate-100 font-bold">{selectedEventModal.user_name} ({selectedEventModal.user_id})</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-400">Endpoint Device:</span>
                <span className="text-slate-100 font-bold">{selectedEventModal.device_name} ({selectedEventModal.device_id})</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-400">Source IP:</span>
                <span className="text-amber-400 font-bold">{selectedEventModal.ip_address}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-400">Ingestion Source App:</span>
                <span className="text-slate-100 font-bold">{selectedEventModal.application}</span>
              </div>
              {selectedEventModal.server_id && (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Target Server:</span>
                  <span className="text-red-400 font-bold">{selectedEventModal.server_name || selectedEventModal.server_id}</span>
                </div>
              )}
              {selectedEventModal.destination_ip && (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Destination IP:</span>
                  <span className="text-pink-400 font-bold">{selectedEventModal.destination_ip}</span>
                </div>
              )}
              <div className="p-3 rounded bg-slate-950 border border-slate-800 font-sans">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">Audit Log Description</div>
                <div className="text-slate-200">{selectedEventModal.description}</div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEventModal(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
