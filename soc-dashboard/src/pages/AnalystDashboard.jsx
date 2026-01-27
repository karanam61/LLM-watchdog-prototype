import { useState, useEffect } from 'react';
import { ShieldAlert, Search, CheckCircle, ExternalLink, RefreshCcw, AlertTriangle, ChevronDown, FileText, Save } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../utils/api';

const AnalystDashboard = () => {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('main'); // main, investigation, history
    const [expandedId, setExpandedId] = useState(null);
    const [activeLogTab, setActiveLogTab] = useState('summary');
    const [logs, setLogs] = useState({ process: null, network: null, file: null, windows: null });
    const [loadingLogs, setLoadingLogs] = useState(false);
    const [analystNotes, setAnalystNotes] = useState({}); // Track notes per alert
    const [savingNotes, setSavingNotes] = useState(false);

    // Poll for alerts with retry logic
    useEffect(() => {
        let retryCount = 0;
        let timeoutId;

        const fetchAlerts = async () => {
            try {
                const res = await api.get('/alerts');

                const data = res.data;
                if (data.alerts) {
                    setAlerts(data.alerts);
                    retryCount = 0; // Reset on success
                }
            } catch (e) {
                console.error("Failed to fetch alerts", e);
                retryCount++;
                // Exponential backoff: 2s, 4s, 8s... max 30s
                const delay = Math.min(2000 * Math.pow(2, retryCount), 30000);
                console.warn(`Retrying in ${delay}ms...`);
                // Note: The setInterval below continues regardless, but this handles burst failures
            } finally {
                setLoading(false);
            }
        };

        fetchAlerts();
        const interval = setInterval(fetchAlerts, 5000); // Normal polling
        return () => {
            clearInterval(interval);
            clearTimeout(timeoutId);
        };
    }, []);

    const handleCloseAlert = async (id, e) => {
        if (e) e.stopPropagation();
        try {
            await api.patch(`/api/alerts/${id}`, { status: 'closed' });
            // Update local state to remove from 'main' view
            setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'closed' } : a));
        } catch (error) {
            console.error("Failed to close alert:", error);
            alert("Failed to close alert: " + (error.response?.data?.error || error.message));
        }
    };

    const handleCreateCase = async (id, e) => {
        if (e) e.stopPropagation();
        try {
            await api.patch(`/api/alerts/${id}`, { status: 'investigating' });
            alert("Case Created! Moved to Investigation Channel.");
            setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'investigating' } : a));
        } catch (error) {
            console.error("Failed to create case:", error);
            alert("Failed to create case: " + (error.response?.data?.error || error.message));
        }
    };

    // Save analyst notes for an alert
    const handleSaveNotes = async (id, notes) => {
        try {
            await api.patch(`/api/alerts/${id}`, { analyst_notes: notes });
        } catch (error) {
            console.error("Failed to save notes:", error);
        }
    };

    const toggleExpand = (id) => {
        if (expandedId === id) {
            setExpandedId(null);
        } else {
            setExpandedId(id);
            setActiveLogTab('summary'); // Reset to summary when opening new alert
            setLogs({ process: null, network: null, file: null, windows: null }); // Reset to null (loading)

            // Pre-fetch all logs in parallel for instant switching
            const alert = alerts.find(a => a.id === id);
            if (alert) {
                ['process', 'network', 'file'].forEach(type => {
                    fetchInvestigationLogs(alert, type);
                });
            }
        }
    };

    const fetchInvestigationLogs = async (alert, type) => {
        setLoadingLogs(true);
        try {
            // FIXED: Using alert_id as verified by backend schema
            let url = `/api/logs?type=${type}&alert_id=${alert.id}`;

            const res = await api.get(url);
            const data = res.data;
            setLogs(prev => ({ ...prev, [type]: data }));
        } catch (e) {
            console.error("Failed to fetch logs", e);
        } finally {
            setLoadingLogs(false);
        }
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL_HIGH': return { border: 'border-red-500', badge: 'bg-red-500/10 text-red-400 border-red-500/50' };
            case 'HIGH': return { border: 'border-orange-500', badge: 'bg-orange-500/10 text-orange-400 border-orange-500/50' };
            default: return { border: 'border-cyan-500', badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/50' };
        }
    };

    const filteredAlerts = alerts.filter(a => {
        if (activeTab === 'main') return (a.status === 'open' || a.status === 'analyzed') && a.severity_class !== 'LOW';
        if (activeTab === 'investigation') return a.status === 'investigating';
        if (activeTab === 'history') return a.status === 'closed';
        return true;
    });

    return (
        <div className="p-8 h-screen flex flex-col max-w-7xl mx-auto">

            {/* Header */}
            <div className="flex justify-between items-end mb-8">
                <div>
                    <h2 className="text-3xl font-bold text-white tracking-tight mb-2">My Operations</h2>
                    <div className="flex gap-4 text-sm text-slate-400">
                        <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> Systems Online</span>
                        <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-cyan-500"></span> AI Engine Active</span>
                    </div>
                </div>

                {/* Tabs */}
                <div className="flex bg-slate-900/50 p-1 rounded-lg border border-slate-800 backdrop-blur-sm">
                    {['main', 'investigation', 'history'].map(tab => (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            className={`px-6 py-2 rounded-md text-sm font-medium transition-all duration-200 capitalize ${activeTab === tab ? 'bg-slate-800 text-white shadow-lg border border-slate-700' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                            {tab} Channel
                        </button>
                    ))}
                </div>
            </div>

            {loading && (
                <div className="flex-1 flex items-center justify-center text-cyan-500 animate-pulse">
                    <RefreshCcw size={32} className="animate-spin" />
                    <span className="ml-3 font-mono">ESTABLISHING UPLINK...</span>
                </div>
            )}

            {/* Alert Feed */}
            <div className="flex-1 space-y-4 overflow-y-auto pb-20 custom-scrollbar pr-2 min-h-0">
                <AnimatePresence>
                    {filteredAlerts.length === 0 && !loading ? (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="p-12 text-center text-slate-500 border-2 border-dashed border-slate-800 rounded-xl"
                        >
                            No alerts found needing attention.
                        </motion.div>
                    ) : (
                        filteredAlerts.map(alert => (
                            <motion.div
                                key={alert.id}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, height: 0 }}
                                transition={{ duration: 0.2 }}
                                className={`
                  glass-panel glass-panel-hover overflow-hidden border-l-4 
                  ${getSeverityColor(alert.severity_class).border}
                `}
                            >
                                {/* Alert Header Row */}
                                <div
                                    className="p-5 flex items-center gap-6 cursor-pointer hover:bg-white/5 transition-colors"
                                    onClick={() => toggleExpand(alert.id)}
                                >
                                    {/* Severity Badge */}
                                    <div className={`px-3 py-1 rounded text-xs font-bold tracking-wider uppercase border ${getSeverityColor(alert.severity_class).badge}`}>
                                        {alert.severity_class?.replace('_', ' ') || 'UNKNOWN'}
                                    </div>

                                    {/* Main Info */}
                                    <div className="flex-1 grid grid-cols-12 gap-8 items-center">
                                        <div className="col-span-4">
                                            <div className="font-semibold text-lg text-white group-hover:text-cyan-400 transition-colors">
                                                {alert.alert_name}
                                            </div>
                                            <div className="text-xs text-slate-500 font-mono mt-1">
                                                {alert.mitre_technique || 'NO-MITRE'} • {new Date(alert.created_at).toLocaleTimeString()}
                                            </div>
                                        </div>

                                        <div className="col-span-3 text-sm text-slate-400 flex items-center gap-2">
                                            <span className="w-2 h-2 rounded-full bg-slate-600"></span>
                                            {alert.source_ip || 'N/A'}
                                        </div>

                                        <div className="col-span-2 text-sm text-slate-400">
                                            {alert.hostname || 'N/A'}
                                        </div>

                                        {/* AI Assessment Pill */}
                                        <div className="col-span-3 flex justify-end">
                                            {alert.ai_verdict ? (
                                                <div className={`flex items-center gap-3 px-4 py-2 rounded-full border bg-slate-950/50 ${alert.ai_verdict === 'MALICIOUS' ? 'border-red-500/50 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.2)]' :
                                                    alert.ai_verdict === 'BENIGN' ? 'border-green-500/50 text-green-400' :
                                                        alert.ai_verdict === 'ERROR' ? 'border-purple-500/50 text-purple-400' :
                                                            alert.ai_verdict === 'SKIPPED' ? 'border-slate-500/50 text-slate-400' :
                                                                'border-yellow-500/50 text-yellow-400'
                                                    }`}>
                                                    <ShieldAlert size={16} />
                                                    <span className="font-bold text-sm tracking-wide">{alert.ai_verdict}</span>
                                                    <span className="text-xs opacity-60 font-mono">{(alert.ai_confidence * 100).toFixed(0)}%</span>
                                                </div>
                                            ) : (
                                                <div className="flex items-center gap-2 text-slate-600 text-sm animate-pulse">
                                                    <RefreshCcw size={14} className="animate-spin" /> Analyzing...
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    <ChevronDown
                                        className={`text-slate-500 transition-transform duration-300 ${expandedId === alert.id ? 'rotate-180' : ''}`}
                                    />
                                </div>

                                {/* Expanded Details */}
                                <AnimatePresence>
                                    {expandedId === alert.id && (
                                        <motion.div
                                            initial={{ height: 0, opacity: 0 }}
                                            animate={{ height: "auto", opacity: 1 }}
                                            exit={{ height: 0, opacity: 0 }}
                                            className="bg-slate-950/50 border-t border-slate-800"
                                        >
                                            {/* Log Tabs */}
                                            <div className="flex border-b border-slate-800 px-6 pt-4 gap-4">
                                                {['summary', 'process', 'network', 'file', 'notes'].map(tab => (
                                                    <button
                                                        key={tab}
                                                        onClick={() => {
                                                            setActiveLogTab(tab);
                                                            // Initialize notes from alert if switching to notes tab
                                                            if (tab === 'notes' && !analystNotes[alert.id]) {
                                                                setAnalystNotes(prev => ({
                                                                    ...prev,
                                                                    [alert.id]: alert.analyst_notes || ''
                                                                }));
                                                            }
                                                        }}
                                                        className={`pb-3 text-sm font-medium border-b-2 transition-colors capitalize flex items-center gap-2 ${activeLogTab === tab
                                                            ? 'border-cyan-500 text-cyan-400'
                                                            : 'border-transparent text-slate-500 hover:text-slate-300'}`}
                                                    >
                                                        {tab === 'summary' ? 'Analysis Summary' : 
                                                         tab === 'notes' ? <><FileText size={14} /> Notes</> : 
                                                         `${tab} Logs`}
                                                    </button>
                                                ))}
                                            </div>

                                            <div className="p-6">
                                                {/* SUMMARY VIEW */}
                                                {activeLogTab === 'summary' && (
                                                    <div className="grid grid-cols-2 gap-8">
                                                        {/* Left: Description & Evidence */}
                                                        <div className="space-y-6">
                                                            <div>
                                                                <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Description</h4>
                                                                <p className="text-slate-300 leading-relaxed">{alert.description}</p>
                                                            </div>


                                                            {alert.ai_evidence && (
                                                                <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-800">
                                                                    <div className="flex items-center gap-2 mb-3 text-cyan-400 text-sm font-semibold">
                                                                        <Search size={16} />
                                                                        AI EVIDENCE CHAIN
                                                                    </div>
                                                                    <ul className="space-y-2">
                                                                        {Array.isArray(alert.ai_evidence) && alert.ai_evidence.map((ev, i) => (
                                                                            <li key={i} className="text-sm text-slate-400 flex gap-2">
                                                                                <span className="text-cyan-500/50">•</span>
                                                                                {ev}
                                                                            </li>
                                                                        ))}
                                                                    </ul>
                                                                </div>
                                                            )}
                                                        </div>

                                                        {/* Right: AI Reasoning & Actions */}
                                                        <div className="space-y-6">
                                                            <div>
                                                                <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">AI Reasoning</h4>
                                                                <div className="text-sm text-slate-300 italic pl-4 border-l-2 border-slate-700">
                                                                    "{alert.ai_reasoning || 'Pending analysis...'}"
                                                                </div>
                                                            </div>

                                                            <div className="flex items-center gap-3 pt-4">
                                                                <button
                                                                    className="glass-button bg-cyan-500/10 text-cyan-400 border border-cyan-500/50 px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-medium hover:bg-cyan-500/20 shadow-[0_0_10px_rgba(6,182,212,0.1)]"
                                                                    onClick={(e) => handleCreateCase(alert.id, e)}
                                                                >
                                                                    <ExternalLink size={16} /> Create Case
                                                                </button>
                                                                <button
                                                                    className="glass-button bg-slate-800 text-slate-300 border border-slate-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-700"
                                                                    onClick={(e) => handleCloseAlert(alert.id, e)}
                                                                >
                                                                    <CheckCircle size={16} className="inline mr-2" />
                                                                    Close Alert
                                                                </button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* NOTES VIEW */}
                                                {activeLogTab === 'notes' && (
                                                    <div className="space-y-4">
                                                        <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-800">
                                                            <div className="flex items-center justify-between mb-3">
                                                                <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold">
                                                                    <FileText size={16} />
                                                                    ANALYST NOTES
                                                                </div>
                                                                <button
                                                                    onClick={async () => {
                                                                        setSavingNotes(true);
                                                                        await handleSaveNotes(alert.id, analystNotes[alert.id] || '');
                                                                        setSavingNotes(false);
                                                                        // Update local alert state
                                                                        setAlerts(prev => prev.map(a => 
                                                                            a.id === alert.id 
                                                                                ? { ...a, analyst_notes: analystNotes[alert.id] } 
                                                                                : a
                                                                        ));
                                                                    }}
                                                                    disabled={savingNotes}
                                                                    className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 rounded-lg text-sm hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
                                                                >
                                                                    <Save size={14} />
                                                                    {savingNotes ? 'Saving...' : 'Save Notes'}
                                                                </button>
                                                            </div>
                                                            <textarea
                                                                value={analystNotes[alert.id] || ''}
                                                                onChange={(e) => setAnalystNotes(prev => ({
                                                                    ...prev,
                                                                    [alert.id]: e.target.value
                                                                }))}
                                                                placeholder="Add investigation notes, findings, or comments here..."
                                                                className="w-full h-48 bg-slate-950 border border-slate-700 rounded-lg p-3 text-slate-300 text-sm placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 resize-none"
                                                            />
                                                            <div className="mt-2 text-xs text-slate-500">
                                                                Notes are saved per alert and visible to all analysts.
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* LOG VIEWS */}
                                                {(activeLogTab !== 'summary' && activeLogTab !== 'notes') && (
                                                    <div className="space-y-4">
                                                        {logs[activeLogTab] === null ? (
                                                            <div className="text-center py-8 text-cyan-500 animate-pulse">
                                                                <RefreshCcw className="animate-spin inline mr-2" /> Fetching detailed forensic logs...
                                                            </div>
                                                        ) : logs[activeLogTab].length === 0 ? (
                                                            <div className="text-center py-8 text-slate-500 italic">
                                                                No {activeLogTab} logs found for this timeframe.
                                                            </div>
                                                        ) : (
                                                            <div className="overflow-x-auto rounded-lg border border-slate-800">
                                                                <table className="w-full text-sm text-left text-slate-400">
                                                                    <thead className="text-xs text-slate-500 uppercase bg-slate-900">
                                                                        <tr>
                                                                            <th className="px-4 py-3">Timestamp</th>
                                                                            {activeLogTab === 'process' && <><th className="px-4 py-3">Process</th><th className="px-4 py-3">Command / Parent</th></>}
                                                                            {activeLogTab === 'network' && <><th className="px-4 py-3">Source</th><th className="px-4 py-3">Destination</th><th className="px-4 py-3">Protocol</th></>}
                                                                            {activeLogTab === 'file' && <><th className="px-4 py-3">Action</th><th className="px-4 py-3">File Path</th><th className="px-4 py-3">Process</th></>}
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody className="divide-y divide-slate-800">
                                                                        {logs[activeLogTab].map((log, idx) => (
                                                                            <tr key={idx} className="bg-slate-950/50 hover:bg-slate-900 transition-colors">
                                                                                <td className="px-4 py-3 font-mono text-xs text-slate-500">{new Date(log.timestamp).toLocaleString()}</td>

                                                                                {/* Process Columns */}
                                                                                {activeLogTab === 'process' && (
                                                                                    <>
                                                                                        <td className="px-4 py-3 font-semibold text-white">{log.process_name}</td>
                                                                                        <td className="px-4 py-3 font-mono text-xs text-slate-400">
                                                                                            <div className="text-cyan-500 mb-1">{log.parent_process}</div>
                                                                                            {log.command_line}
                                                                                        </td>
                                                                                    </>
                                                                                )}

                                                                                {/* Network Columns */}
                                                                                {activeLogTab === 'network' && (
                                                                                    <>
                                                                                        <td className="px-4 py-3 text-white">{log.source_ip}</td>
                                                                                        <td className="px-4 py-3 text-cyan-400">{log.dest_ip}:{log.dest_port}</td>
                                                                                        <td className="px-4 py-3 uppercase text-xs font-bold">{log.protocol}</td>
                                                                                    </>
                                                                                )}

                                                                                {/* File Columns */}
                                                                                {activeLogTab === 'file' && (
                                                                                    <>
                                                                                        <td className="px-4 py-3 font-bold text-white">{log.action}</td>
                                                                                        <td className="px-4 py-3 font-mono text-xs text-slate-400">{log.file_path}</td>
                                                                                        <td className="px-4 py-3 text-cyan-400">{log.process_name}</td>
                                                                                    </>
                                                                                )}
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </motion.div>
                        ))
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default AnalystDashboard;
