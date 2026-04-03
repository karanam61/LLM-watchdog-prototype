import { useState, useEffect } from 'react';
import { ShieldAlert, Search, CheckCircle, ExternalLink, RefreshCcw, AlertTriangle, ChevronDown, FileText, Save, ChevronLeft, ChevronRight, ThumbsUp, ThumbsDown, MessageSquare } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../utils/api';

const AnalystDashboard = () => {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('main');
    const [expandedId, setExpandedId] = useState(null);
    const [activeLogTab, setActiveLogTab] = useState('summary');
    const [logs, setLogs] = useState({ process: null, network: null, file: null, windows: null });
    const [loadingLogs, setLoadingLogs] = useState(false);
    const [analystNotes, setAnalystNotes] = useState({});
    const [savingNotes, setSavingNotes] = useState(false);
    const [feedbackState, setFeedbackState] = useState({});
    const [feedbackStats, setFeedbackStats] = useState(null);

    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [hasNext, setHasNext] = useState(false);
    const [hasPrev, setHasPrev] = useState(false);
    const perPage = 20;

    useEffect(() => {
        let retryCount = 0;
        let timeoutId;

        const fetchAlerts = async () => {
            try {
                const res = await api.get(`/alerts?page=${page}&per_page=${perPage}`);
                const data = res.data;
                if (data.alerts) {
                    setAlerts(data.alerts);
                    setTotalPages(data.total_pages || 1);
                    setHasNext(data.has_next || false);
                    setHasPrev(data.has_prev || false);
                    retryCount = 0;
                }
            } catch (e) {
                console.error("Failed to fetch alerts", e);
                retryCount++;
                const delay = Math.min(2000 * Math.pow(2, retryCount), 30000);
                console.warn(`Retrying in ${delay}ms...`);
            } finally {
                setLoading(false);
            }
        };

        fetchAlerts();
        const interval = setInterval(fetchAlerts, 5000);
        return () => {
            clearInterval(interval);
            clearTimeout(timeoutId);
        };
    }, [page]);

    const handleCloseAlert = async (id, e) => {
        if (e) e.stopPropagation();
        try {
            await api.patch(`/api/alerts/${id}`, { status: 'closed' });
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

    const handleReanalyze = async (id, e) => {
        if (e) e.stopPropagation();
        try {
            await api.post(`/api/alerts/${id}/reanalyze`);
            setAlerts(prev => prev.map(a => a.id === id ? { ...a, ai_verdict: null, ai_reasoning: null, ai_evidence: null, status: 'open' } : a));
        } catch (error) {
            console.error("Failed to reanalyze:", error);
            alert("Failed to reanalyze: " + (error.response?.data?.error || error.message));
        }
    };

    const handleSaveNotes = async (id, notes) => {
        try {
            await api.patch(`/api/alerts/${id}`, { analyst_notes: notes });
        } catch (error) {
            console.error("Failed to save notes:", error);
        }
    };

    const handleSubmitFeedback = async (alertId, verdict, notes) => {
        setFeedbackState(prev => ({
            ...prev,
            [alertId]: { ...prev[alertId], submitting: true }
        }));

        try {
            const res = await api.post(`/api/alerts/${alertId}/feedback`, {
                analyst_verdict: verdict,
                analyst_notes: notes
            });

            setAlerts(prev => prev.map(a =>
                a.id === alertId
                    ? { ...a, analyst_verdict: verdict, analyst_notes: notes }
                    : a
            ));

            fetchFeedbackStats();
            alert(`Feedback submitted! AI was ${res.data.ai_was_correct ? 'CORRECT ✓' : 'INCORRECT ✗'}`);
        } catch (error) {
            console.error("Failed to submit feedback:", error);
            alert("Failed to submit feedback: " + (error.response?.data?.error || error.message));
        } finally {
            setFeedbackState(prev => ({
                ...prev,
                [alertId]: { ...prev[alertId], submitting: false }
            }));
        }
    };

    const fetchFeedbackStats = async () => {
        try {
            const res = await api.get('/api/feedback/stats');
            setFeedbackStats(res.data);
        } catch (error) {
            console.error("Failed to fetch feedback stats:", error);
        }
    };

    useEffect(() => {
        fetchFeedbackStats();
    }, []);

    const toggleExpand = (id) => {
        if (expandedId === id) {
            setExpandedId(null);
        } else {
            setExpandedId(id);
            setActiveLogTab('summary');
            setLogs({ process: null, network: null, file: null, windows: null });

            const alert = alerts.find(a => a.id === id);
            if (alert) {
                ['process', 'network', 'file', 'windows'].forEach(type => {
                    fetchInvestigationLogs(alert, type);
                });
            }
        }
    };

    const fetchInvestigationLogs = async (alert, type) => {
        setLoadingLogs(true);
        try {
            let url = `/api/logs?type=${type}&alert_id=${alert.id}`;
            const res = await api.get(url);
            const data = Array.isArray(res.data) ? res.data : [];
            setLogs(prev => ({ ...prev, [type]: data }));
        } catch (e) {
            console.error("Failed to fetch logs", e);
            setLogs(prev => ({ ...prev, [type]: [] }));
        } finally {
            setLoadingLogs(false);
        }
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL_HIGH': return { border: 'border-l-threat-critical', badge: 's-badge-critical', strip: 'severity-critical' };
            case 'HIGH': return { border: 'border-l-threat-high', badge: 's-badge-high', strip: 'severity-high' };
            case 'MEDIUM': return { border: 'border-l-threat-medium', badge: 's-badge-medium', strip: 'severity-medium' };
            case 'LOW': return { border: 'border-l-threat-low', badge: 's-badge-low', strip: 'severity-low' };
            default: return { border: 'border-l-steel-500', badge: 's-badge-info', strip: '' };
        }
    };

    const getVerdictStyle = (verdict) => {
        switch (verdict) {
            case 'MALICIOUS': return 'border-threat-critical/40 text-threat-critical bg-threat-critical/5';
            case 'BENIGN': return 'border-status-live/40 text-status-live bg-status-live/5';
            case 'ERROR': return 'border-cyber-500/40 text-cyber-400 bg-cyber-500/5';
            case 'SKIPPED': return 'border-sentinel-600 text-sentinel-400 bg-sentinel-800';
            default: return 'border-status-warn/40 text-status-warn bg-status-warn/5';
        }
    };

    const filteredAlerts = alerts.filter(a => {
        if (activeTab === 'main') return (a.status === 'open' || a.status === 'analyzed') && a.severity_class !== 'LOW';
        if (activeTab === 'investigation') return a.status === 'investigating';
        if (activeTab === 'history') return a.status === 'closed';
        return true;
    });

    return (
        <div className="p-6 h-screen flex flex-col max-w-[1400px] mx-auto">

            {/* Header */}
            <div className="flex justify-between items-end mb-6">
                <div>
                    <h2 className="text-2xl font-bold text-sentinel-50 tracking-tight mb-1">Alert Triage</h2>
                    <div className="flex gap-4 text-xs text-sentinel-400">
                        <span className="flex items-center gap-1.5"><span className="s-dot-live animate-pulse-slow" /> Systems Online</span>
                        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyber-500" /> AI Engine Active</span>
                        <span className="tabular-nums">{filteredAlerts.length} alerts</span>
                    </div>
                </div>

                {/* Tab Bar — UX: nav-state-active, primary-action */}
                <div className="flex bg-sentinel-900 p-1 rounded-lg border border-sentinel-700">
                    {['main', 'investigation', 'history'].map(tab => (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            className={`px-5 py-2 rounded-md text-sm font-medium transition-all duration-200 capitalize ${activeTab === tab
                                ? 'bg-cyber-500/15 text-cyber-400 shadow-sm'
                                : 'text-sentinel-400 hover:text-sentinel-200'
                            }`}
                        >
                            {tab === 'main' ? 'Active' : tab}
                        </button>
                    ))}
                </div>
            </div>

            {/* Loading State — UX: progressive-loading, skeleton */}
            {loading && (
                <div className="flex-1 flex items-center justify-center" role="status" aria-live="polite">
                    <div className="flex flex-col items-center gap-3">
                        <RefreshCcw size={28} className="animate-spin text-cyber-500" />
                        <span className="text-sm font-mono text-sentinel-300 tracking-wider">ESTABLISHING UPLINK...</span>
                    </div>
                </div>
            )}

            {/* Alert Feed */}
            <div className="flex-1 space-y-2 overflow-y-auto pb-20 s-scroll pr-1 min-h-0">
                <AnimatePresence>
                    {filteredAlerts.length === 0 && !loading ? (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="p-10 text-center text-sentinel-500 border border-dashed border-sentinel-700 rounded-xl"
                        >
                            <ShieldAlert size={32} className="mx-auto mb-3 opacity-40" />
                            <p className="text-sm">No alerts in this channel.</p>
                        </motion.div>
                    ) : (
                        filteredAlerts.map((alert, index) => (
                            <motion.div
                                key={alert.id}
                                initial={{ opacity: 0, y: 8 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, height: 0 }}
                                transition={{ duration: 0.2, delay: index * 0.03 }}
                                className={`s-panel-interactive overflow-hidden severity-strip ${getSeverityColor(alert.severity_class).strip} border-l-[3px]`}
                                style={{ borderLeftColor: `var(--severity-color)` }}
                            >
                                {/* Alert Header Row — UX: touch-target-size ≥44px, data-dense */}
                                <div
                                    className="px-4 py-3 flex items-center gap-4 cursor-pointer hover:bg-sentinel-800/30 transition-colors min-h-[52px]"
                                    onClick={() => toggleExpand(alert.id)}
                                    role="button"
                                    aria-expanded={expandedId === alert.id}
                                    aria-label={`${alert.alert_name} — ${alert.severity_class || 'Unknown'} severity`}
                                    tabIndex={0}
                                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleExpand(alert.id))}
                                >
                                    {/* Severity Badge */}
                                    <div className={getSeverityColor(alert.severity_class).badge}>
                                        {alert.severity_class?.replace('_', ' ') || 'UNKNOWN'}
                                    </div>

                                    {/* Main Info Grid */}
                                    <div className="flex-1 grid grid-cols-12 gap-4 items-center">
                                        <div className="col-span-4 min-w-0">
                                            <div className="font-semibold text-sm text-sentinel-50 truncate">
                                                {alert.alert_name}
                                            </div>
                                            <div className="text-2xs text-sentinel-400 font-mono mt-0.5 truncate">
                                                {alert.mitre_technique || 'NO-MITRE'} · {new Date(alert.created_at).toLocaleTimeString()}
                                            </div>
                                        </div>

                                        <div className="col-span-3 text-xs text-sentinel-300 flex items-center gap-1.5 truncate">
                                            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-600 flex-shrink-0" />
                                            {alert.source_ip || 'N/A'}
                                        </div>

                                        <div className="col-span-2 text-xs text-sentinel-400 truncate">
                                            {alert.hostname || 'N/A'}
                                        </div>

                                        {/* AI Verdict Pill */}
                                        <div className="col-span-3 flex justify-end">
                                            {alert.ai_verdict ? (
                                                <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-bold tracking-wide ${getVerdictStyle(alert.ai_verdict)}`}>
                                                    <ShieldAlert size={13} />
                                                    <span>{alert.ai_verdict}</span>
                                                    <span className="opacity-50 font-mono text-2xs">{(alert.ai_confidence * 100).toFixed(0)}%</span>
                                                </div>
                                            ) : (
                                                <div className="flex items-center gap-1.5 text-sentinel-500 text-xs animate-pulse">
                                                    <RefreshCcw size={12} className="animate-spin" /> Analyzing...
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    <ChevronDown
                                        size={16}
                                        className={`text-sentinel-500 transition-transform duration-200 flex-shrink-0 ${expandedId === alert.id ? 'rotate-180' : ''}`}
                                    />
                                </div>

                                {/* Expanded Details */}
                                <AnimatePresence>
                                    {expandedId === alert.id && (
                                        <motion.div
                                            initial={{ height: 0, opacity: 0 }}
                                            animate={{ height: "auto", opacity: 1 }}
                                            exit={{ height: 0, opacity: 0 }}
                                            transition={{ duration: 0.25, ease: [0.25, 0.1, 0.25, 1] }}
                                            className="bg-sentinel-950/60 border-t border-sentinel-700/50"
                                        >
                                            {/* Investigation Tabs — UX: nav-label-icon */}
                                            <div className="flex border-b border-sentinel-700/50 px-5 pt-3 gap-1 overflow-x-auto">
                                                {['summary', 'feedback', 'process', 'network', 'file', 'windows', 'notes'].map(tab => (
                                                    <button
                                                        key={tab}
                                                        onClick={() => {
                                                            setActiveLogTab(tab);
                                                            if (tab === 'notes' && !analystNotes[alert.id]) {
                                                                setAnalystNotes(prev => ({
                                                                    ...prev,
                                                                    [alert.id]: alert.analyst_notes || ''
                                                                }));
                                                            }
                                                        }}
                                                        className={`pb-2.5 px-3 text-xs font-medium border-b-2 transition-colors capitalize flex items-center gap-1.5 whitespace-nowrap ${activeLogTab === tab
                                                            ? 'border-cyber-500 text-cyber-400'
                                                            : 'border-transparent text-sentinel-500 hover:text-sentinel-300'}`}
                                                    >
                                                        {tab === 'summary' ? 'Analysis' :
                                                         tab === 'feedback' ? <><MessageSquare size={12} /> Feedback</> :
                                                         tab === 'notes' ? <><FileText size={12} /> Notes</> :
                                                         tab === 'windows' ? 'Win Events' :
                                                         tab}
                                                    </button>
                                                ))}
                                            </div>

                                            <div className="p-5">
                                                {/* SUMMARY VIEW */}
                                                {activeLogTab === 'summary' && (
                                                    <div className="grid grid-cols-2 gap-6">
                                                        <div className="space-y-4">
                                                            <div>
                                                                <h4 className="s-section-label">Description</h4>
                                                                <p className="text-sm text-sentinel-200 leading-relaxed">{alert.description}</p>
                                                            </div>

                                                            {alert.ai_evidence && (
                                                                <div className="bg-sentinel-900/60 rounded-lg p-4 border border-sentinel-700/50">
                                                                    <div className="flex items-center gap-2 mb-2.5 text-cyber-400 text-xs font-semibold uppercase tracking-wider">
                                                                        <Search size={14} />
                                                                        Evidence Chain
                                                                    </div>
                                                                    <ul className="space-y-1.5">
                                                                        {Array.isArray(alert.ai_evidence) && alert.ai_evidence.map((ev, i) => (
                                                                            <li key={i} className="text-xs text-sentinel-300 flex gap-2 leading-relaxed">
                                                                                <span className="text-cyber-500/60 mt-0.5">›</span>
                                                                                {ev}
                                                                            </li>
                                                                        ))}
                                                                    </ul>
                                                                </div>
                                                            )}
                                                        </div>

                                                        <div className="space-y-4">
                                                            <div>
                                                                <h4 className="s-section-label">AI Reasoning</h4>
                                                                <div className="text-sm text-sentinel-300 italic pl-3 border-l-2 border-sentinel-700">
                                                                    "{alert.ai_reasoning || 'Pending analysis...'}"
                                                                </div>
                                                            </div>

                                                            {alert.ai_confidence && (
                                                                <div className="flex gap-3">
                                                                    <div className="flex-1 bg-sentinel-900/60 rounded-lg p-3 border border-sentinel-700/50">
                                                                        <div className="s-section-label mb-1">Confidence</div>
                                                                        <div className="flex items-center gap-3">
                                                                            <span className={`text-xl font-bold tabular-nums ${
                                                                                alert.ai_confidence >= 0.8 ? 'text-status-live' :
                                                                                alert.ai_confidence >= 0.5 ? 'text-status-warn' : 'text-threat-critical'
                                                                            }`}>
                                                                                {(alert.ai_confidence * 100).toFixed(0)}%
                                                                            </span>
                                                                            <div className="flex-1 bg-sentinel-800 rounded-full h-1.5">
                                                                                <div className={`h-1.5 rounded-full transition-all duration-500 ${
                                                                                    alert.ai_confidence >= 0.8 ? 'bg-status-live' :
                                                                                    alert.ai_confidence >= 0.5 ? 'bg-status-warn' : 'bg-threat-critical'
                                                                                }`} style={{ width: `${alert.ai_confidence * 100}%` }} />
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                    {(() => {
                                                                        const noveltyEvidence = Array.isArray(alert.ai_evidence) && alert.ai_evidence.find(e => typeof e === 'string' && e.includes('Novelty Assessment:'));
                                                                        const level = noveltyEvidence ? noveltyEvidence.split('Novelty Assessment:')[1]?.trim().split(' ')[0] : null;
                                                                        return level ? (
                                                                            <div className={`flex-1 rounded-lg p-3 border ${
                                                                                level === 'NOVEL' ? 'bg-cyber-500/5 border-cyber-500/20' :
                                                                                level === 'PARTIAL' ? 'bg-status-warn/5 border-status-warn/20' :
                                                                                'bg-status-live/5 border-status-live/20'
                                                                            }`}>
                                                                                <div className="s-section-label mb-1">Knowledge</div>
                                                                                <span className={`text-sm font-bold ${
                                                                                    level === 'NOVEL' ? 'text-cyber-400' :
                                                                                    level === 'PARTIAL' ? 'text-status-warn' : 'text-status-live'
                                                                                }`}>{level}</span>
                                                                                <p className="text-2xs text-sentinel-500 mt-0.5">
                                                                                    {level === 'NOVEL' ? 'Unseen — human review required' :
                                                                                     level === 'PARTIAL' ? 'Partially matches known patterns' :
                                                                                     'Matches known patterns'}
                                                                                </p>
                                                                            </div>
                                                                        ) : null;
                                                                    })()}
                                                                </div>
                                                            )}

                                                            {alert.ai_recommendation && (
                                                                <div className="bg-sentinel-900/60 rounded-lg p-3 border border-status-warn/15">
                                                                    <div className="flex items-center gap-1.5 mb-1.5">
                                                                        <AlertTriangle size={13} className="text-status-warn" />
                                                                        <span className="text-2xs font-semibold text-status-warn uppercase tracking-wider">Recommended Actions</span>
                                                                    </div>
                                                                    <p className="text-xs text-sentinel-300 leading-relaxed">{alert.ai_recommendation}</p>
                                                                </div>
                                                            )}

                                                            {/* Action Buttons — UX: primary-action, destructive-emphasis */}
                                                            <div className="flex items-center gap-2 pt-2">
                                                                <button
                                                                    className="s-btn-primary text-xs"
                                                                    onClick={(e) => handleCreateCase(alert.id, e)}
                                                                >
                                                                    <ExternalLink size={14} /> Escalate
                                                                </button>
                                                                <button
                                                                    className="s-btn-ghost text-xs"
                                                                    onClick={(e) => handleCloseAlert(alert.id, e)}
                                                                >
                                                                    <CheckCircle size={14} />
                                                                    Close
                                                                </button>
                                                                {alert.ai_verdict && (
                                                                    <button
                                                                        className="s-btn text-xs bg-cyber-500/10 text-cyber-400 border border-cyber-500/30 hover:bg-cyber-500/20"
                                                                        onClick={(e) => handleReanalyze(alert.id, e)}
                                                                    >
                                                                        <RefreshCcw size={14} /> Re-analyze
                                                                    </button>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* FEEDBACK VIEW */}
                                                {activeLogTab === 'feedback' && (
                                                    <div className="space-y-4 max-w-2xl">
                                                        <div className="bg-sentinel-900/60 rounded-lg p-4 border border-sentinel-700/50">
                                                            <div className="flex items-center gap-2 text-cyber-400 text-xs font-semibold uppercase tracking-wider mb-4">
                                                                <MessageSquare size={14} />
                                                                Analyst Feedback on AI Verdict
                                                            </div>

                                                            {alert.analyst_verdict && (
                                                                <div className="mb-4 p-2.5 bg-status-live/5 border border-status-live/20 rounded-lg">
                                                                    <span className="text-status-live text-xs">
                                                                        ✓ Feedback submitted: <strong>{alert.analyst_verdict.toUpperCase()}</strong>
                                                                    </span>
                                                                </div>
                                                            )}

                                                            <div className="mb-4 p-2.5 bg-sentinel-800/50 rounded-lg">
                                                                <span className="text-sentinel-400 text-xs">AI Verdict: </span>
                                                                <span className={`font-bold text-xs ${
                                                                    alert.ai_verdict === 'MALICIOUS' ? 'text-threat-critical' :
                                                                    alert.ai_verdict === 'BENIGN' ? 'text-status-live' : 'text-status-warn'
                                                                }`}>
                                                                    {alert.ai_verdict || 'Pending'}
                                                                </span>
                                                                <span className="text-sentinel-500 text-xs ml-2 tabular-nums">
                                                                    ({((alert.ai_confidence || 0) * 100).toFixed(0)}% confidence)
                                                                </span>
                                                            </div>

                                                            {/* Verdict Selection — UX: touch-target-size */}
                                                            <div className="mb-4">
                                                                <label className="text-xs text-sentinel-400 mb-2 block font-medium">Your Verdict:</label>
                                                                <div className="flex gap-2">
                                                                    {['benign', 'suspicious', 'malicious'].map(verdict => (
                                                                        <button
                                                                            key={verdict}
                                                                            onClick={() => setFeedbackState(prev => ({
                                                                                ...prev,
                                                                                [alert.id]: { ...prev[alert.id], verdict }
                                                                            }))}
                                                                            className={`px-4 py-2.5 rounded-lg text-xs font-bold border transition-all uppercase tracking-wide ${
                                                                                feedbackState[alert.id]?.verdict === verdict
                                                                                    ? verdict === 'benign' ? 'bg-status-live/15 border-status-live text-status-live' :
                                                                                      verdict === 'malicious' ? 'bg-threat-critical/15 border-threat-critical text-threat-critical' :
                                                                                      'bg-status-warn/15 border-status-warn text-status-warn'
                                                                                    : 'bg-sentinel-800 border-sentinel-700 text-sentinel-400 hover:border-sentinel-600'
                                                                            }`}
                                                                        >
                                                                            {verdict === 'benign' && <ThumbsUp size={13} className="inline mr-1.5" />}
                                                                            {verdict === 'malicious' && <ThumbsDown size={13} className="inline mr-1.5" />}
                                                                            {verdict}
                                                                        </button>
                                                                    ))}
                                                                </div>
                                                            </div>

                                                            <div className="mb-4">
                                                                <label className="text-xs text-sentinel-400 mb-2 block font-medium">Why? (Optional)</label>
                                                                <textarea
                                                                    value={feedbackState[alert.id]?.notes || ''}
                                                                    onChange={(e) => setFeedbackState(prev => ({
                                                                        ...prev,
                                                                        [alert.id]: { ...prev[alert.id], notes: e.target.value }
                                                                    }))}
                                                                    placeholder="e.g., 'Scheduled IT maintenance' or 'Confirmed credential theft'"
                                                                    className="s-input h-20 resize-none"
                                                                />
                                                            </div>

                                                            <button
                                                                onClick={() => handleSubmitFeedback(
                                                                    alert.id,
                                                                    feedbackState[alert.id]?.verdict,
                                                                    feedbackState[alert.id]?.notes || ''
                                                                )}
                                                                disabled={!feedbackState[alert.id]?.verdict || feedbackState[alert.id]?.submitting}
                                                                className="s-btn-primary w-full disabled:opacity-40 disabled:cursor-not-allowed"
                                                            >
                                                                {feedbackState[alert.id]?.submitting ? 'Submitting...' : 'Submit Feedback'}
                                                            </button>

                                                            <p className="mt-2 text-2xs text-sentinel-500">
                                                                Your feedback improves AI accuracy for similar future alerts.
                                                            </p>
                                                        </div>

                                                        {feedbackStats && feedbackStats.total_reviewed > 0 && (
                                                            <div className="bg-sentinel-900/60 rounded-lg p-4 border border-sentinel-700/50">
                                                                <div className="text-xs text-sentinel-400 mb-2">AI Accuracy ({feedbackStats.total_reviewed} reviews)</div>
                                                                <div className="flex items-center gap-4">
                                                                    <div className="text-2xl font-bold text-cyber-400 tabular-nums">
                                                                        {feedbackStats.accuracy?.toFixed(1) || 0}%
                                                                    </div>
                                                                    <div className="text-xs text-sentinel-500 tabular-nums">
                                                                        {feedbackStats.correct} correct / {feedbackStats.incorrect} incorrect
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}

                                                {/* NOTES VIEW */}
                                                {activeLogTab === 'notes' && (
                                                    <div className="max-w-2xl">
                                                        <div className="bg-sentinel-900/60 rounded-lg p-4 border border-sentinel-700/50">
                                                            <div className="flex items-center justify-between mb-3">
                                                                <div className="flex items-center gap-2 text-cyber-400 text-xs font-semibold uppercase tracking-wider">
                                                                    <FileText size={14} />
                                                                    Analyst Notes
                                                                </div>
                                                                <button
                                                                    onClick={async () => {
                                                                        setSavingNotes(true);
                                                                        await handleSaveNotes(alert.id, analystNotes[alert.id] || '');
                                                                        setSavingNotes(false);
                                                                        setAlerts(prev => prev.map(a =>
                                                                            a.id === alert.id
                                                                                ? { ...a, analyst_notes: analystNotes[alert.id] }
                                                                                : a
                                                                        ));
                                                                    }}
                                                                    disabled={savingNotes}
                                                                    className="s-btn-primary text-xs py-1.5 disabled:opacity-40"
                                                                >
                                                                    <Save size={13} />
                                                                    {savingNotes ? 'Saving...' : 'Save'}
                                                                </button>
                                                            </div>
                                                            <textarea
                                                                value={analystNotes[alert.id] || ''}
                                                                onChange={(e) => setAnalystNotes(prev => ({
                                                                    ...prev,
                                                                    [alert.id]: e.target.value
                                                                }))}
                                                                placeholder="Add investigation notes, findings, or comments..."
                                                                className="s-input h-40 resize-none"
                                                            />
                                                            <p className="mt-2 text-2xs text-sentinel-500">
                                                                Notes are saved per alert and visible to all analysts.
                                                            </p>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* LOG VIEWS — UX: s-table, data-table */}
                                                {(activeLogTab !== 'summary' && activeLogTab !== 'notes' && activeLogTab !== 'feedback') && (
                                                    <div>
                                                        {logs[activeLogTab] === null ? (
                                                            <div className="text-center py-8 text-cyber-500 animate-pulse text-sm">
                                                                <RefreshCcw className="animate-spin inline mr-2" size={16} /> Fetching forensic logs...
                                                            </div>
                                                        ) : logs[activeLogTab].length === 0 ? (
                                                            <div className="text-center py-8 text-sentinel-500 italic text-sm">
                                                                No {activeLogTab} logs found for this timeframe.
                                                            </div>
                                                        ) : (
                                                            <div className="overflow-x-auto rounded-lg border border-sentinel-700/50">
                                                                <table className="s-table">
                                                                    <thead>
                                                                        <tr>
                                                                            <th>Timestamp</th>
                                                                            {activeLogTab === 'process' && <><th>Process</th><th>Command / Parent</th></>}
                                                                            {activeLogTab === 'network' && <><th>Source</th><th>Destination</th><th>Protocol</th></>}
                                                                            {activeLogTab === 'file' && <><th>Action</th><th>File Path</th><th>Process</th></>}
                                                                            {activeLogTab === 'windows' && <><th>Event ID</th><th>Message</th><th>User</th></>}
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        {logs[activeLogTab].map((log, idx) => (
                                                                            <tr key={idx}>
                                                                                <td className="font-mono text-2xs text-sentinel-500">{new Date(log.timestamp).toLocaleString()}</td>

                                                                                {activeLogTab === 'process' && (
                                                                                    <>
                                                                                        <td className="font-semibold text-sentinel-100">{log.process_name}</td>
                                                                                        <td className="font-mono text-2xs text-sentinel-400">
                                                                                            <div className="text-cyber-400 mb-0.5">{log.parent_process}</div>
                                                                                            {log.command_line}
                                                                                        </td>
                                                                                    </>
                                                                                )}

                                                                                {activeLogTab === 'network' && (
                                                                                    <>
                                                                                        <td className="text-sentinel-100">{log.source_ip}</td>
                                                                                        <td className="text-cyber-400">{log.dest_ip}:{log.dest_port}</td>
                                                                                        <td className="uppercase text-2xs font-bold">{log.protocol}</td>
                                                                                    </>
                                                                                )}

                                                                                {activeLogTab === 'file' && (
                                                                                    <>
                                                                                        <td className="font-bold text-sentinel-100">{log.action}</td>
                                                                                        <td className="font-mono text-2xs text-sentinel-400">{log.file_path}</td>
                                                                                        <td className="text-cyber-400">{log.process_name}</td>
                                                                                    </>
                                                                                )}

                                                                                {activeLogTab === 'windows' && (
                                                                                    <>
                                                                                        <td className="font-bold text-status-warn">{log.event_id}</td>
                                                                                        <td className="font-mono text-2xs text-sentinel-400">
                                                                                            <div className="text-sentinel-200 mb-0.5">{log.event_type}</div>
                                                                                            {log.event_message}
                                                                                        </td>
                                                                                        <td className="text-cyber-400">{log.username}</td>
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

            {/* Pagination — UX: touch-target-size, tabular-nums */}
            {!loading && totalPages > 1 && (
                <div className="mt-3 flex items-center justify-center gap-3 py-3 bg-sentinel-900/50 border border-sentinel-700 rounded-lg">
                    <button
                        onClick={() => setPage(p => Math.max(1, p - 1))}
                        disabled={!hasPrev}
                        className={`s-btn text-xs ${hasPrev ? 'bg-sentinel-800 text-sentinel-200 border border-sentinel-700 hover:border-cyber-500/40' : 'bg-sentinel-900 text-sentinel-600 border border-sentinel-800 cursor-not-allowed'}`}
                    >
                        <ChevronLeft size={14} /> Previous
                    </button>

                    <div className="flex items-center gap-2 px-3 py-1.5 bg-sentinel-800/50 rounded-lg border border-sentinel-700">
                        <span className="text-sentinel-400 text-xs">Page</span>
                        <span className="text-cyber-400 font-bold text-sm tabular-nums">{page}</span>
                        <span className="text-sentinel-400 text-xs">of</span>
                        <span className="text-sentinel-100 font-bold text-sm tabular-nums">{totalPages}</span>
                    </div>

                    <button
                        onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                        disabled={!hasNext}
                        className={`s-btn text-xs ${hasNext ? 'bg-sentinel-800 text-sentinel-200 border border-sentinel-700 hover:border-cyber-500/40' : 'bg-sentinel-900 text-sentinel-600 border border-sentinel-800 cursor-not-allowed'}`}
                    >
                        Next <ChevronRight size={14} />
                    </button>
                </div>
            )}
        </div>
    );
};

export default AnalystDashboard;
