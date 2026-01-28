import React, { useState, useEffect } from 'react';
import { ShieldCheck, AlertCircle, CheckCircle, XCircle, Search, Brain, FileText, RefreshCcw, ChevronDown, Award } from 'lucide-react';
import api from '../utils/api';

const TransparencyDashboard = () => {
    const [alerts, setAlerts] = useState([]);
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [proofData, setProofData] = useState(null);
    const [summary, setSummary] = useState(null);
    const [loading, setLoading] = useState(true);
    const [expandedSections, setExpandedSections] = useState({});

    // Fetch alerts and summary
    useEffect(() => {
        const fetchData = async () => {
            try {
                const [alertsRes, summaryRes] = await Promise.all([
                    api.get('/alerts'),
                    api.get('/api/transparency/summary')
                ]);

                const alertsList = alertsRes.data?.alerts || [];
                setAlerts(alertsList.filter(a => a.ai_verdict && a.ai_verdict !== 'ERROR'));
                setSummary(summaryRes.data || {});
                setLoading(false);
            } catch (e) {
                console.error('Failed to fetch transparency data:', e);
                setAlerts([]);
                setSummary({});
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, []);

    // Fetch proof for selected alert
    const handleAlertSelect = async (alertId) => {
        setSelectedAlert(alertId);
        setProofData(null);
        try {
            const res = await api.get(`/api/transparency/proof/${alertId}`);
            setProofData(res.data);
        } catch (e) {
            console.error('Failed to fetch proof:', e);
        }
    };

    const toggleSection = (section) => {
        setExpandedSections(prev => ({
            ...prev,
            [section]: !prev[section]
        }));
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-screen">
                <RefreshCcw className="animate-spin text-cyan-500" size={40} />
                <span className="ml-3 text-cyan-500 font-mono">Loading AI Transparency Dashboard...</span>
            </div>
        );
    }

    const getVerificationColor = (score) => {
        if (score >= 80) return 'text-green-500 border-green-500 bg-green-500/10';
        if (score >= 50) return 'text-yellow-500 border-yellow-500 bg-yellow-500/10';
        return 'text-red-500 border-red-500 bg-red-500/10';
    };

    const getVerdictColor = (verdict) => {
        if (verdict?.includes('VERIFIED')) return 'text-green-500';
        if (verdict?.includes('WARNING')) return 'text-yellow-500';
        return 'text-red-500';
    };

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6 h-screen overflow-y-auto">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
                        <ShieldCheck className="text-cyan-500" size={36} />
                        AI Transparency & Proof Dashboard
                    </h1>
                    <p className="text-slate-400 text-sm">
                        Verify that the AI is performing legitimate analysis and not hallucinating
                    </p>
                </div>
                <div className="flex items-center gap-2 text-cyan-500">
                    <Brain size={20} />
                    <span className="font-mono text-sm">{alerts.length} analyzed alerts</span>
                </div>
            </div>

            {/* Summary Stats */}
            {summary && (
                <div className="grid grid-cols-4 gap-6">
                    <div className="glass-panel p-6 border-t-4 border-green-500">
                        <div className="flex justify-between items-start mb-2">
                            <div>
                                <p className="text-slate-400 text-xs uppercase tracking-wider">Deep Analysis</p>
                                <h3 className="text-2xl font-bold text-white mt-1">
                                    {summary.total_deep_analysis || 0}
                                </h3>
                                <p className="text-xs text-green-500 mt-1">
                                    {summary.total_analyzed > 0
                                        ? ((summary.total_deep_analysis / summary.total_analyzed) * 100).toFixed(0)
                                        : 0}% of total
                                </p>
                            </div>
                            <CheckCircle className="text-green-500" />
                        </div>
                    </div>

                    <div className="glass-panel p-6 border-t-4 border-yellow-500">
                        <div className="flex justify-between items-start mb-2">
                            <div>
                                <p className="text-slate-400 text-xs uppercase tracking-wider">Shallow Analysis</p>
                                <h3 className="text-2xl font-bold text-white mt-1">
                                    {summary.total_shallow_analysis || 0}
                                </h3>
                                <p className="text-xs text-yellow-500 mt-1">
                                    {summary.total_analyzed > 0
                                        ? ((summary.total_shallow_analysis / summary.total_analyzed) * 100).toFixed(0)
                                        : 0}% of total
                                </p>
                            </div>
                            <AlertCircle className="text-yellow-500" />
                        </div>
                    </div>

                    <div className="glass-panel p-6 border-t-4 border-cyan-500">
                        <div className="flex justify-between items-start mb-2">
                            <div>
                                <p className="text-slate-400 text-xs uppercase tracking-wider">Avg Evidence Items</p>
                                <h3 className="text-2xl font-bold text-white mt-1">
                                    {(summary.avg_evidence_depth || 0).toFixed(1)}
                                </h3>
                            </div>
                            <FileText className="text-cyan-500" />
                        </div>
                    </div>

                    <div className="glass-panel p-6 border-t-4 border-purple-500">
                        <div className="flex justify-between items-start mb-2">
                            <div>
                                <p className="text-slate-400 text-xs uppercase tracking-wider">Verdict Distribution</p>
                                <div className="text-sm mt-2 space-y-1">
                                    {summary.verdict_distribution && Object.entries(summary.verdict_distribution).map(([verdict, count]) => (
                                        <div key={verdict} className="flex justify-between">
                                            <span className="text-slate-400">{verdict}:</span>
                                            <span className="text-white font-semibold">{count}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Main Content */}
            <div className="grid grid-cols-12 gap-6">
                {/* Alert Selection */}
                <div className="col-span-4 glass-panel p-6">
                    <h3 className="text-lg font-semibold text-slate-300 mb-4">Select Alert to Verify</h3>
                    <div className="space-y-2 max-h-96 overflow-y-auto custom-scrollbar">
                        {alerts.length === 0 ? (
                            <div className="text-slate-500 text-sm italic">No analyzed alerts available</div>
                        ) : (
                            alerts.map(alert => (
                                <button
                                    key={alert.id}
                                    onClick={() => handleAlertSelect(alert.id)}
                                    className={`w-full text-left p-3 rounded border transition-all ${selectedAlert === alert.id
                                            ? 'bg-cyan-500/20 border-cyan-500'
                                            : 'bg-slate-900/50 border-slate-700 hover:border-slate-600'
                                        }`}
                                >
                                    <div className="flex items-start justify-between gap-2 mb-2">
                                        <span className="text-white text-sm font-semibold flex-1">
                                            {alert.alert_name}
                                        </span>
                                        <span className={`text-xs px-2 py-1 rounded ${alert.ai_verdict === 'malicious' ? 'bg-red-500/20 text-red-400' :
                                                alert.ai_verdict === 'suspicious' ? 'bg-yellow-500/20 text-yellow-400' :
                                                    'bg-green-500/20 text-green-400'
                                            }`}>
                                            {alert.ai_verdict?.toUpperCase()}
                                        </span>
                                    </div>
                                    <div className="text-slate-500 text-xs font-mono">
                                        ID: {alert.id}
                                    </div>
                                    <div className="text-slate-600 text-xs mt-1">
                                        Evidence: {Array.isArray(alert.ai_evidence) ? alert.ai_evidence.length : 0} items
                                    </div>
                                </button>
                            ))
                        )}
                    </div>
                </div>

                {/* Proof Details */}
                <div className="col-span-8 glass-panel p-6">
                    <h3 className="text-lg font-semibold text-slate-300 mb-4">AI Analysis Verification</h3>

                    {!selectedAlert ? (
                        <div className="text-center py-12 text-slate-500">
                            <ShieldCheck size={48} className="mx-auto mb-3 opacity-50" />
                            <p>Select an alert to view AI transparency proof</p>
                        </div>
                    ) : !proofData ? (
                        <div className="text-center py-12">
                            <RefreshCcw className="animate-spin mx-auto text-cyan-500" size={40} />
                            <p className="text-slate-500 mt-3">Generating proof...</p>
                        </div>
                    ) : (
                        <div className="space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar pr-2">
                            {/* Verification Score */}
                            <div className={`rounded-lg p-6 border-2 ${getVerificationColor(proofData.verification?.verification_score || 0)}`}>
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center gap-3">
                                        <Award size={32} />
                                        <div>
                                            <h4 className="text-lg font-bold">Verification Score</h4>
                                            <p className="text-xs opacity-80">AI analysis authenticity check</p>
                                        </div>
                                    </div>
                                    <div className="text-4xl font-bold">
                                        {(proofData.verification?.verification_score || 0).toFixed(1)}%
                                    </div>
                                </div>
                                <div className="w-full bg-slate-800 h-3 rounded-full overflow-hidden">
                                    <div
                                        className="h-full transition-all duration-500 bg-current"
                                        style={{ width: `${proofData.verification?.verification_score || 0}%` }}
                                    />
                                </div>
                                <div className={`mt-4 text-sm font-bold ${getVerdictColor(proofData.verification?.final_verdict)}`}>
                                    {proofData.verification?.final_verdict}
                                </div>
                            </div>

                            {/* Verification Details */}
                            {proofData.verification && (
                                <div className="bg-slate-900/50 rounded-lg border border-slate-800">
                                    <button
                                        onClick={() => toggleSection('verification')}
                                        className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-800/50 transition-colors"
                                    >
                                        <div className="flex items-center gap-3">
                                            <Search size={18} className="text-cyan-500" />
                                            <span className="text-white font-semibold">Verification Analysis</span>
                                        </div>
                                        <ChevronDown
                                            className={`text-slate-500 transition-transform ${expandedSections['verification'] ? 'rotate-180' : ''
                                                }`}
                                        />
                                    </button>

                                    {expandedSections['verification'] && (
                                        <div className="p-4 pt-0 space-y-3 border-t border-slate-800">
                                            <div>
                                                <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                    Facts Found
                                                </h5>
                                                <div className="space-y-1">
                                                    {proofData.verification.facts_found?.map((fact, idx) => (
                                                        <div key={idx} className="flex items-start gap-2 text-sm">
                                                            <CheckCircle size={14} className="text-green-500 mt-0.5" />
                                                            <span className="text-slate-300">{fact}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>

                                            {proofData.verification.missing_facts?.length > 0 && (
                                                <div>
                                                    <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                        Missing Evidence
                                                    </h5>
                                                    <div className="space-y-1">
                                                        {proofData.verification.missing_facts.map((fact, idx) => (
                                                            <div key={idx} className="flex items-start gap-2 text-sm">
                                                                <XCircle size={14} className="text-red-500 mt-0.5" />
                                                                <span className="text-slate-300">{fact}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

                                            {proofData.verification.rag_usage?.length > 0 && (
                                                <div>
                                                    <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                        RAG Knowledge Utilized
                                                    </h5>
                                                    <div className="space-y-1">
                                                        {proofData.verification.rag_usage.map((source, idx) => (
                                                            <div key={idx} className="flex items-start gap-2 text-sm">
                                                                <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5"></span>
                                                                <span className="text-cyan-300">{source}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Original Alert Data */}
                            <div className="bg-slate-900/50 rounded-lg border border-slate-800">
                                <button
                                    onClick={() => toggleSection('alert')}
                                    className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-800/50 transition-colors"
                                >
                                    <div className="flex items-center gap-3">
                                        <AlertCircle size={18} className="text-orange-500" />
                                        <span className="text-white font-semibold">Original Alert Data</span>
                                    </div>
                                    <ChevronDown
                                        className={`text-slate-500 transition-transform ${expandedSections['alert'] ? 'rotate-180' : ''
                                            }`}
                                    />
                                </button>

                                {expandedSections['alert'] && proofData.alert_data && (
                                    <div className="p-4 pt-0 border-t border-slate-800">
                                        <pre className="text-xs bg-slate-950/50 p-3 rounded overflow-x-auto text-slate-300">
                                            {JSON.stringify(proofData.alert_data, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </div>

                            {/* AI Analysis */}
                            <div className="bg-slate-900/50 rounded-lg border border-slate-800">
                                <button
                                    onClick={() => toggleSection('analysis')}
                                    className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-800/50 transition-colors"
                                >
                                    <div className="flex items-center gap-3">
                                        <Brain size={18} className="text-purple-500" />
                                        <span className="text-white font-semibold">AI Analysis Output</span>
                                    </div>
                                    <ChevronDown
                                        className={`text-slate-500 transition-transform ${expandedSections['analysis'] ? 'rotate-180' : ''
                                            }`}
                                    />
                                </button>

                                {expandedSections['analysis'] && proofData.ai_analysis && (
                                    <div className="p-4 pt-0 space-y-3 border-t border-slate-800">
                                        <div>
                                            <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                Verdict & Confidence
                                            </h5>
                                            <div className="flex gap-4 text-sm">
                                                <span className="text-white">
                                                    <span className="text-slate-400">Verdict:</span> {proofData.ai_analysis.verdict}
                                                </span>
                                                <span className="text-white">
                                                    <span className="text-slate-400">Confidence:</span> {(proofData.ai_analysis.confidence * 100).toFixed(0)}%
                                                </span>
                                            </div>
                                        </div>

                                        <div>
                                            <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                AI Reasoning
                                            </h5>
                                            <p className="text-sm text-slate-300 italic">
                                                "{proofData.ai_analysis.reasoning}"
                                            </p>
                                        </div>

                                        {proofData.ai_analysis.evidence && proofData.ai_analysis.evidence.length > 0 && (
                                            <div>
                                                <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                    AI Evidence Chain
                                                </h5>
                                                <ul className="space-y-1">
                                                    {proofData.ai_analysis.evidence.map((ev, idx) => (
                                                        <li key={idx} className="text-sm text-slate-300 flex gap-2">
                                                            <span className="text-cyan-500">•</span>
                                                            {ev}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        )}

                                        {proofData.ai_analysis.chain_of_thought && proofData.ai_analysis.chain_of_thought.length > 0 && (
                                            <div>
                                                <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                    Chain of Thought
                                                </h5>
                                                <div className="space-y-2">
                                                    {proofData.ai_analysis.chain_of_thought.map((step, idx) => (
                                                        <div key={idx} className="bg-slate-950/50 rounded p-2 text-xs">
                                                            <div className="text-purple-400 font-semibold mb-1">
                                                                Step {idx + 1}: {step.step}
                                                            </div>
                                                            <div className="text-slate-400">{step.reasoning}</div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>

                            {/* Correlated Logs */}
                            {proofData.correlated_logs && Object.keys(proofData.correlated_logs).length > 0 && (
                                <div className="bg-slate-900/50 rounded-lg border border-slate-800">
                                    <button
                                        onClick={() => toggleSection('logs')}
                                        className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-800/50 transition-colors"
                                    >
                                        <div className="flex items-center gap-3">
                                            <FileText size={18} className="text-blue-500" />
                                            <span className="text-white font-semibold">Correlated Logs</span>
                                            <span className="text-slate-500 text-sm">
                                                {Object.values(proofData.correlated_logs).reduce((sum, logs) => sum + logs.length, 0)} total
                                            </span>
                                        </div>
                                        <ChevronDown
                                            className={`text-slate-500 transition-transform ${expandedSections['logs'] ? 'rotate-180' : ''
                                                }`}
                                        />
                                    </button>

                                    {expandedSections['logs'] && (
                                        <div className="p-4 pt-0 border-t border-slate-800">
                                            {Object.entries(proofData.correlated_logs).map(([logType, logs]) => (
                                                logs.length > 0 && (
                                                    <div key={logType} className="mb-3">
                                                        <h5 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                                                            {logType} ({logs.length})
                                                        </h5>
                                                        <div className="text-xs text-slate-500">
                                                            {logs.length} log entries available
                                                        </div>
                                                    </div>
                                                )
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default TransparencyDashboard;
