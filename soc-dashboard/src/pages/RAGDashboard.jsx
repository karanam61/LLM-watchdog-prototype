import React, { useState, useEffect } from 'react';
import { Database, Search, BookOpen, TrendingUp, Activity, CheckCircle, XCircle, RefreshCcw, ChevronDown } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import api from '../utils/api';

const COLORS = ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981'];

const RAGDashboard = () => {
    const [alerts, setAlerts] = useState([]);
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [ragData, setRagData] = useState(null);
    const [ragError, setRagError] = useState(null);
    const [ragLoading, setRagLoading] = useState(false);
    const [stats, setStats] = useState(null);
    const [collections, setCollections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expandedSources, setExpandedSources] = useState({});

    // Fetch alerts and RAG stats
    useEffect(() => {
        const fetchData = async () => {
            try {
                const [alertsRes, statsRes, collectionsRes] = await Promise.all([
                    api.get('/alerts'),
                    api.get('/api/rag/stats'),
                    api.get('/api/rag/collections/status')
                ]);

                const alertsList = alertsRes.data?.alerts || [];
                setAlerts(alertsList.filter(a => a.ai_verdict && a.ai_verdict !== 'ERROR'));
                setStats(statsRes.data || {});
                setCollections(collectionsRes.data?.collections || []);
                setLoading(false);
            } catch (e) {
                console.error('Failed to fetch RAG data:', e);
                setAlerts([]);
                setStats({});
                setCollections([]);
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 10000); // Update every 10s
        return () => clearInterval(interval);
    }, []);

    // Fetch RAG usage for selected alert
    const handleAlertSelect = async (alertId) => {
        setSelectedAlert(alertId);
        setRagData(null);
        setRagError(null);
        setRagLoading(true);
        try {
            const res = await api.get(`/api/rag/usage/${alertId}`, { timeout: 30000 });
            setRagData(res.data);
            setRagError(null);
        } catch (e) {
            console.error('Failed to fetch RAG usage:', e);
            setRagError(e.response?.data?.error || e.message || 'Failed to load RAG data');
        } finally {
            setRagLoading(false);
        }
    };

    const toggleSource = (source) => {
        setExpandedSources(prev => ({
            ...prev,
            [source]: !prev[source]
        }));
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-screen">
                <RefreshCcw className="animate-spin text-cyan-500" size={40} />
                <span className="ml-3 text-cyan-500 font-mono">Loading RAG Visualization...</span>
            </div>
        );
    }

    const collectionData = collections.map(c => ({
        name: c.name,
        count: c.document_count || 0
    }));

    const queryData = stats?.query_distribution ?
        Object.entries(stats.query_distribution).map(([name, value]) => ({ name, value })) : [];

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6 h-screen overflow-y-auto">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">RAG System Visualization</h1>
                    <p className="text-slate-400 text-sm">
                        Track how the AI retrieves and uses knowledge from the RAG system
                    </p>
                </div>
                <div className="flex items-center gap-2 text-cyan-500">
                    <Database size={20} />
                    <span className="font-mono text-sm">{stats?.total_queries || 0} queries</span>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-4 gap-6">
                <div className="glass-panel p-6 border-t-4 border-cyan-500">
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Total Queries</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {stats?.total_queries || 0}
                            </h3>
                        </div>
                        <Search className="text-cyan-500" />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-blue-500">
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Avg Query Time</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {(stats?.avg_query_time || 0).toFixed(3)}s
                            </h3>
                        </div>
                        <Activity className="text-blue-500" />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-purple-500">
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Avg Docs Retrieved</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {(stats?.avg_docs_retrieved || 0).toFixed(1)}
                            </h3>
                        </div>
                        <BookOpen className="text-purple-500" />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-green-500">
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Cache Hit Rate</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {((stats?.cache_hit_rate || 0) * 100).toFixed(0)}%
                            </h3>
                        </div>
                        <TrendingUp className="text-green-500" />
                    </div>
                </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-2 gap-6">
                <div className="glass-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-slate-300 mb-6">Knowledge Base Collections</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={collectionData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                            <XAxis dataKey="name" stroke="#64748b" angle={-45} textAnchor="end" height={80} style={{ fontSize: '10px' }} />
                            <YAxis stroke="#64748b" />
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
                            <Bar dataKey="count" fill="#06b6d4" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                <div className="glass-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-slate-300 mb-6">Query Distribution by Source</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={queryData}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                                outerRadius={80}
                                fill="#8884d8"
                                dataKey="value"
                            >
                                {queryData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Collection Status */}
            <div className="glass-panel p-6">
                <h3 className="text-lg font-semibold text-slate-300 mb-4">Knowledge Base Status</h3>
                <div className="grid grid-cols-3 gap-4">
                    {collections.map((coll, idx) => (
                        <div key={idx} className="bg-slate-900/50 rounded-lg p-4 border border-slate-800">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-white font-semibold text-sm">{coll.name}</span>
                                {coll.status === 'active' ? (
                                    <CheckCircle size={16} className="text-green-500" />
                                ) : (
                                    <XCircle size={16} className="text-red-500" />
                                )}
                            </div>
                            <div className="text-slate-400 text-xs">
                                {coll.document_count !== undefined ? (
                                    <span>{coll.document_count} documents</span>
                                ) : (
                                    <span className="text-red-400">{coll.error}</span>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Alert-Specific RAG Usage */}
            <div className="grid grid-cols-12 gap-6">
                {/* Alert Selection */}
                <div className="col-span-4 glass-panel p-6">
                    <h3 className="text-lg font-semibold text-slate-300 mb-4">Select Alert to Inspect</h3>
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
                                    <div className="text-white text-sm font-semibold mb-1">
                                        {alert.alert_name}
                                    </div>
                                    <div className="text-slate-500 text-xs font-mono">
                                        ID: {alert.id} • {alert.ai_verdict}
                                    </div>
                                </button>
                            ))
                        )}
                    </div>
                </div>

                {/* RAG Usage Details */}
                <div className="col-span-8 glass-panel p-6">
                    <h3 className="text-lg font-semibold text-slate-300 mb-4">RAG Knowledge Retrieval</h3>

                    {!selectedAlert ? (
                        <div className="text-center py-12 text-slate-500">
                            <Database size={48} className="mx-auto mb-3 opacity-50" />
                            <p>Select an alert to view RAG usage details</p>
                        </div>
                    ) : ragLoading ? (
                        <div className="text-center py-12">
                            <RefreshCcw className="animate-spin mx-auto text-cyan-500" size={40} />
                            <p className="text-slate-500 mt-3">Loading RAG data...</p>
                        </div>
                    ) : ragError ? (
                        <div className="text-center py-12">
                            <XCircle className="mx-auto text-red-500 mb-3" size={48} />
                            <p className="text-red-400 font-semibold">Failed to load RAG data</p>
                            <p className="text-slate-500 text-sm mt-2">{ragError}</p>
                            <button 
                                onClick={() => handleAlertSelect(selectedAlert)}
                                className="mt-4 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors"
                            >
                                Retry
                            </button>
                        </div>
                    ) : !ragData ? (
                        <div className="text-center py-12 text-slate-500">
                            <Database size={48} className="mx-auto mb-3 opacity-50" />
                            <p>No RAG data available for this alert</p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {/* Summary */}
                            <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-800">
                                <div className="grid grid-cols-3 gap-4 text-sm">
                                    <div>
                                        <span className="text-slate-400">Sources Queried:</span>
                                        <span className="text-white font-semibold ml-2">
                                            {ragData.sources_queried?.length || 0}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-slate-400">Docs Retrieved:</span>
                                        <span className="text-cyan-400 font-semibold ml-2">
                                            {ragData.total_documents_retrieved || 0}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-slate-400">Query Time:</span>
                                        <span className="text-purple-400 font-semibold ml-2">
                                            {(ragData.total_query_time || 0).toFixed(3)}s
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Retrieved Documents by Source */}
                            <div className="space-y-3">
                                <h4 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
                                    Retrieved Knowledge
                                </h4>
                                {ragData.sources_queried?.map((source, idx) => (
                                    <div key={idx} className="bg-slate-900/50 rounded-lg border border-slate-800">
                                        <button
                                            onClick={() => toggleSource(source)}
                                            className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-800/50 transition-colors"
                                        >
                                            <div className="flex items-center gap-3">
                                                <BookOpen size={18} className="text-cyan-500" />
                                                <span className="text-white font-semibold">{source}</span>
                                                <span className="text-slate-500 text-xs">
                                                    {ragData.retrieved_by_source?.[source]?.length || 0} docs
                                                </span>
                                            </div>
                                            <ChevronDown
                                                className={`text-slate-500 transition-transform ${expandedSources[source] ? 'rotate-180' : ''
                                                    }`}
                                            />
                                        </button>

                                        {expandedSources[source] && ragData.retrieved_by_source?.[source] && (
                                            <div className="p-4 pt-0 space-y-2 border-t border-slate-800">
                                                {ragData.retrieved_by_source[source].map((doc, docIdx) => (
                                                    <div key={docIdx} className="bg-slate-950/50 rounded p-3 text-xs">
                                                        <div className="flex justify-between items-start mb-2">
                                                            <span className="text-cyan-400 font-mono">
                                                                Relevance: {(doc.distance || doc.score || 0).toFixed(3)}
                                                            </span>
                                                        </div>
                                                        <div className="text-slate-300 leading-relaxed">
                                                            {doc.text || doc.content || 'No content'}
                                                        </div>
                                                        {doc.metadata && (
                                                            <div className="text-slate-500 mt-2 text-xs">
                                                                <details>
                                                                    <summary className="cursor-pointer hover:text-cyan-500">
                                                                        Metadata
                                                                    </summary>
                                                                    <pre className="mt-1 bg-slate-950 p-2 rounded overflow-x-auto">
                                                                        {JSON.stringify(doc.metadata, null, 2)}
                                                                    </pre>
                                                                </details>
                                                            </div>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>

                            {/* AI Usage Evidence */}
                            {ragData.ai_used_sources && ragData.ai_used_sources.length > 0 && (
                                <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
                                    <h4 className="text-green-400 font-semibold mb-2 flex items-center gap-2">
                                        <CheckCircle size={16} />
                                        AI Utilized RAG Knowledge
                                    </h4>
                                    <ul className="space-y-1 text-sm text-slate-300">
                                        {ragData.ai_used_sources.map((source, idx) => (
                                            <li key={idx} className="flex items-center gap-2">
                                                <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                                {source}
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default RAGDashboard;
