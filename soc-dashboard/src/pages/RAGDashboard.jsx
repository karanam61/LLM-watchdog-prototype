import React, { useState, useEffect } from 'react';
import { Database, Search, BookOpen, TrendingUp, Activity, CheckCircle, XCircle, RefreshCcw, ChevronDown } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import api from '../utils/api';

const COLORS = ['#7C5CFC', '#5B8DEF', '#00E5A0', '#FF6B2C', '#F5A623', '#a78bfa'];

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
                <RefreshCcw className="animate-spin text-cyber-500" size={40} />
                <span className="ml-3 text-cyber-500 font-mono">Loading RAG Visualization...</span>
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
        <div className="p-8 max-w-7xl mx-auto space-y-6 h-screen overflow-y-auto s-scroll">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold text-sentinel-50 mb-2">RAG System Visualization</h1>
                    <p className="text-sentinel-400 text-sm">
                        Track how the AI retrieves and uses knowledge from the RAG system
                    </p>
                </div>
                <div className="flex items-center gap-2 text-cyber-500">
                    <Database size={20} />
                    <span className="font-mono text-sm">{stats?.total_queries || 0} queries</span>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-4 gap-6">
                <div className="s-metric-card" style={{ '--metric-color': '#7C5CFC' }}>
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="s-metric-label">Total Queries</p>
                            <h3 className="s-metric-value">
                                {stats?.total_queries || 0}
                            </h3>
                        </div>
                        <Search className="text-cyber-500" />
                    </div>
                </div>

                <div className="s-metric-card" style={{ '--metric-color': '#5B8DEF' }}>
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="s-metric-label">Avg Query Time</p>
                            <h3 className="s-metric-value">
                                {(stats?.avg_query_time || 0).toFixed(3)}s
                            </h3>
                        </div>
                        <Activity className="text-steel-500" />
                    </div>
                </div>

                <div className="s-metric-card" style={{ '--metric-color': '#a78bfa' }}>
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="s-metric-label">Avg Docs Retrieved</p>
                            <h3 className="s-metric-value">
                                {(stats?.avg_docs_retrieved || 0).toFixed(1)}
                            </h3>
                        </div>
                        <BookOpen className="text-cyber-400" />
                    </div>
                </div>

                <div className="s-metric-card" style={{ '--metric-color': '#00E5A0' }}>
                    <div className="flex justify-between items-start mb-2">
                        <div>
                            <p className="s-metric-label">Cache Hit Rate</p>
                            <h3 className="s-metric-value">
                                {((stats?.cache_hit_rate || 0) * 100).toFixed(0)}%
                            </h3>
                        </div>
                        <TrendingUp className="text-status-live" />
                    </div>
                </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-2 gap-6">
                <div className="s-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-6">Knowledge Base Collections</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={collectionData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1E2A42" />
                            <XAxis dataKey="name" stroke="#3D4F7C" angle={-45} textAnchor="end" height={80} style={{ fontSize: '10px' }} />
                            <YAxis stroke="#3D4F7C" />
                            <Tooltip contentStyle={{ backgroundColor: '#0C1220', borderColor: '#1E2A42' }} />
                            <Bar dataKey="count" fill="#7C5CFC" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                <div className="s-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-6">Query Distribution by Source</h3>
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
                            <Tooltip contentStyle={{ backgroundColor: '#0C1220', borderColor: '#1E2A42' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Collection Status */}
            <div className="s-panel p-6">
                <h3 className="text-lg font-semibold text-sentinel-200 mb-4">Knowledge Base Status</h3>
                <div className="grid grid-cols-3 gap-4">
                    {collections.map((coll, idx) => (
                        <div key={idx} className="bg-sentinel-850 rounded-lg p-4 border border-sentinel-700">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sentinel-50 font-semibold text-sm">{coll.name}</span>
                                {coll.status === 'active' ? (
                                    <CheckCircle size={16} className="text-status-live" />
                                ) : (
                                    <XCircle size={16} className="text-status-error" />
                                )}
                            </div>
                            <div className="text-sentinel-400 text-xs">
                                {coll.document_count !== undefined ? (
                                    <span>{coll.document_count} documents</span>
                                ) : (
                                    <span className="text-threat-critical">{coll.error}</span>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Alert-Specific RAG Usage */}
            <div className="grid grid-cols-12 gap-6">
                {/* Alert Selection */}
                <div className="col-span-4 s-panel p-6">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-4">Select Alert to Inspect</h3>
                    <div className="space-y-2 max-h-96 overflow-y-auto s-scroll">
                        {alerts.length === 0 ? (
                            <div className="text-sentinel-500 text-sm italic">No analyzed alerts available</div>
                        ) : (
                            alerts.map(alert => (
                                <button
                                    key={alert.id}
                                    onClick={() => handleAlertSelect(alert.id)}
                                    className={`w-full text-left p-3 rounded border transition-all ${selectedAlert === alert.id
                                            ? 'bg-cyber-500/15 border-cyber-500'
                                            : 'bg-sentinel-900 border-sentinel-700 hover:border-sentinel-500'
                                        }`}
                                >
                                    <div className="text-sentinel-50 text-sm font-semibold mb-1">
                                        {alert.alert_name}
                                    </div>
                                    <div className="text-sentinel-500 text-xs font-mono">
                                        ID: {alert.id} • {alert.ai_verdict}
                                    </div>
                                </button>
                            ))
                        )}
                    </div>
                </div>

                {/* RAG Usage Details */}
                <div className="col-span-8 s-panel p-6">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-4">RAG Knowledge Retrieval</h3>

                    {!selectedAlert ? (
                        <div className="text-center py-12 text-sentinel-500">
                            <Database size={48} className="mx-auto mb-3 opacity-50" />
                            <p>Select an alert to view RAG usage details</p>
                        </div>
                    ) : ragLoading ? (
                        <div className="text-center py-12">
                            <RefreshCcw className="animate-spin mx-auto text-cyber-500" size={40} />
                            <p className="text-sentinel-500 mt-3">Loading RAG data...</p>
                        </div>
                    ) : ragError ? (
                        <div className="text-center py-12">
                            <XCircle className="mx-auto text-threat-critical mb-3" size={48} />
                            <p className="text-threat-critical font-semibold">Failed to load RAG data</p>
                            <p className="text-sentinel-500 text-sm mt-2">{ragError}</p>
                            <button 
                                onClick={() => handleAlertSelect(selectedAlert)}
                                className="s-btn-primary mt-4"
                            >
                                Retry
                            </button>
                        </div>
                    ) : !ragData ? (
                        <div className="text-center py-12 text-sentinel-500">
                            <Database size={48} className="mx-auto mb-3 opacity-50" />
                            <p>No RAG data available for this alert</p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {/* Summary */}
                            <div className="bg-sentinel-850 rounded-lg p-4 border border-sentinel-700">
                                <div className="grid grid-cols-3 gap-4 text-sm">
                                    <div>
                                        <span className="text-sentinel-400">Sources Queried:</span>
                                        <span className="text-sentinel-50 font-semibold ml-2">
                                            {ragData.sources_queried?.length || 0}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-sentinel-400">Docs Retrieved:</span>
                                        <span className="text-cyber-400 font-semibold ml-2">
                                            {ragData.total_documents_retrieved || 0}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-sentinel-400">Query Time:</span>
                                        <span className="text-cyber-400 font-semibold ml-2">
                                            {(ragData.total_query_time || 0).toFixed(3)}s
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Retrieved Documents by Source */}
                            <div className="space-y-3">
                                <h4 className="text-sm font-semibold text-sentinel-400 uppercase tracking-wider">
                                    Retrieved Knowledge
                                </h4>
                                {ragData.sources_queried?.map((source, idx) => (
                                    <div key={idx} className="bg-sentinel-850 rounded-lg border border-sentinel-700">
                                        <button
                                            onClick={() => toggleSource(source)}
                                            className="w-full flex items-center justify-between p-4 text-left hover:bg-sentinel-800 transition-colors"
                                        >
                                            <div className="flex items-center gap-3">
                                                <BookOpen size={18} className="text-cyber-500" />
                                                <span className="text-sentinel-50 font-semibold">{source}</span>
                                                <span className="text-sentinel-500 text-xs">
                                                    {ragData.retrieved_by_source?.[source]?.length || 0} docs
                                                </span>
                                            </div>
                                            <ChevronDown
                                                className={`text-sentinel-500 transition-transform ${expandedSources[source] ? 'rotate-180' : ''
                                                    }`}
                                            />
                                        </button>

                                        {expandedSources[source] && ragData.retrieved_by_source?.[source] && (
                                            <div className="p-4 pt-0 space-y-2 border-t border-sentinel-700">
                                                {ragData.retrieved_by_source[source].map((doc, docIdx) => (
                                                    <div key={docIdx} className="bg-sentinel-950 rounded p-3 text-xs">
                                                        <div className="flex justify-between items-start mb-2">
                                                            <span className="text-cyber-400 font-mono">
                                                                Relevance: {(doc.distance || doc.score || 0).toFixed(3)}
                                                            </span>
                                                        </div>
                                                        <div className="text-sentinel-300 leading-relaxed">
                                                            {doc.text || doc.content || 'No content'}
                                                        </div>
                                                        {doc.metadata && (
                                                            <div className="text-sentinel-500 mt-2 text-xs">
                                                                <details>
                                                                    <summary className="cursor-pointer hover:text-cyber-500">
                                                                        Metadata
                                                                    </summary>
                                                                    <pre className="mt-1 bg-sentinel-950 p-2 rounded overflow-x-auto">
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
                                <div className="bg-status-live/5 border border-status-live/20 rounded-lg p-4">
                                    <h4 className="text-status-live font-semibold mb-2 flex items-center gap-2">
                                        <CheckCircle size={16} />
                                        AI Utilized RAG Knowledge
                                    </h4>
                                    <ul className="space-y-1 text-sm text-sentinel-300">
                                        {ragData.ai_used_sources.map((source, idx) => (
                                            <li key={idx} className="flex items-center gap-2">
                                                <span className="w-1.5 h-1.5 rounded-full bg-status-live"></span>
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
