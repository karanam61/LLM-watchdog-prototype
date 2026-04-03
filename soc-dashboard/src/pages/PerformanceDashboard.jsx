import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { Activity, Cpu, Server, Database, DollarSign, Clock, AlertCircle, CheckCircle, RefreshCcw, TrendingUp } from 'lucide-react';
import api from '../utils/api';

const COLORS = ['#7C5CFC', '#5B8DEF', '#00E5A0', '#FF6B2C', '#F5A623'];

const PerformanceDashboard = () => {
    const [metrics, setMetrics] = useState(null);
    const [history, setHistory] = useState([]);
    const [errors, setErrors] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchMetrics = async () => {
            try {
                const [metricsRes, historyRes, errorsRes] = await Promise.all([
                    api.get('/api/monitoring/metrics/dashboard'),
                    api.get('/api/monitoring/metrics/history?hours=24'),
                    api.get('/api/monitoring/metrics/errors?limit=10')
                ]);

                setMetrics(metricsRes.data);
                setHistory(historyRes.data.history || []);
                setErrors(errorsRes.data.errors || []);
                setLoading(false);
            } catch (e) {
                console.error('Failed to fetch metrics:', e);
                setLoading(false);
            }
        };

        fetchMetrics();
        const interval = setInterval(fetchMetrics, 5000); // Update every 5s
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-screen">
                <RefreshCcw className="animate-spin text-cyber-500" size={40} />
                <span className="ml-3 text-cyber-500 font-mono">Loading System Metrics...</span>
            </div>
        );
    }

    if (!metrics) {
        return (
            <div className="flex items-center justify-center h-screen text-threat-critical">
                <AlertCircle size={40} />
                <span className="ml-3 font-mono">Failed to load metrics</span>
            </div>
        );
    }

    const systemMetrics = metrics?.system_metrics || { cpu_percent: 0, memory_percent: 0, memory_used_gb: 0 };
    const alertStats = metrics?.alert_stats || { total_processed: 0, by_verdict: {}, pending_queue: 0 };
    const budgetInfo = metrics?.budget || { spent: 0, remaining: 0 };
    const aiMetrics = metrics?.ai_metrics || {
        avg_processing_time: 0,
        total_cost: 0,
        total_requests: 0,
        total_input_tokens: 0,
        total_output_tokens: 0
    };
    const ragStats = metrics?.rag_stats || { total_queries: 0, avg_query_time: 0 };
    const uptimeSeconds = metrics?.uptime_seconds || 0;

    const chartData = (history || []).map(h => ({
        time: new Date((h?.timestamp || 0) * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        cpu: h?.system_metrics?.cpu_percent || 0,
        memory: h?.system_metrics?.memory_percent || 0,
        alerts: h?.alert_stats?.total_processed || 0
    }));

    const verdictData = alertStats.by_verdict ?
        Object.entries(alertStats.by_verdict).map(([name, value]) => ({ name, value })) : [];

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-8 h-screen overflow-y-auto s-scroll">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold text-sentinel-50 mb-2">System Performance Metrics</h1>
                    <p className="text-sentinel-400 text-sm">Real-time monitoring of AI-SOC Watchdog systems</p>
                </div>
                <div className="flex items-center gap-2 text-status-live">
                    <div className="s-dot-live"></div>
                    <span className="font-mono text-sm">LIVE</span>
                </div>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-4 gap-6">
                <div className="s-metric-card" style={{ '--metric-color': '#7C5CFC' }}>
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="s-metric-label">CPU Usage</p>
                            <h3 className="s-metric-value">
                                {(systemMetrics.cpu_percent || 0).toFixed(1)}%
                            </h3>
                        </div>
                        <Cpu className="text-cyber-500" />
                    </div>
                    <div className="w-full bg-sentinel-800 h-2 rounded-full">
                        <div
                            className="bg-cyber-500 h-full rounded-full transition-all duration-300"
                            style={{ width: `${systemMetrics.cpu_percent || 0}%` }}
                        />
                    </div>
                </div>

                <div className="s-metric-card" style={{ '--metric-color': '#5B8DEF' }}>
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="s-metric-label">Memory</p>
                            <h3 className="s-metric-value">
                                {(systemMetrics.memory_used_gb || 0).toFixed(1)} GB
                            </h3>
                            <p className="s-metric-sub">
                                {(systemMetrics.memory_percent || 0).toFixed(0)}%
                            </p>
                        </div>
                        <Server className="text-steel-500" />
                    </div>
                    <div className="w-full bg-sentinel-800 h-2 rounded-full">
                        <div
                            className="bg-steel-500 h-full rounded-full transition-all duration-300"
                            style={{ width: `${systemMetrics.memory_percent || 0}%` }}
                        />
                    </div>
                </div>

                <div className="s-metric-card" style={{ '--metric-color': '#00E5A0' }}>
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="s-metric-label">AI Cost</p>
                            <h3 className="s-metric-value">
                                ${(aiMetrics.total_cost || 0).toFixed(2)}
                            </h3>
                            <p className="s-metric-sub">
                                {aiMetrics.total_requests || 0} calls
                            </p>
                        </div>
                        <DollarSign className="text-[#00E5A0]" />
                    </div>
                </div>

                <div className="s-metric-card" style={{ '--metric-color': '#F5A623' }}>
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="s-metric-label">Uptime</p>
                            <h3 className="s-metric-value">
                                {Math.floor(uptimeSeconds / 3600)}h {Math.floor((uptimeSeconds % 3600) / 60)}m
                            </h3>
                        </div>
                        <Clock className="text-[#F5A623]" />
                    </div>
                </div>
            </div>

            {/* Alerts Processed — standalone row */}
            <div className="grid grid-cols-4 gap-6">
                <div className="s-metric-card" style={{ '--metric-color': '#FF6B2C' }}>
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="s-metric-label">Alerts Processed</p>
                            <h3 className="s-metric-value">
                                {alertStats.total_processed || 0}
                            </h3>
                            <p className="s-metric-sub">
                                {alertStats.pending_queue || 0} queued
                            </p>
                        </div>
                        <TrendingUp className="text-[#FF6B2C]" />
                    </div>
                </div>
            </div>

            {/* Main Charts */}
            <div className="grid grid-cols-2 gap-6">
                <div className="s-panel p-6 h-96">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-6">System Resource Usage (24h)</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={chartData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1E2A42" />
                            <XAxis dataKey="time" stroke="#3D4F7C" style={{ fontSize: '12px' }} />
                            <YAxis stroke="#3D4F7C" />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#0C1220', borderColor: '#1E2A42' }}
                                itemStyle={{ color: '#e2e8f0' }}
                            />
                            <Line type="monotone" dataKey="cpu" stroke="#7C5CFC" strokeWidth={2} dot={false} name="CPU %" />
                            <Line type="monotone" dataKey="memory" stroke="#5B8DEF" strokeWidth={2} dot={false} name="Memory %" />
                        </LineChart>
                    </ResponsiveContainer>
                </div>

                <div className="s-panel p-6 h-96">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-6">Alert Processing Volume (24h)</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1E2A42" />
                            <XAxis dataKey="time" stroke="#3D4F7C" style={{ fontSize: '12px' }} />
                            <YAxis stroke="#3D4F7C" />
                            <Tooltip contentStyle={{ backgroundColor: '#0C1220', borderColor: '#1E2A42' }} />
                            <Bar dataKey="alerts" fill="#7C5CFC" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Secondary Charts and Stats */}
            <div className="grid grid-cols-3 gap-6">
                <div className="s-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-6">AI Verdict Distribution</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={verdictData}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={({ name, value }) => `${name}: ${value}`}
                                outerRadius={80}
                                fill="#8884d8"
                                dataKey="value"
                            >
                                {verdictData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: '#0C1220', borderColor: '#1E2A42' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>

                <div className="s-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-6">AI Performance Stats</h3>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <span className="text-sentinel-400 text-sm">Avg Response Time</span>
                            <span className="text-sentinel-50 font-semibold">
                                {(aiMetrics.avg_processing_time || 0).toFixed(2)}s
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-sentinel-400 text-sm">Input Tokens</span>
                            <span className="text-cyber-400 font-semibold">
                                {aiMetrics.total_input_tokens.toLocaleString()}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-sentinel-400 text-sm">Output Tokens</span>
                            <span className="text-cyber-400 font-semibold">
                                {aiMetrics.total_output_tokens.toLocaleString()}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-sentinel-400 text-sm">Cost per Alert</span>
                            <span className="text-[#00E5A0] font-semibold">
                                ${(aiMetrics.total_cost / Math.max(alertStats.total_processed, 1)).toFixed(4)}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-sentinel-400 text-sm">RAG Queries</span>
                            <span className="text-steel-500 font-semibold">
                                {ragStats.total_queries}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-sentinel-400 text-sm">Avg RAG Time</span>
                            <span className="text-steel-500 font-semibold">
                                {(ragStats.avg_query_time || 0).toFixed(3)}s
                            </span>
                        </div>
                    </div>
                </div>

                <div className="s-panel p-6 h-80 relative overflow-hidden">
                    <h3 className="text-lg font-semibold text-sentinel-200 mb-4">Recent Errors</h3>
                    <div className="space-y-2 overflow-y-auto max-h-64 s-scroll">
                        {errors.length === 0 ? (
                            <div className="text-[#00E5A0] flex items-center gap-2 text-sm">
                                <CheckCircle size={16} />
                                No errors in the last 24 hours
                            </div>
                        ) : (
                            errors.map((error, i) => (
                                <div key={i} className="flex items-start gap-3 text-sm p-2 hover:bg-sentinel-800 rounded">
                                    <AlertCircle size={16} className="text-threat-critical mt-0.5" />
                                    <div className="flex-1">
                                        <div className="text-sentinel-500 text-xs">
                                            {new Date(error.timestamp * 1000).toLocaleTimeString()}
                                        </div>
                                        <div className="text-sentinel-200">{error.component}</div>
                                        <div className="text-threat-critical text-xs font-mono">{error.error}</div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PerformanceDashboard;
