import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { Activity, Cpu, Server, Database, DollarSign, Clock, AlertCircle, CheckCircle, RefreshCcw, TrendingUp } from 'lucide-react';
import api from '../utils/api';

const COLORS = ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b'];

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
                <RefreshCcw className="animate-spin text-cyan-500" size={40} />
                <span className="ml-3 text-cyan-500 font-mono">Loading System Metrics...</span>
            </div>
        );
    }

    if (!metrics) {
        return (
            <div className="flex items-center justify-center h-screen text-red-500">
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
        <div className="p-8 max-w-7xl mx-auto space-y-8 h-screen overflow-y-auto">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">System Performance Metrics</h1>
                    <p className="text-slate-400 text-sm">Real-time monitoring of AI-SOC Watchdog systems</p>
                </div>
                <div className="flex items-center gap-2 text-green-500">
                    <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                    <span className="font-mono text-sm">LIVE</span>
                </div>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-5 gap-6">
                <div className="glass-panel p-6 border-t-4 border-blue-500">
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">CPU Usage</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {(systemMetrics.cpu_percent || 0).toFixed(1)}%
                            </h3>
                        </div>
                        <Cpu className="text-blue-500" />
                    </div>
                    <div className="w-full bg-slate-800 h-2 rounded-full">
                        <div
                            className="bg-blue-500 h-full rounded-full transition-all duration-300"
                            style={{ width: `${systemMetrics.cpu_percent || 0}%` }}
                        />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-indigo-500">
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Memory</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {(systemMetrics.memory_used_gb || 0).toFixed(1)} GB
                            </h3>
                            <p className="text-xs text-slate-500">
                                {(systemMetrics.memory_percent || 0).toFixed(0)}%
                            </p>
                        </div>
                        <Server className="text-indigo-500" />
                    </div>
                    <div className="w-full bg-slate-800 h-2 rounded-full">
                        <div
                            className="bg-indigo-500 h-full rounded-full transition-all duration-300"
                            style={{ width: `${systemMetrics.memory_percent || 0}%` }}
                        />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-cyan-500">
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">AI Cost</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                ${(aiMetrics.total_cost || 0).toFixed(2)}
                            </h3>
                            <p className="text-xs text-slate-500">
                                {aiMetrics.total_requests || 0} calls
                            </p>
                        </div>
                        <DollarSign className="text-cyan-500" />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-green-500">
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Uptime</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {Math.floor(uptimeSeconds / 3600)}h {Math.floor((uptimeSeconds % 3600) / 60)}m
                            </h3>
                        </div>
                        <Clock className="text-green-500" />
                    </div>
                </div>

                <div className="glass-panel p-6 border-t-4 border-purple-500">
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <p className="text-slate-400 text-xs uppercase tracking-wider">Alerts Processed</p>
                            <h3 className="text-2xl font-bold text-white mt-1">
                                {alertStats.total_processed || 0}
                            </h3>
                            <p className="text-xs text-slate-500">
                                {alertStats.pending_queue || 0} queued
                            </p>
                        </div>
                        <TrendingUp className="text-purple-500" />
                    </div>
                </div>
            </div>

            {/* Main Charts */}
            <div className="grid grid-cols-2 gap-6">
                <div className="glass-panel p-6 h-96">
                    <h3 className="text-lg font-semibold text-slate-300 mb-6">System Resource Usage (24h)</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={chartData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                            <XAxis dataKey="time" stroke="#64748b" style={{ fontSize: '12px' }} />
                            <YAxis stroke="#64748b" />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                                itemStyle={{ color: '#e2e8f0' }}
                            />
                            <Line type="monotone" dataKey="cpu" stroke="#3b82f6" strokeWidth={2} dot={false} name="CPU %" />
                            <Line type="monotone" dataKey="memory" stroke="#8b5cf6" strokeWidth={2} dot={false} name="Memory %" />
                        </LineChart>
                    </ResponsiveContainer>
                </div>

                <div className="glass-panel p-6 h-96">
                    <h3 className="text-lg font-semibold text-slate-300 mb-6">Alert Processing Volume (24h)</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                            <XAxis dataKey="time" stroke="#64748b" style={{ fontSize: '12px' }} />
                            <YAxis stroke="#64748b" />
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
                            <Bar dataKey="alerts" fill="#06b6d4" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Secondary Charts and Stats */}
            <div className="grid grid-cols-3 gap-6">
                <div className="glass-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-slate-300 mb-6">AI Verdict Distribution</h3>
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
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>

                <div className="glass-panel p-6 h-80">
                    <h3 className="text-lg font-semibold text-slate-300 mb-6">AI Performance Stats</h3>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">Avg Response Time</span>
                            <span className="text-white font-semibold">
                                {(aiMetrics.avg_processing_time || 0).toFixed(2)}s
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">Input Tokens</span>
                            <span className="text-cyan-400 font-semibold">
                                {aiMetrics.total_input_tokens.toLocaleString()}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">Output Tokens</span>
                            <span className="text-purple-400 font-semibold">
                                {aiMetrics.total_output_tokens.toLocaleString()}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">Cost per Alert</span>
                            <span className="text-green-400 font-semibold">
                                ${(aiMetrics.total_cost / Math.max(alertStats.total_processed, 1)).toFixed(4)}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">RAG Queries</span>
                            <span className="text-blue-400 font-semibold">
                                {ragStats.total_queries}
                            </span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">Avg RAG Time</span>
                            <span className="text-indigo-400 font-semibold">
                                {(ragStats.avg_query_time || 0).toFixed(3)}s
                            </span>
                        </div>
                    </div>
                </div>

                <div className="glass-panel p-6 h-80 relative overflow-hidden">
                    <h3 className="text-lg font-semibold text-slate-300 mb-4">Recent Errors</h3>
                    <div className="space-y-2 overflow-y-auto max-h-64 custom-scrollbar">
                        {errors.length === 0 ? (
                            <div className="text-green-500 flex items-center gap-2 text-sm">
                                <CheckCircle size={16} />
                                No errors in the last 24 hours
                            </div>
                        ) : (
                            errors.map((error, i) => (
                                <div key={i} className="flex items-start gap-3 text-sm p-2 hover:bg-slate-800 rounded">
                                    <AlertCircle size={16} className="text-red-500 mt-0.5" />
                                    <div className="flex-1">
                                        <div className="text-slate-500 text-xs">
                                            {new Date(error.timestamp * 1000).toLocaleTimeString()}
                                        </div>
                                        <div className="text-slate-300">{error.component}</div>
                                        <div className="text-red-400 text-xs font-mono">{error.error}</div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div >
    );
};

export default PerformanceDashboard;
