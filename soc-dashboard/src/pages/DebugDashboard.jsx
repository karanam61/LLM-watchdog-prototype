import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Pause, Trash2, Filter, Search, AlertCircle } from 'lucide-react';
import api from '../utils/api';

const DebugDashboard = () => {
    const [logs, setLogs] = useState([]);
    const [paused, setPaused] = useState(false);
    const [selectedCategory, setSelectedCategory] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [categories, setCategories] = useState([]);
    const logsEndRef = useRef(null);
    const [autoScroll, setAutoScroll] = useState(true);

    // Fetch available categories
    useEffect(() => {
        const fetchCategories = async () => {
            try {
                const res = await api.get('/api/monitoring/logs/categories');
                const cats = res.data?.categories || [];
                setCategories(['all', ...cats]);
            } catch (e) {
                console.error("Failed to fetch categories", e);
                setCategories(['all']); // Fallback
            }
        };
        fetchCategories();
    }, []);

    // Fetch logs from Backend
    useEffect(() => {
        if (paused) return;

        const fetchLogs = async () => {
            try {
                const params = new URLSearchParams();
                if (selectedCategory !== 'all') params.append('category', selectedCategory);
                if (searchTerm) params.append('search', searchTerm);
                params.append('limit', '200');

                const res = await api.get(`/api/monitoring/logs/recent?${params.toString()}`);
                const data = res.data;
                if (data.operations) {
                    setLogs(data.operations);
                    if (autoScroll) {
                        setTimeout(() => logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
                    }
                }
            } catch (e) {
                console.error("Log poll failed", e);
            }
        };

        fetchLogs();
        const interval = setInterval(fetchLogs, 1000); // Poll every 1s for real-time feel

        return () => clearInterval(interval);
    }, [paused, selectedCategory, searchTerm, autoScroll]);

    const getStatusColor = (status) => {
        if (status === 'error') return 'text-red-500 bg-red-500/10 border-red-500/30';
        if (status === 'warning') return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
        return 'text-green-500 bg-green-500/10 border-green-500/30';
    };

    const getCategoryColor = (category) => {
        const colors = {
            'API': 'text-cyan-400',
            'FUNCTION': 'text-blue-400',
            'WORKER': 'text-purple-400',
            'AI': 'text-pink-400',
            'DATABASE': 'text-green-400',
            'SECURITY': 'text-red-400',
            'RAG': 'text-orange-400',
            'QUEUE': 'text-indigo-400',
            'ERROR': 'text-red-500'
        };
        return colors[category] || 'text-slate-400';
    };

    return (
        <div className="p-6 h-screen flex flex-col gap-4 overflow-hidden">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-mono font-bold text-green-500 flex items-center gap-2">
                        <Terminal size={28} />
                        LIVE SYSTEM DEBUG
                    </h1>
                    <p className="text-slate-500 text-sm font-mono mt-1">
                        Real-time operational trace - every API call, function, worker action, and AI step
                    </p>
                </div>

                <div className="flex gap-2 items-center">
                    {/* Auto-scroll toggle */}
                    <label className="flex items-center gap-2 text-sm font-mono text-slate-400 cursor-pointer">
                        <input
                            type="checkbox"
                            checked={autoScroll}
                            onChange={(e) => setAutoScroll(e.target.checked)}
                            className="rounded"
                        />
                        AUTO_SCROLL
                    </label>

                    <button
                        onClick={() => setPaused(!paused)}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-mono border ${paused ? 'border-yellow-500 text-yellow-500' : 'border-green-500 text-green-500 bg-green-500/10'}`}
                    >
                        {paused ? <Play size={14} /> : <Pause size={14} />}
                        {paused ? 'RESUME' : 'PAUSE'}
                    </button>
                    <button
                        onClick={() => setLogs([])}
                        className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-mono border border-slate-600 text-slate-400 hover:text-white"
                    >
                        <Trash2 size={14} /> CLEAR
                    </button>
                </div>
            </div>

            {/* Filters */}
            <div className="flex gap-4 items-center">
                <div className="flex items-center gap-2">
                    <Filter size={16} className="text-slate-500" />
                    <select
                        value={selectedCategory}
                        onChange={(e) => setSelectedCategory(e.target.value)}
                        className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                    >
                        {categories.map(cat => (
                            <option key={cat} value={cat}>{cat.toUpperCase()}</option>
                        ))}
                    </select>
                </div>

                <div className="flex-1 relative">
                    <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                    <input
                        type="text"
                        placeholder="Search operations..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded pl-10 pr-4 py-1.5 text-sm font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                    />
                </div>

                <div className="text-sm font-mono text-slate-500">
                    {logs.length} operations
                </div>
            </div>

            {/* Log Terminal */}
            <div className="flex-1 bg-black border border-green-900/50 rounded-lg p-4 overflow-auto font-mono text-xs relative shadow-[0_0_30px_rgba(34,197,94,0.1)] custom-scrollbar">
                <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-b from-green-900/5 to-transparent pointer-events-none" />

                {logs.length === 0 ? (
                    <div className="text-slate-600 italic flex items-center gap-2">
                        <AlertCircle size={16} />
                        {paused ? 'Paused - No operations to display' : 'Waiting for operations...'}
                    </div>
                ) : (
                    logs.map((log, idx) => (
                        <div
                            key={idx}
                            className={`mb-2 p-2 border-l-2 ${getStatusColor(log.status)} border rounded hover:bg-slate-900/30 transition-colors`}
                        >
                            {/* Timestamp + Category + Status */}
                            <div className="flex items-center gap-3 mb-1">
                                <span className="text-slate-600 text-xs">
                                    [{new Date(log.datetime).toLocaleTimeString('en-US', {
                                        hour12: false,
                                        hour: '2-digit',
                                        minute: '2-digit',
                                        second: '2-digit',
                                        fractionalSecondDigits: 3
                                    })}]
                                </span>
                                <span className={`font-bold px-2 py-0.5 rounded text-xs border ${getCategoryColor(log.category)} border-current/20 bg-current/5`}>
                                    {log.category}
                                </span>
                                <span className="text-white font-semibold flex-1">
                                    {log.operation}
                                </span>
                                {log.duration && (
                                    <span className="text-cyan-500 text-xs">
                                        {log.duration.toFixed(3)}s
                                    </span>
                                )}
                                <span className={`text-xs uppercase font-bold ${log.status === 'error' ? 'text-red-500' : log.status === 'warning' ? 'text-yellow-500' : 'text-green-500'}`}>
                                    {log.status}
                                </span>
                            </div>

                            {/* Human-readable explanation */}
                            {log.explanation && (
                                <div className="text-slate-400 text-xs pl-4 mb-1">
                                    {log.explanation}
                                </div>
                            )}

                            {/* Details */}
                            {log.details && Object.keys(log.details).length > 0 && (
                                <div className="text-slate-500 text-xs pl-4 mt-1">
                                    <details className="cursor-pointer">
                                        <summary className="hover:text-cyan-500">Details</summary>
                                        <pre className="mt-1 text-xs bg-slate-950/50 p-2 rounded overflow-x-auto">
                                            {JSON.stringify(log.details, null, 2)}
                                        </pre>
                                    </details>
                                </div>
                            )}
                        </div>
                    ))
                )}
                <div ref={logsEndRef} />
            </div>

            {/* Legend */}
            <div className="flex gap-4 text-xs font-mono text-slate-500">
                <span className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full bg-green-500"></div>
                    Success
                </span>
                <span className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full bg-yellow-500"></div>
                    Warning
                </span>
                <span className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full bg-red-500"></div>
                    Error
                </span>
                <span className="ml-auto text-slate-600">
                    Non-technical friendly explanations for every operation
                </span>
            </div>
        </div>
    );
};

export default DebugDashboard;
