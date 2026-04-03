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
        if (status === 'error') return 'text-status-error border-status-error/40';
        if (status === 'warning') return 'text-status-warn border-status-warn/40';
        return 'text-status-live border-status-live/40';
    };

    const getStatusBg = (status) => {
        if (status === 'error') return 'bg-status-error/5';
        if (status === 'warning') return 'bg-status-warn/5';
        return 'bg-status-live/5';
    };

    const getCategoryColor = (category) => {
        const colors = {
            'API': 'text-cyber-400',
            'FUNCTION': 'text-steel-500',
            'WORKER': 'text-[#a78bfa]',
            'AI': 'text-[#f472b6]',
            'DATABASE': 'text-status-live',
            'SECURITY': 'text-threat-critical',
            'RAG': 'text-threat-high',
            'QUEUE': 'text-[#818cf8]',
            'ERROR': 'text-threat-critical'
        };
        return colors[category] || 'text-sentinel-400';
    };

    return (
        <div className="p-6 h-screen flex flex-col gap-4 overflow-hidden">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-mono font-bold text-cyber-400 flex items-center gap-2">
                        <Terminal size={28} />
                        LIVE SYSTEM DEBUG
                    </h1>
                    <p className="text-sentinel-500 text-sm font-mono mt-1">
                        Real-time operational trace — every API call, function, worker action, and AI step
                    </p>
                </div>

                <div className="flex gap-2 items-center">
                    {/* Auto-scroll toggle */}
                    <label className="flex items-center gap-2 text-sm font-mono text-sentinel-400 cursor-pointer select-none">
                        <input
                            type="checkbox"
                            checked={autoScroll}
                            onChange={(e) => setAutoScroll(e.target.checked)}
                            className="rounded border-sentinel-600 bg-sentinel-900 text-cyber-500 focus:ring-cyber-500/30 focus:ring-offset-0"
                        />
                        AUTO_SCROLL
                    </label>

                    <button
                        onClick={() => setPaused(!paused)}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-mono border transition-all duration-200 ${
                            paused
                                ? 'border-status-warn text-status-warn bg-status-warn/10'
                                : 'border-cyber-500 text-cyber-400 bg-cyber-500/10 shadow-glow-cyber'
                        }`}
                    >
                        {paused ? <Play size={14} /> : <Pause size={14} />}
                        {paused ? 'RESUME' : 'PAUSE'}
                    </button>
                    <button
                        onClick={() => setLogs([])}
                        className="s-btn-ghost text-sm font-mono"
                    >
                        <Trash2 size={14} /> CLEAR
                    </button>
                </div>
            </div>

            {/* Filters */}
            <div className="flex gap-4 items-center">
                <div className="flex items-center gap-2">
                    <Filter size={16} className="text-sentinel-500" />
                    <select
                        value={selectedCategory}
                        onChange={(e) => setSelectedCategory(e.target.value)}
                        className="s-select text-sm font-mono !w-auto"
                    >
                        {categories.map(cat => (
                            <option key={cat} value={cat}>{cat.toUpperCase()}</option>
                        ))}
                    </select>
                </div>

                <div className="flex-1 relative">
                    <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-sentinel-500 pointer-events-none" />
                    <input
                        type="text"
                        placeholder="Search operations..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="s-input font-mono !pl-10"
                    />
                </div>

                <div className="text-sm font-mono text-sentinel-500 tabular-nums">
                    {logs.length} operations
                </div>
            </div>

            {/* Log Terminal */}
            <div className="flex-1 bg-sentinel-950 border border-sentinel-700 rounded-xl overflow-hidden shadow-glow-cyber flex flex-col">
                {/* Fake title bar */}
                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-sentinel-700 bg-sentinel-900/60 shrink-0">
                    <div className="flex items-center gap-1.5">
                        <div className="w-3 h-3 rounded-full bg-[#FF5F57]" />
                        <div className="w-3 h-3 rounded-full bg-[#FEBC2E]" />
                        <div className="w-3 h-3 rounded-full bg-[#28C840]" />
                    </div>
                    <span className="text-sentinel-400 text-xs font-mono tracking-wider ml-2">
                        SENTINEL DEBUG STREAM
                    </span>
                    {!paused && (
                        <div className="ml-auto flex items-center gap-1.5">
                            <div className="s-dot-live animate-pulse" />
                            <span className="text-2xs font-mono text-status-live">LIVE</span>
                        </div>
                    )}
                </div>

                {/* Log content */}
                <div className="flex-1 p-4 overflow-auto font-mono text-xs s-scroll">
                    {logs.length === 0 ? (
                        <div className="text-sentinel-500 italic flex items-center gap-2 py-8 justify-center">
                            <AlertCircle size={16} className="text-sentinel-600" />
                            {paused ? 'Stream paused — no operations to display' : 'Waiting for operations...'}
                        </div>
                    ) : (
                        logs.map((log, idx) => (
                            <div
                                key={idx}
                                className={`mb-1.5 p-2.5 border-l-2 ${getStatusColor(log.status)} ${getStatusBg(log.status)} rounded-r-lg hover:bg-sentinel-900/50 transition-colors`}
                            >
                                {/* Timestamp + Category + Status */}
                                <div className="flex items-center gap-3 mb-1">
                                    <span className="text-sentinel-500 text-xs tabular-nums">
                                        [{new Date(log.datetime).toLocaleTimeString('en-US', {
                                            hour12: false,
                                            hour: '2-digit',
                                            minute: '2-digit',
                                            second: '2-digit',
                                            fractionalSecondDigits: 3
                                        })}]
                                    </span>
                                    <span className={`font-bold px-2 py-0.5 rounded text-2xs bg-sentinel-800 border border-sentinel-700 ${getCategoryColor(log.category)}`}>
                                        {log.category}
                                    </span>
                                    <span className="text-sentinel-50 font-semibold flex-1">
                                        {log.operation}
                                    </span>
                                    {log.duration && (
                                        <span className="text-cyber-400 text-xs tabular-nums">
                                            {log.duration.toFixed(3)}s
                                        </span>
                                    )}
                                    <span className={`text-xs uppercase font-bold ${
                                        log.status === 'error'
                                            ? 'text-status-error'
                                            : log.status === 'warning'
                                                ? 'text-status-warn'
                                                : 'text-status-live'
                                    }`}>
                                        {log.status}
                                    </span>
                                </div>

                                {/* Human-readable explanation */}
                                {log.explanation && (
                                    <div className="text-sentinel-400 text-xs pl-4 mb-1">
                                        {log.explanation}
                                    </div>
                                )}

                                {/* Details */}
                                {log.details && Object.keys(log.details).length > 0 && (
                                    <div className="text-sentinel-500 text-xs pl-4 mt-1">
                                        <details className="cursor-pointer">
                                            <summary className="hover:text-cyber-400 transition-colors">Details</summary>
                                            <pre className="mt-1 text-xs bg-sentinel-950 border border-sentinel-700/50 p-2 rounded-lg overflow-x-auto s-scroll text-sentinel-300">
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
            </div>

            {/* Legend */}
            <div className="flex gap-4 text-xs font-mono text-sentinel-500">
                <span className="flex items-center gap-1.5">
                    <div className="s-dot-live" />
                    Success
                </span>
                <span className="flex items-center gap-1.5">
                    <div className="s-dot-warn" />
                    Warning
                </span>
                <span className="flex items-center gap-1.5">
                    <div className="s-dot-error" />
                    Error
                </span>
                <span className="ml-auto text-sentinel-600">
                    Non-technical friendly explanations for every operation
                </span>
            </div>
        </div>
    );
};

export default DebugDashboard;
