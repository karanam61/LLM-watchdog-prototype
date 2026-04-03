import { useState } from 'react';
import { ShieldAlert, Lock, User, AlertCircle } from 'lucide-react';

const Login = ({ onLogin }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await fetch('http://localhost:5000/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                onLogin(data.username);
            } else {
                setError(data.error || 'Login failed');
            }
        } catch (err) {
            setError('Connection failed. Is the backend running?');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-sentinel-950 bg-grid flex items-center justify-center p-4 relative overflow-hidden">
            {/* Ambient glow orbs */}
            <div className="absolute top-[-10%] left-[-5%] w-[600px] h-[600px] rounded-full blur-[200px]"
                 style={{ background: 'rgba(124, 92, 252, 0.04)' }} />
            <div className="absolute bottom-[-10%] right-[-5%] w-[600px] h-[600px] rounded-full blur-[200px]"
                 style={{ background: 'rgba(91, 141, 239, 0.04)' }} />

            <div className="relative w-full max-w-md flex flex-col items-center">
                {/* Logo & Branding */}
                <div className="text-center mb-10">
                    <div className="inline-flex items-center justify-center w-[72px] h-[72px] rounded-2xl bg-gradient-to-br from-cyber-500 to-steel-500 mb-5 shadow-glow-cyber">
                        <ShieldAlert size={36} className="text-white" />
                    </div>
                    <h1 className="text-3xl font-bold tracking-wider text-sentinel-50">SENTINEL</h1>
                    <p className="text-sentinel-400 text-sm mt-2 tracking-wide">AI-SOC Autonomous Defense Platform</p>
                </div>

                {/* Login Card */}
                <div className="s-panel-elevated w-full p-8 rounded-2xl">
                    <h2 className="text-lg font-semibold text-sentinel-100 mb-6 tracking-wide">Operator Authentication</h2>

                    {error && (
                        <div className="mb-5 p-3 bg-threat-critical/10 border border-threat-critical/30 rounded-lg flex items-center gap-2.5 text-threat-critical text-sm">
                            <AlertCircle size={16} className="shrink-0" />
                            {error}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-5">
                        <div>
                            <label className="block text-sm font-medium text-sentinel-400 mb-2">Username</label>
                            <div className="relative">
                                <User size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-sentinel-500" />
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    className="s-input w-full bg-sentinel-950 border border-sentinel-700 rounded-lg py-3 pl-10 pr-4 text-sentinel-50 placeholder-sentinel-500 focus:outline-none focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500 transition-colors"
                                    placeholder="Enter callsign"
                                    required
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-sentinel-400 mb-2">Password</label>
                            <div className="relative">
                                <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-sentinel-500" />
                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="s-input w-full bg-sentinel-950 border border-sentinel-700 rounded-lg py-3 pl-10 pr-4 text-sentinel-50 placeholder-sentinel-500 focus:outline-none focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500 transition-colors"
                                    placeholder="Enter passphrase"
                                    required
                                />
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="s-btn-primary w-full bg-gradient-to-r from-cyber-500 to-cyber-600 text-white font-semibold py-3 rounded-lg hover:shadow-glow-cyber focus:outline-none focus:ring-2 focus:ring-cyber-500 focus:ring-offset-2 focus:ring-offset-sentinel-900 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {loading ? 'Authenticating...' : 'Authenticate'}
                        </button>
                    </form>

                    <div className="mt-6 pt-6 border-t border-sentinel-700">
                        <p className="text-xs text-sentinel-500 text-center">
                            Authorized personnel only. All access is monitored and logged.
                        </p>
                    </div>
                </div>

                {/* Version footer */}
                <p className="mt-8 text-xs text-sentinel-600 tracking-wide">v2.0.0 — SENTINEL Platform</p>
            </div>
        </div>
    );
};

export default Login;
