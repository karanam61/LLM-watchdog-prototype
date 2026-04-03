import React from 'react';
import { Shield, RefreshCcw, AlertTriangle } from 'lucide-react';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, info: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true };
    }

    componentDidCatch(error, info) {
        console.error("Uncaught error:", error, info);
        this.setState({ error, info });
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="flex items-center justify-center h-screen w-full bg-sentinel-950 text-sentinel-50 bg-grid">
                    {/* Ambient glow */}
                    <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-threat-critical/5 rounded-full blur-[120px]" />

                    <div className="relative s-panel-elevated p-10 max-w-lg text-center">
                        <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-threat-critical/10 border border-threat-critical/20 flex items-center justify-center">
                            <AlertTriangle size={32} className="text-threat-critical" />
                        </div>

                        <h1 className="text-2xl font-bold text-sentinel-50 mb-2">System Fault Detected</h1>
                        <p className="text-sentinel-300 mb-6">
                            The SENTINEL platform encountered a critical error. Diagnostic data has been captured.
                        </p>

                        {this.state.error && (
                            <div className="bg-sentinel-950 border border-sentinel-700 rounded-lg p-4 mb-6 text-left">
                                <div className="text-2xs font-semibold text-threat-critical uppercase tracking-wider mb-2">Error Trace</div>
                                <pre className="text-xs font-mono text-sentinel-300 overflow-auto max-h-32 s-scroll">
                                    {this.state.error.toString()}
                                </pre>
                            </div>
                        )}

                        <button
                            onClick={() => window.location.reload()}
                            className="s-btn-primary gap-2"
                        >
                            <RefreshCcw size={16} />
                            Restart Platform
                        </button>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
