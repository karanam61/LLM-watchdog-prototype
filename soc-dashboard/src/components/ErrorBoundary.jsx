
import React from 'react';

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
                <div className="flex items-center justify-center h-screen w-full bg-gray-900 text-white">
                    <div className="p-8 border border-red-500 rounded-lg bg-black/50 backdrop-blur-md max-w-lg">
                        <h1 className="text-2xl font-bold text-red-500 mb-4">⚠️ System Error</h1>
                        <p className="text-gray-300 mb-4">
                            The AI-SOC Dashboard encountered a critical error.
                        </p>
                        <div className="bg-gray-800 p-4 rounded text-xs font-mono mb-4 overflow-auto max-h-40">
                            {this.state.error && this.state.error.toString()}
                        </div>
                        <button
                            onClick={() => window.location.reload()}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-semibold transition-colors"
                        >
                            Reload System
                        </button>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
