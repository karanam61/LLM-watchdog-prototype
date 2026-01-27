import { LayoutDashboard, Activity, Terminal, ShieldCheck, Database, Brain } from 'lucide-react';
import { useLocation, Link } from 'react-router-dom';

const Sidebar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;



  return (
    <div className="w-72 h-screen bg-slate-950/80 backdrop-blur-xl border-r border-slate-800 flex flex-col relative z-20">

      {/* Brand Header */}
      <div className="p-6 border-b border-slate-800/60 pb-8">
        <div className="flex items-center gap-3 mb-1">
          <div className="relative">
            <div className="absolute inset-0 bg-cyan-500 blur-lg opacity-40 animate-pulse-slow"></div>
            <ShieldCheck className="w-8 h-8 text-cyan-400 relative z-10" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white glow-text-cyan">
            AI-SOC
            <span className="text-cyan-500 ml-1">WATCHDOG</span>
          </h1>
        </div>
        <div className="text-xs text-slate-500 font-mono pl-11 tracking-widest uppercase">
          Autonomous Defense
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2 mt-4 overflow-y-auto">
        <div className="text-xs font-semibold text-slate-600 uppercase tracking-wider mb-4 px-2">
          Operations
        </div>

        <Link to="/analyst" className={`nav-item ${isActive('/analyst') ? 'active' : ''}`}>
          <LayoutDashboard size={20} />
          <span className="font-medium">Analyst Console</span>
          {isActive('/analyst') && <div className="ml-auto w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></div>}
        </Link>

        <div className="text-xs font-semibold text-slate-600 uppercase tracking-wider mb-4 px-2 mt-6">
          Monitoring
        </div>

        <Link to="/performance" className={`nav-item ${isActive('/performance') ? 'active' : ''}`}>
          <Activity size={20} />
          <span className="font-medium">System Metrics</span>
          {isActive('/performance') && <div className="ml-auto w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></div>}
        </Link>

        <Link to="/debug" className={`nav-item ${isActive('/debug') ? 'active' : ''}`}>
          <Terminal size={20} />
          <span className="font-medium">System Debug</span>
          {isActive('/debug') && <div className="ml-auto w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></div>}
        </Link>

        <div className="text-xs font-semibold text-slate-600 uppercase tracking-wider mb-4 px-2 mt-6">
          AI Insights
        </div>

        <Link to="/rag" className={`nav-item ${isActive('/rag') ? 'active' : ''}`}>
          <Database size={20} />
          <span className="font-medium">RAG Visualization</span>
          {isActive('/rag') && <div className="ml-auto w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></div>}
        </Link>

        <Link to="/transparency" className={`nav-item ${isActive('/transparency') ? 'active' : ''}`}>
          <Brain size={20} />
          <span className="font-medium">AI Transparency</span>
          {isActive('/transparency') && <div className="ml-auto w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></div>}
        </Link>
      </nav>

      {/* User Section */}

    </div>
  );
};

export default Sidebar;
