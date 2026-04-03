import { LayoutDashboard, Activity, Terminal, Database, Brain, LogOut, User, ChevronLeft, ChevronRight, Shield } from 'lucide-react';
import { useLocation, Link } from 'react-router-dom';

const navSections = [
  {
    label: 'Operations',
    items: [
      { path: '/analyst', icon: LayoutDashboard, label: 'Alert Triage', badge: null },
    ],
  },
  {
    label: 'Monitoring',
    items: [
      { path: '/performance', icon: Activity, label: 'System Metrics' },
      { path: '/debug', icon: Terminal, label: 'Live Debug' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { path: '/rag', icon: Database, label: 'RAG Knowledge' },
      { path: '/transparency', icon: Brain, label: 'AI Proof' },
    ],
  },
];

const Sidebar = ({ user, onLogout, collapsed, onToggle }) => {
  const location = useLocation();
  const isActive = (path) => location.pathname === path;

  return (
    <div
      className={`${collapsed ? 'w-[68px]' : 'w-64'} h-screen bg-sentinel-900/80 backdrop-blur-xl border-r border-sentinel-700/60 flex flex-col relative z-20 transition-all duration-300 ease-out`}
    >
      {/* Brand */}
      <div className={`p-4 ${collapsed ? 'px-3' : 'px-5'} border-b border-sentinel-700/40`}>
        <div className="flex items-center gap-3">
          <div className="relative flex-shrink-0">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyber-500 to-steel-500 flex items-center justify-center shadow-glow-cyber">
              <Shield className="w-5 h-5 text-white" strokeWidth={2.5} />
            </div>
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <h1 className="text-base font-bold tracking-tight text-sentinel-50 leading-tight">
                SENTINEL
              </h1>
              <div className="text-2xs text-sentinel-500 font-mono tracking-wider uppercase">
                AI-SOC Watchdog
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 overflow-y-auto s-scroll" aria-label="Primary navigation">
        {navSections.map((section) => (
          <div key={section.label} className="mb-4">
            {!collapsed && (
              <div className="s-section-label px-5 mb-2">{section.label}</div>
            )}
            <div className={`space-y-0.5 ${collapsed ? 'px-2' : 'px-3'}`}>
              {section.items.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  aria-label={collapsed ? item.label : undefined}
                  aria-current={isActive(item.path) ? 'page' : undefined}
                  className={`s-nav-item ${collapsed ? 'justify-center px-0' : ''} ${isActive(item.path) ? 'active' : ''}`}
                >
                  <item.icon size={18} className="flex-shrink-0" />
                  {!collapsed && <span>{item.label}</span>}
                  {!collapsed && isActive(item.path) && (
                    <div className="ml-auto s-dot-live" />
                  )}
                </Link>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Environment Indicator */}
      {!collapsed && (
        <div className="mx-4 mb-3 px-3 py-2 rounded-lg bg-status-live/5 border border-status-live/20">
          <div className="flex items-center gap-2">
            <div className="s-dot-live animate-pulse-slow" />
            <span className="text-2xs font-mono text-status-live tracking-wider uppercase">Systems Online</span>
          </div>
        </div>
      )}

      {/* User Section */}
      <div className={`border-t border-sentinel-700/40 ${collapsed ? 'p-2' : 'p-3'}`}>
        <div className={`flex items-center ${collapsed ? 'justify-center' : 'gap-3 px-2 py-2'}`}>
          <div className="w-8 h-8 rounded-lg bg-cyber-500/15 flex items-center justify-center flex-shrink-0">
            <User size={15} className="text-cyber-400" />
          </div>
          {!collapsed && (
            <>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-sentinel-100 truncate">{user?.username || 'Analyst'}</div>
                <div className="text-2xs text-sentinel-500">SOC Analyst</div>
              </div>
              <button
                onClick={onLogout}
                className="p-2.5 text-sentinel-400 hover:text-threat-critical hover:bg-threat-critical/10 rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400 min-w-[44px] min-h-[44px] flex items-center justify-center"
                aria-label="Logout"
              >
                <LogOut size={15} />
              </button>
            </>
          )}
        </div>
      </div>

      {/* Collapse Toggle */}
      <button
        onClick={onToggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="absolute -right-3 top-1/2 -translate-y-1/2 w-7 h-7 bg-sentinel-800 border border-sentinel-700 rounded-full flex items-center justify-center text-sentinel-400 hover:text-sentinel-200 hover:bg-sentinel-700 transition-colors z-30 shadow-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400"
      >
        {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
      </button>
    </div>
  );
};

export default Sidebar;
