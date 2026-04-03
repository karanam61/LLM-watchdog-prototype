import { useState } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Sidebar from './components/Sidebar';

import AnalystDashboard from './pages/AnalystDashboard';
import PerformanceDashboard from './pages/PerformanceDashboard';
import DebugDashboard from './pages/DebugDashboard';
import RAGDashboard from './pages/RAGDashboard';
import TransparencyDashboard from './pages/TransparencyDashboard';

const pageVariants = {
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.25, ease: [0.25, 0.1, 0.25, 1] } },
  exit: { opacity: 0, y: -4, transition: { duration: 0.15 } },
};

function AnimatedPage({ children }) {
  return (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
      className="h-full"
    >
      {children}
    </motion.div>
  );
}

function App() {
  const location = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const user = { username: 'analyst', role: 'analyst' };

  const handleLogout = () => {
    console.log('Auth disabled for demo');
  };

  return (
    <div className="flex bg-sentinel-950 min-h-screen text-sentinel-50 font-sans antialiased overflow-hidden">
      {/* Ambient gradient — subtle, not overwhelming */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] bg-cyber-500/[0.03] rounded-full blur-[120px]" />
        <div className="absolute -bottom-40 -right-40 w-[500px] h-[500px] bg-steel-500/[0.02] rounded-full blur-[120px]" />
        <div className="absolute inset-0 bg-grid opacity-40" />
      </div>

      <Sidebar
        user={user}
        onLogout={handleLogout}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      <main className="flex-1 overflow-hidden relative z-10">
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            <Route path="/" element={<Navigate to="/analyst" replace />} />
            <Route path="/analyst" element={<AnimatedPage><AnalystDashboard /></AnimatedPage>} />
            <Route path="/performance" element={<AnimatedPage><PerformanceDashboard /></AnimatedPage>} />
            <Route path="/debug" element={<AnimatedPage><DebugDashboard /></AnimatedPage>} />
            <Route path="/rag" element={<AnimatedPage><RAGDashboard /></AnimatedPage>} />
            <Route path="/transparency" element={<AnimatedPage><TransparencyDashboard /></AnimatedPage>} />
            <Route path="*" element={<Navigate to="/analyst" replace />} />
          </Routes>
        </AnimatePresence>
      </main>
    </div>
  );
}

export default App;
