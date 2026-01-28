import { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar';

import AnalystDashboard from './pages/AnalystDashboard';
import PerformanceDashboard from './pages/PerformanceDashboard';
import DebugDashboard from './pages/DebugDashboard';
import RAGDashboard from './pages/RAGDashboard';
import TransparencyDashboard from './pages/TransparencyDashboard';

function App() {
  const location = useLocation();

  // Demo user (auth disabled for hosting)
  const user = { username: 'analyst', role: 'analyst' };

  const handleLogout = () => {
    // Auth disabled - logout does nothing
    console.log('Auth disabled for demo');
  };

  return (
    <div className="flex bg-slate-950 min-h-screen text-slate-100 font-sans antialiased overflow-hidden">
      <Sidebar user={user} onLogout={handleLogout} />

      <div className="flex-1 overflow-auto relative">
        {/* Background Ambient Glow */}
        <div className="absolute top-0 left-0 w-full h-96 bg-cyan-900/10 blur-[100px] pointer-events-none" />

        <Routes>
          {/* Default to Analyst Dashboard */}
          <Route path="/" element={<Navigate to="/analyst" replace />} />

          {/* All Routes (No Auth Required) */}
          <Route path="/analyst" element={<AnalystDashboard />} />
          <Route path="/performance" element={<PerformanceDashboard />} />
          <Route path="/debug" element={<DebugDashboard />} />
          <Route path="/rag" element={<RAGDashboard />} />
          <Route path="/transparency" element={<TransparencyDashboard />} />

          {/* Catch all */}
          <Route path="*" element={<Navigate to="/analyst" replace />} />
        </Routes>
      </div>
    </div>
  );
}

export default App;
