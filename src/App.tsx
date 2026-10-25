import React, { useState, useEffect } from 'react';
import { DoorDashboard } from './components/DoorDashboard';
import { OwnerConsole } from './components/OwnerConsole';
import { OfflineAssessmentTool } from './components/OfflineAssessmentTool';
import { ToastProvider, useToast } from './components/Toast';
import { securityEngine, PQC_PROFILES } from './services/securityEngine';

type TabView = 'door' | 'owner' | 'offline_tool';

const AppContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabView>('door');
  const [hwOnline, setHwOnline] = useState(securityEngine.getDeviceTelemetry().is_online);
  const [hwIp, setHwIp] = useState(securityEngine.getDeviceTelemetry().ip_address);
  const [risk, setRisk] = useState(securityEngine.getRiskLevel());
  const { showToast } = useToast();

  useEffect(() => {
    const update = () => {
      const telem = securityEngine.getDeviceTelemetry();
      setHwOnline(telem.is_online);
      setHwIp(telem.ip_address);
      setRisk(securityEngine.getRiskLevel());
    };

    update();
    const unsub = securityEngine.subscribe(update);
    return () => {
      unsub();
    };
  }, []);

  const toggleHw = () => {
    securityEngine.toggleHardwareStatus();
    showToast(`Simulated ESP8266 Node toggled to ${!hwOnline ? 'ONLINE' : 'OFFLINE'}`, 'info');
  };

  const activePqc = PQC_PROFILES[risk];

  return (
    <div>
      {/* Top Navigation */}
      <nav className="navbar">
        <div className="nav-brand">
          <div className="brand-icon">🛡️</div>
          <div>
            <div className="brand-title">Agentic AI • Adaptive PQC Smart Door Lock</div>
            <div className="brand-sub">NIST Quantum-Resistant IoT Security Simulation & ESP8266 Hardware Node</div>
          </div>
        </div>
        <div className="nav-badges">
          <button
            className={`badge ${hwOnline ? 'badge-online' : 'badge-offline'}`}
            onClick={toggleHw}
            title="Click to toggle ESP8266 hardware node online/offline simulation"
            style={{ background: 'none', border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            <span style={{ fontSize: '10px' }}>●</span> ESP8266: {hwOnline ? `ONLINE (${hwIp})` : 'OFFLINE'}
          </button>
          <div className="badge badge-pqc">
            🔐 {activePqc.kem} / {activePqc.signature}
          </div>
          <button
            className={`nav-link ${activeTab === 'door' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('door')}
          >
            Door Control
          </button>
          <button
            className={`nav-link ${activeTab === 'owner' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('owner')}
          >
            Owner Console ➔
          </button>
          <button
            className={`nav-link ${activeTab === 'offline_tool' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('offline_tool')}
          >
            CICIoT Tool
          </button>
        </div>
      </nav>

      {/* Main View Delivery */}
      <main>
        {activeTab === 'door' && <DoorDashboard onNavigateToOwner={() => setActiveTab('owner')} />}
        {activeTab === 'owner' && <OwnerConsole onNavigateToDoor={() => setActiveTab('door')} />}
        {activeTab === 'offline_tool' && <OfflineAssessmentTool onNavigateToOwner={() => setActiveTab('owner')} />}
      </main>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
};

export default App;
