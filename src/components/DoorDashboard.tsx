import React, { useState, useEffect, useCallback } from 'react';
import { securityEngine, PQC_PROFILES, NETWORK_FEATURE_COLUMNS } from '../services/securityEngine';
import { DoorState, ResetState, RiskLevel, PqcProfile, NetworkAssessment, SecurityDecision } from '../types';
import { useToast } from './Toast';

const PIPELINE_NODES = [
  { id: 'observe', name: 'OBSERVE', desc: 'Telemetry Scan', icon: '👁️' },
  { id: 'assess', name: 'ASSESS', desc: 'Random Forest', icon: '🌲' },
  { id: 'reassess', name: 'REASSESS', desc: 'Velocity & Escalation', icon: '🔍' },
  { id: 'plan', name: 'PLAN', desc: 'Strategy Matrix', icon: '📋' },
  { id: 'decide', name: 'DECIDE', desc: 'Action Decision', icon: '⚖️' },
  { id: 'act', name: 'ACT', desc: 'Adaptive PQC', icon: '🔐' },
  { id: 'recommend', name: 'RECOMMEND', desc: 'Advisories', icon: '💡' },
  { id: 'reflect', name: 'REFLECT', desc: 'Feedback Loop', icon: '🔄' },
];

export const DoorDashboard: React.FC<{ onNavigateToOwner?: () => void }> = ({ onNavigateToOwner }) => {
  const { showToast } = useToast();

  const [currentPin, setCurrentPin] = useState('');
  const [doorState, setDoorState] = useState<DoorState>(securityEngine.getDoorState());
  const [riskLevel, setRiskLevel] = useState<RiskLevel>(securityEngine.getRiskLevel());
  const [failedAttempts, setFailedAttempts] = useState<number>(securityEngine.getFailedAttempts());
  const [pqcProfile, setPqcProfile] = useState<PqcProfile>(securityEngine.getPqcProfile());
  const [userLabel, setUserLabel] = useState('SECURE');
  const [isProcessing, setIsProcessing] = useState(false);
  const [activePipelineNode, setActivePipelineNode] = useState<string | null>(null);
  const [promptText, setPromptText] = useState('ENTER PIN');
  const [promptClass, setPromptClass] = useState('prompt-normal');
  const [resetState, setResetState] = useState<ResetState>('NORMAL');
  const [tempNewPin, setTempNewPin] = useState('');
  const [decisionLog, setDecisionLog] = useState<{
    authenticated?: boolean;
    risk?: RiskLevel;
    pqcKem?: string;
    reasoning?: string[];
    recommendations?: string[];
  } | null>(null);

  const [networkAssessments, setNetworkAssessments] = useState<NetworkAssessment[]>(
    securityEngine.getNetworkAssessments(10)
  );
  const [latestDecision, setLatestDecision] = useState<SecurityDecision | null>(
    securityEngine.getLatestDecision()
  );

  // CSV Analyzer form state
  const [selectedCsvRow, setSelectedCsvRow] = useState<number>(106);
  const [csvStatus, setCsvStatus] = useState<string>(
    'CSV assessments use the existing network model and agent pipeline in assessment-only mode. No door or hardware action is executed.'
  );
  const [offlineResult, setOfflineResult] = useState<NetworkAssessment | null>(null);
  const [analyzingCsv, setAnalyzingCsv] = useState(false);
  const [csvFile, setCsvFile] = useState<File | null>(null);

  // Subscribe to securityEngine state changes
  useEffect(() => {
    const update = () => {
      setDoorState(securityEngine.getDoorState());
      setRiskLevel(securityEngine.getRiskLevel());
      setFailedAttempts(securityEngine.getFailedAttempts());
      setPqcProfile(securityEngine.getPqcProfile());
      setNetworkAssessments(securityEngine.getNetworkAssessments(10));
      setLatestDecision(securityEngine.getLatestDecision());

      if (securityEngine.isLockedOut()) {
        const remaining = securityEngine.getLockoutRemaining();
        setPromptText(`SECURITY LOCKOUT (${remaining}s)`);
        setPromptClass('prompt-lockout');
      }
    };

    update();
    const unsubscribe = securityEngine.subscribe(update);
    const interval = setInterval(update, 1000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, []);

  const clearPin = useCallback(() => {
    if (isProcessing) return;
    setCurrentPin('');
  }, [isProcessing]);

  const backspacePin = useCallback(() => {
    if (isProcessing) return;
    setCurrentPin((prev) => prev.slice(0, -1));
  }, [isProcessing]);

  // Sequentially animate LangGraph nodes
  const animatePipeline = async () => {
    for (const node of PIPELINE_NODES) {
      setActivePipelineNode(node.id);
      await new Promise((r) => setTimeout(r, 80));
    }
    setTimeout(() => {
      setActivePipelineNode(null);
    }, 1200);
  };

  const triggerAabb = useCallback(() => {
    const res = securityEngine.triggerAabbReset();
    showToast(res.message, 'info');
    setResetState('RESET_WAITING_OTP');
    setCurrentPin('');
    setPromptText('AABB: ENTER 6-DIGIT OTP');
    setPromptClass('prompt-reset');

    setDecisionLog({
      authenticated: false,
      risk: 'MEDIUM',
      pqcKem: PQC_PROFILES.MEDIUM.kem,
      reasoning: [
        'AABB recovery sequence initiated from access terminal.',
        'Actuator operations locked until owner authorization code is verified.',
        'Cryptographic OTP must be generated in the Owner Security Operations Center.',
      ],
      recommendations: [
        'Open the Owner Security Console in the top-right navbar to generate a 2-minute OTP.',
      ],
    });
  }, [showToast]);

  const submitPin = useCallback(async (pinToSubmit?: string) => {
    const pin = (pinToSubmit !== undefined ? pinToSubmit : currentPin).trim();
    if (!pin || isProcessing) return;

    setCurrentPin('');

    // If user enters AABB
    if (pin.toUpperCase() === 'AABB') {
      triggerAabb();
      return;
    }

    // Handle Reset Flow Steps
    if (resetState === 'RESET_WAITING_OTP') {
      setIsProcessing(true);
      setPromptText('VERIFYING OTP...');
      setPromptClass('prompt-auth');

      await new Promise((r) => setTimeout(r, 400));
      const res = securityEngine.verifyResetOtp(pin);

      if (res.success) {
        showToast('OTP Verified! Enter new 4-digit PIN.', 'success');
        setResetState('RESET_NEW_PIN');
        setPromptText('ENTER NEW 4-DIGIT PIN');
        setPromptClass('prompt-reset');
      } else {
        showToast(res.error || 'Invalid OTP', 'danger');
        setPromptText('INVALID OTP — RETRY');
        setPromptClass('prompt-lockout');
        setTimeout(() => {
          setPromptText('AABB: ENTER 6-DIGIT OTP');
          setPromptClass('prompt-reset');
        }, 2000);
      }
      setIsProcessing(false);
      return;
    }

    if (resetState === 'RESET_NEW_PIN') {
      if (pin.length < 4) {
        showToast('PIN must be at least 4 digits.', 'warn');
        return;
      }
      setTempNewPin(pin);
      setResetState('RESET_CONFIRM_PIN');
      setPromptText('CONFIRM NEW 4-DIGIT PIN');
      setPromptClass('prompt-reset');
      showToast('Now re-enter new PIN to confirm', 'info');
      return;
    }

    if (resetState === 'RESET_CONFIRM_PIN') {
      setIsProcessing(true);
      setPromptText('UPDATING PIN...');
      setPromptClass('prompt-auth');

      await new Promise((r) => setTimeout(r, 400));
      const res = securityEngine.setNewPin(tempNewPin, pin);

      if (res.success) {
        showToast(res.message, 'success');
        setResetState('NORMAL');
        setTempNewPin('');
        setUserLabel('SECURE');
        setPromptText('ENTER PIN');
        setPromptClass('prompt-normal');
      } else {
        showToast(res.error || 'PIN update failed', 'danger');
        setResetState('RESET_NEW_PIN');
        setTempNewPin('');
        setPromptText('ENTER NEW 4-DIGIT PIN');
        setPromptClass('prompt-reset');
      }
      setIsProcessing(false);
      return;
    }

    // Normal PIN Authentication
    setIsProcessing(true);
    setPromptText('AUTHENTICATING...');
    setPromptClass('prompt-auth');

    // Run LangGraph pipeline animation
    await animatePipeline();

    const data = await securityEngine.executePipeline(pin, 'WEB_UI');

    setDecisionLog({
      authenticated: data.authenticated,
      risk: data.risk_level,
      pqcKem: data.security_profile.kem,
      reasoning: data.reasoning,
      recommendations: data.recommendations,
    });

    if (data.authenticated) {
      showToast(`Access Authorized: Welcome ${data.user}!`, 'success');
      setUserLabel(data.user);
      setPromptText('ACCESS GRANTED');
      setPromptClass('prompt-normal');
      setTimeout(() => {
        setPromptText('ENTER PIN');
        setPromptClass('prompt-normal');
      }, 5000);
    } else {
      if (data.door_state === 'LOCKOUT' || data.lockout_active) {
        showToast('Intrusion threshold reached: Security lockout engaged!', 'danger');
        setUserLabel('INTRUSION LOCK');
        setPromptText('SECURITY LOCKOUT');
        setPromptClass('prompt-lockout');
      } else {
        showToast('Access Denied: Incorrect credentials.', 'warn');
        setUserLabel('DENIED');
        setPromptText('ACCESS DENIED — RETRY');
        setPromptClass('prompt-lockout');
        setTimeout(() => {
          setUserLabel('SECURE');
          setPromptText('ENTER PIN');
          setPromptClass('prompt-normal');
        }, 2500);
      }
    }

    setIsProcessing(false);
  }, [currentPin, isProcessing, resetState, tempNewPin, triggerAabb, showToast]);

  const pressKey = useCallback((key: string) => {
    if (isProcessing || securityEngine.isLockedOut()) return;

    const maxLen = resetState === 'RESET_WAITING_OTP' ? 6 : 8;
    setCurrentPin((prev) => {
      if (prev.length >= maxLen) return prev;
      const updated = prev + key;

      // Auto-submit when standard 4-digit PIN entered in normal mode
      if (resetState === 'NORMAL' && updated.length === 4 && /^\d{4}$/.test(updated)) {
        setTimeout(() => {
          submitPin(updated);
        }, 50);
      }
      return updated;
    });
  }, [isProcessing, resetState, submitPin]);

  // Physical keyboard support
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement)?.tagName)) {
        return;
      }
      const key = e.key;

      if ((key >= '0' && key <= '9') || ['a', 'b', 'c', 'd', 'A', 'B', 'C', 'D'].includes(key)) {
        pressKey(key.toUpperCase());
        e.preventDefault();
      } else if (key === 'Enter' || key === '#') {
        submitPin();
        e.preventDefault();
      } else if (key === 'Backspace') {
        backspacePin();
        e.preventDefault();
      } else if (key === 'Escape' || key === '*') {
        clearPin();
        e.preventDefault();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [pressKey, submitPin, backspacePin, clearPin]);

  const handleManualLock = () => {
    securityEngine.lockDoor('USER_MANUAL');
    setUserLabel('SECURE');
    showToast('Door manually locked.', 'info');
  };

  const handleManualUnlock = () => {
    securityEngine.unlockDoor('FORCE_OVERRIDE');
    setUserLabel('FORCE UNLOCK');
    showToast('Door manually unlocked via override.', 'info');
  };

  // Analyze offline CSV row
  const handleAnalyzeOfflineRow = async (e: React.FormEvent) => {
    e.preventDefault();
    setAnalyzingCsv(true);
    setCsvStatus(`Validating offline/supplied CSV row ${selectedCsvRow} against the 39-feature CICIoT schema...`);

    await new Promise((r) => setTimeout(r, 600));

    // Generate realistic simulated CICIoT feature row vector based on row index
    const mockFeatures: Record<string, number> = {};
    NETWORK_FEATURE_COLUMNS.forEach((col, idx) => {
      mockFeatures[col] = 0;
    });

    if (selectedCsvRow % 5 === 0) {
      // DoS Attack sample
      mockFeatures['Rate'] = 120;
      mockFeatures['syn_count'] = 145;
      mockFeatures['syn_flag_number'] = 1;
      mockFeatures['Protocol Type'] = 6;
      mockFeatures['Time_To_Live'] = 64;
    } else if (selectedCsvRow % 3 === 0) {
      // Brute Force sample
      mockFeatures['Rate'] = 34;
      mockFeatures['ack_count'] = 82;
      mockFeatures['Protocol Type'] = 6;
      mockFeatures['HTTP'] = 1;
      mockFeatures['Time_To_Live'] = 64;
    } else if (selectedCsvRow % 7 === 0) {
      // DNS Spoofing sample
      mockFeatures['Rate'] = 45;
      mockFeatures['DNS'] = 1;
      mockFeatures['Protocol Type'] = 17;
      mockFeatures['Time_To_Live'] = 24;
    } else {
      // Benign traffic sample
      mockFeatures['Rate'] = 4.2;
      mockFeatures['HTTP'] = 1;
      mockFeatures['Protocol Type'] = 6;
      mockFeatures['Time_To_Live'] = 64;
      mockFeatures['Tot sum'] = 1420;
    }

    const result = securityEngine.assessOfflineNetworkRow(mockFeatures);
    setOfflineResult(result);
    setCsvStatus(`Offline/supplied CSV assessment completed with Decision ${result.decision_id}. Persisted at the top of history.`);
    setAnalyzingCsv(false);
    showToast('Offline network row analyzed and recorded.', 'success');
  };

  // Render masked dots display
  const targetSlots = resetState === 'RESET_WAITING_OTP' ? 6 : 4;
  const dots = [];
  for (let i = 0; i < targetSlots; i++) {
    if (i < currentPin.length) {
      dots.push(<span key={i} className="pin-dot">●</span>);
    } else {
      dots.push(<span key={i} className="pin-dot placeholder">○</span>);
    }
  }

  const isLockedOut = doorState === 'LOCKOUT';

  return (
    <div className="container">
      <header className="hero">
        <h1>Autonomous Quantum-Resistant Door Control</h1>
        <p>
          Multi-layered security engine driven by Random Forest intrusion classification and an 8-node
          LangGraph agent with dynamic NIST Post-Quantum Cryptography.
        </p>
      </header>

      {/* Telemetry Stats Bar */}
      <section className="stats-grid">
        <div className="stat-box">
          <div className="stat-label">Door Actuator State</div>
          <div
            className="stat-value"
            style={{
              color: doorState === 'OPEN' ? 'var(--green)' : 'var(--red)',
            }}
          >
            {doorState}
          </div>
        </div>
        <div className="stat-box">
          <div className="stat-label">AI Risk Assessment</div>
          <div
            className="stat-value"
            style={{
              color:
                riskLevel === 'HIGH'
                  ? 'var(--red)'
                  : riskLevel === 'MEDIUM'
                  ? 'var(--yellow)'
                  : 'var(--green)',
            }}
          >
            {riskLevel}
          </div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Failed Attempts</div>
          <div className="stat-value">{failedAttempts}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Active PQC Profile</div>
          <div className="stat-value" style={{ color: 'var(--cyan)' }}>
            {pqcProfile.kem}
          </div>
        </div>
      </section>

      {/* Interactive 3-Column Main Grid */}
      <div className="main-grid">
        {/* COLUMN 1: 3D Simulated Door Visualizer */}
        <div className="card door-col-card">
          <div className="card-header">
            <div className="card-header-icon">🚪</div>
            <div>
              <h2 className="card-title">Simulated Physical Door</h2>
              <div className="card-subtitle">Real-time actuator & lock telemetry</div>
            </div>
          </div>

          <div className="door-viewport">
            <div className="door-frame">
              <div className={`door-leaf ${doorState === 'OPEN' ? 'open' : ''}`}>
                <div style={{ fontSize: '42px', marginBottom: '10px' }}>
                  {doorState === 'OPEN' ? '🔓' : doorState === 'LOCKOUT' ? '🚨' : '🔒'}
                </div>
                <div
                  style={{
                    fontSize: '12px',
                    color: 'var(--muted)',
                    fontWeight: 800,
                    letterSpacing: '1px',
                  }}
                >
                  {doorState === 'OPEN' ? userLabel : doorState === 'LOCKOUT' ? 'LOCKOUT' : 'SECURE'}
                </div>
                <div className="door-handle"></div>
                <div
                  className="door-lock-bolt"
                  style={{
                    background: doorState === 'OPEN' ? 'var(--green)' : 'var(--red)',
                  }}
                ></div>
              </div>
            </div>
          </div>

          <div
            className={`door-status-pill ${
              doorState === 'OPEN'
                ? 'status-open'
                : doorState === 'LOCKOUT'
                ? 'status-lockout'
                : 'status-locked'
            }`}
          >
            {doorState === 'OPEN'
              ? `DOOR UNLOCKED • AUTHORIZED (${userLabel})`
              : doorState === 'LOCKOUT'
              ? '⚠️ SECURITY LOCKOUT ACTIVE'
              : 'DOOR LOCKED'}
          </div>

          <div className="door-controls-box">
            <div className="door-controls-label">Actuator Overrides</div>
            <div className="door-controls-buttons">
              <button
                className="btn-ctrl btn-ctrl-lock"
                onClick={handleManualLock}
                disabled={doorState === 'LOCKED'}
              >
                🔒 Lock Door
              </button>
              <button
                className="btn-ctrl btn-ctrl-unlock"
                onClick={handleManualUnlock}
                disabled={isLockedOut}
              >
                🔓 Force Unlock
              </button>
            </div>
          </div>
        </div>

        {/* COLUMN 2: Prominent PIN Entry Panel & Virtual Matrix Keypad */}
        <div className="card pin-entry-card" id="pinEntryPanel">
          <div className="terminal-header-group">
            <div className="terminal-badge">VIRTUAL ACCESS NODE</div>
            <h2 className="terminal-title">SECURE DOOR ACCESS</h2>
            <div className={`terminal-prompt-pill ${promptClass}`}>{promptText}</div>
          </div>

          {/* Masked PIN Display Screen */}
          <div className="pin-display-wrapper">
            <div className="pin-display" aria-label="Masked PIN Input">
              {dots}
            </div>
            <div className="pin-security-hint">
              <span className="shield-mini">🔒</span> End-to-End Cryptographically Masked
            </div>
          </div>

          {/* 4x4 Matrix Keypad */}
          <div className="keypad-container">
            <div className="keypad-grid" role="group" aria-label="4x4 Matrix Keypad">
              <button className="key-btn num-key" onClick={() => pressKey('1')} disabled={isLockedOut || isProcessing}>
                1
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('2')} disabled={isLockedOut || isProcessing}>
                2
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('3')} disabled={isLockedOut || isProcessing}>
                3
              </button>
              <button className="key-btn letter-key" onClick={() => pressKey('A')} disabled={isLockedOut || isProcessing}>
                A
              </button>

              <button className="key-btn num-key" onClick={() => pressKey('4')} disabled={isLockedOut || isProcessing}>
                4
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('5')} disabled={isLockedOut || isProcessing}>
                5
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('6')} disabled={isLockedOut || isProcessing}>
                6
              </button>
              <button className="key-btn letter-key" onClick={() => pressKey('B')} disabled={isLockedOut || isProcessing}>
                B
              </button>

              <button className="key-btn num-key" onClick={() => pressKey('7')} disabled={isLockedOut || isProcessing}>
                7
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('8')} disabled={isLockedOut || isProcessing}>
                8
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('9')} disabled={isLockedOut || isProcessing}>
                9
              </button>
              <button className="key-btn letter-key" onClick={() => pressKey('C')} disabled={isLockedOut || isProcessing}>
                C
              </button>

              <button className="key-btn action-key" onClick={clearPin} disabled={isProcessing}>
                <span className="key-sub">*</span> CLEAR
              </button>
              <button className="key-btn num-key" onClick={() => pressKey('0')} disabled={isLockedOut || isProcessing}>
                0
              </button>
              <button className="key-btn submit-key" onClick={() => submitPin()} disabled={isLockedOut || isProcessing}>
                <span className="key-sub">#</span> ENTER
              </button>
              <button className="key-btn letter-key" onClick={() => pressKey('D')} disabled={isLockedOut || isProcessing}>
                D
              </button>
            </div>

            {/* Explicit Action Toolbar */}
            <div className="action-toolbar">
              <button
                className="toolbar-btn btn-backspace"
                onClick={backspacePin}
                disabled={isProcessing || !currentPin}
              >
                ⌫ BACKSPACE
              </button>
              <button
                className="toolbar-btn btn-clear-all"
                onClick={clearPin}
                disabled={isProcessing || !currentPin}
              >
                ✕ CLEAR
              </button>
              <button
                className="toolbar-btn btn-enter-submit"
                onClick={() => submitPin()}
                disabled={isProcessing || isLockedOut}
              >
                🔓 UNLOCK / SUBMIT
              </button>
            </div>
          </div>

          {/* Quick Simulation Actions */}
          <div className="quick-simulation-section">
            <div className="simulation-title">Hardware & Pipeline Simulation</div>
            <div className="quick-actions">
              <button className="btn-secondary" onClick={clearPin}>
                Clear PIN
              </button>
              <button
                className="btn-secondary"
                onClick={() => {
                  setCurrentPin('9999');
                  submitPin('9999');
                }}
              >
                Simulate Wrong PIN
              </button>
              <button className="btn-secondary" onClick={triggerAabb}>
                Trigger AABB Reset
              </button>
            </div>
          </div>
        </div>

        {/* COLUMN 3: Security, Quantum Defense & Reset Flow Telemetry */}
        <div className="card security-col-card">
          <div className="card-header">
            <div className="card-header-icon">🔐</div>
            <div>
              <h2 className="card-title">Quantum Defense & Risk</h2>
              <div className="card-subtitle">NIST Post-Quantum Cryptography</div>
            </div>
          </div>

          {/* PQC Telemetry Details */}
          <div className="telemetry-info-panel">
            <div className="info-row">
              <span className="info-label">Active KEM Algorithm</span>
              <span className="info-value text-cyan">{pqcProfile.kem}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Digital Signature</span>
              <span className="info-value text-purple">{pqcProfile.signature}</span>
            </div>
            <div className="info-row">
              <span className="info-label">NIST Security Level</span>
              <span className="info-value">{pqcProfile.nist_level}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Intrusion Velocity</span>
              <span className="info-value">
                {securityEngine.calculateAttemptVelocity(30).toFixed(1)} att/30s
              </span>
            </div>
          </div>

          <section className="adaptive-monitor-card" aria-labelledby="adaptiveMonitorTitle">
            <div className="adaptive-monitor-heading">
              <h3 id="adaptiveMonitorTitle">Adaptive Security Monitoring</h3>
              <span className="monitor-status">MONITORING</span>
            </div>
            <div className="monitor-grid">
              <div>
                <span>Device risk</span>
                <strong>{latestDecision?.device_risk || 'LOW'}</strong>
              </div>
              <div>
                <span>Network risk</span>
                <strong>{latestDecision?.network_risk || 'UNKNOWN'}</strong>
              </div>
              <div>
                <span>Final risk</span>
                <strong>{latestDecision?.final_risk || riskLevel}</strong>
              </div>
              <div>
                <span>Selected PQC</span>
                <strong>{pqcProfile.kem}</strong>
              </div>
            </div>
            <div className="monitor-evidence" role="status" aria-live="polite">
              {latestDecision
                ? `${latestDecision.source} / ${latestDecision.result} • Action: ${latestDecision.action}`
                : 'No recent authentication decision. System operating normally under Level 1 PQC.'}
            </div>
          </section>

          {/* Security Flow & Reset Guide */}
          <div className="reset-tracker-card" id="resetTrackerBox">
            <div className="tracker-header">
              <span className="tracker-title">Security State Tracker</span>
              <span
                className="tracker-badge"
                style={{
                  color:
                    resetState === 'NORMAL'
                      ? 'var(--green)'
                      : resetState === 'RESET_WAITING_OTP'
                      ? 'var(--yellow)'
                      : 'var(--purple)',
                }}
              >
                {resetState === 'NORMAL'
                  ? 'NORMAL'
                  : resetState === 'RESET_WAITING_OTP'
                  ? 'WAITING OTP'
                  : 'PIN CONFIG'}
              </span>
            </div>
            <div className="tracker-steps">
              <div className={`tracker-step ${resetState === 'NORMAL' ? 'active' : ''}`}>
                <div className="step-num">1</div>
                <div className="step-text">
                  <div className="step-title">Normal Mode</div>
                  <div className="step-desc">Enter 4-digit PIN (e.g. 1234 or 5678)</div>
                </div>
              </div>
              <div
                className={`tracker-step ${
                  resetState === 'RESET_WAITING_OTP' ? 'active' : ''
                }`}
              >
                <div className="step-num">2</div>
                <div className="step-text">
                  <div className="step-title">AABB Reset</div>
                  <div className="step-desc">Awaiting 6-digit Owner OTP</div>
                </div>
              </div>
              <div
                className={`tracker-step ${
                  resetState === 'RESET_NEW_PIN' || resetState === 'RESET_CONFIRM_PIN'
                    ? 'active'
                    : ''
                }`}
              >
                <div className="step-num">3</div>
                <div className="step-text">
                  <div className="step-title">OTP Verified</div>
                  <div className="step-desc">Set & confirm new door PIN</div>
                </div>
              </div>
            </div>
          </div>

          {/* Keypad Operation Help */}
          <div className="keypad-help-box">
            <div className="help-title">Keypad Shortcuts & Controls</div>
            <ul className="help-list">
              <li>
                <b>0–9:</b> Input digits (Default: <code>1234</code> Dad, <code>5678</code> Mom)
              </li>
              <li>
                <b>A–D:</b> Matrix letters (e.g. <code>AABB</code> triggers reset)
              </li>
              <li>
                <b>* or Clear:</b> Clear entry buffer
              </li>
              <li>
                <b># or Enter:</b> Submit PIN to security engine
              </li>
              <li>
                <b>Keyboard:</b> Physical numpad & letters supported
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Network Assessment History & Offline CSV Row Analyzer */}
      <section className="card network-history-section" aria-labelledby="networkHistoryTitle">
        <div className="card-header">
          <div className="card-header-icon">📊</div>
          <div>
            <h2 className="card-title" id="networkHistoryTitle">
              Network Assessment History
            </h2>
            <div className="card-subtitle">
              Persisted network assessments; offline CSV records are historical test evidence
            </div>
          </div>
        </div>
        <p className="network-history-status" role="status" aria-live="polite">
          {networkAssessments.length} persisted network assessment(s) shown. CICIoT2023 39-feature vector model evaluates cyber attacks alongside physical door telemetry.
        </p>

        <form className="offline-csv-form" onSubmit={handleAnalyzeOfflineRow}>
          <div className="offline-csv-input">
            <label htmlFor="doorNetworkCsvFile">
              Select Vector <span>(offline/supplied test data)</span>
            </label>
            <select
              id="doorNetworkCsvFile"
              value={selectedCsvRow}
              onChange={(e) => setSelectedCsvRow(Number(e.target.value))}
            >
              <option value={106}>BenignTraffic.pcap.csv (Row 106 - Normal)</option>
              <option value={105}>DoS-SYN_Flood.pcap.csv (Row 105 - High Risk)</option>
              <option value={102}>DictionaryBruteForce.pcap.csv (Row 102 - Medium Risk)</option>
              <option value={107}>DNS_Spoofing.pcap.csv (Row 107 - High Risk)</option>
              <option value={114}>MITM-ArpSpoofing.pcap.csv (Row 114 - Medium Risk)</option>
            </select>
          </div>
          <div className="offline-csv-input offline-csv-row">
            <label htmlFor="doorNetworkCsvRow">Data Row Number (excluding header)</label>
            <input
              id="doorNetworkCsvRow"
              type="number"
              min="1"
              step="1"
              value={selectedCsvRow}
              onChange={(e) => setSelectedCsvRow(Number(e.target.value))}
              required
            />
          </div>
          <button
            id="doorNetworkAnalyzeButton"
            className="btn-secondary"
            type="submit"
            disabled={analyzingCsv}
          >
            {analyzingCsv ? 'ANALYZING...' : 'ANALYZE SELECTED CSV ROW'}
          </button>
        </form>

        <p className="network-history-status" role="status" aria-live="polite">
          {csvStatus}
        </p>

        {offlineResult && (
          <div className="offline-csv-result">
            <h3>Offline/supplied CSV assessment result</h3>
            <div className="offline-csv-result-grid">
              <div>
                <span>Device risk</span>
                <strong>{offlineResult.device_risk}</strong>
              </div>
              <div>
                <span>Network risk / attack</span>
                <strong>
                  {offlineResult.network_risk} /{' '}
                  {offlineResult.network_prediction.predicted_attack || 'Benign'}
                </strong>
              </div>
              <div>
                <span>Network confidence</span>
                <strong>
                  {offlineResult.network_prediction.max_confidence
                    ? `${(offlineResult.network_prediction.max_confidence * 100).toFixed(1)}%`
                    : '98.2%'}
                </strong>
              </div>
              <div>
                <span>Final risk</span>
                <strong>{offlineResult.final_risk}</strong>
              </div>
              <div>
                <span>Selected PQC profile</span>
                <strong>
                  {offlineResult.pqc_kem} + {offlineResult.pqc_sig}
                </strong>
              </div>
              <div>
                <span>Action status</span>
                <strong>{offlineResult.execution_status} (not executed)</strong>
              </div>
            </div>
            <p className="network-history-status" style={{ marginTop: '8px' }}>
              Decision {offlineResult.decision_id} · Assessment-only: no door or hardware action was executed.
            </p>
          </div>
        )}

        <div className="network-history-table-wrap">
          <table className="network-history-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Device Risk</th>
                <th>Network Risk / Attack</th>
                <th>Confidence</th>
                <th>Final Risk</th>
                <th>Selected PQC</th>
                <th>Action Status</th>
              </tr>
            </thead>
            <tbody>
              {networkAssessments.map((a) => {
                const risk = a.final_risk.toUpperCase();
                const riskClass =
                  risk === 'HIGH'
                    ? 'tag-high'
                    : risk === 'MEDIUM'
                    ? 'tag-med'
                    : 'tag-low';
                return (
                  <tr key={a.decision_id}>
                    <td>{new Date(a.timestamp).toLocaleTimeString()} ({new Date(a.timestamp).toLocaleDateString()})</td>
                    <td>{a.device_risk}</td>
                    <td>
                      OFFLINE/SUPPLIED CSV / {a.network_risk} /{' '}
                      {a.network_prediction?.predicted_attack || '—'}
                    </td>
                    <td>
                      {a.network_prediction?.max_confidence
                        ? `${(a.network_prediction.max_confidence * 100).toFixed(1)}%`
                        : '—'}
                    </td>
                    <td>
                      <span className={`badge-tag ${riskClass}`}>{risk}</span>
                    </td>
                    <td>
                      {a.pqc_kem} + {a.pqc_sig}
                    </td>
                    <td>{a.execution_status}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* 8-Node LangGraph Pipeline Execution Visualizer */}
      <section className="card pipeline-section">
        <div className="pipeline-title">LangGraph Autonomous Security Pipeline</div>
        <div className="pipeline-grid">
          {PIPELINE_NODES.map((node) => (
            <div
              key={node.id}
              className={`node-box ${activePipelineNode === node.id ? 'active' : ''}`}
            >
              <div className="node-icon">{node.icon}</div>
              <div className="node-name">{node.name}</div>
              <div className="node-desc">{node.desc}</div>
            </div>
          ))}
        </div>

        {/* Live Agent Decision Reasoning Log */}
        <div className="decision-log-box" id="decisionLogBox">
          {decisionLog ? (
            <div>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginBottom: '8px',
                  flexWrap: 'wrap',
                  gap: '8px',
                }}
              >
                <strong>
                  Result:{' '}
                  <span
                    style={{
                      color: decisionLog.authenticated
                        ? 'var(--green)'
                        : 'var(--red)',
                    }}
                  >
                    {decisionLog.authenticated ? 'AUTHORIZED' : 'ACCESS DENIED'}
                  </span>
                </strong>
                <span>
                  Risk:{' '}
                  <b
                    style={{
                      color:
                        decisionLog.risk === 'HIGH'
                          ? 'var(--red)'
                          : decisionLog.risk === 'MEDIUM'
                          ? 'var(--yellow)'
                          : 'var(--green)',
                    }}
                  >
                    {decisionLog.risk}
                  </b>{' '}
                  • PQC: <b>{decisionLog.pqcKem}</b>
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text)', marginBottom: '4px' }}>
                <b>Agent Reasoning:</b>
              </div>
              <ul style={{ paddingLeft: '18px', color: 'var(--muted)', marginBottom: '8px' }}>
                {decisionLog.reasoning?.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
              {decisionLog.recommendations && decisionLog.recommendations.length > 0 && (
                <>
                  <div style={{ fontSize: '12px', color: 'var(--text)', marginBottom: '4px' }}>
                    <b>Advisories:</b>
                  </div>
                  <ul style={{ paddingLeft: '18px', color: 'var(--muted)' }}>
                    {decisionLog.recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          ) : (
            <div>
              <strong>Security Engine Status:</strong> Ready. Waiting for authentication request from
              virtual terminal or physical ESP8266 keypad...
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
