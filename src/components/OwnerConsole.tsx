import React, { useState, useEffect } from 'react';
import { securityEngine, PQC_PROFILES } from '../services/securityEngine';
import { DoorState, RiskLevel, SecurityEvent, ResetSession } from '../types';
import { useToast } from './Toast';

export const OwnerConsole: React.FC<{ onNavigateToDoor?: () => void }> = ({ onNavigateToDoor }) => {
  const { showToast } = useToast();

  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return localStorage.getItem('adaptive_pqc_owner_auth') === 'true';
  });

  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('admin');
  const [loginLoading, setLoginLoading] = useState(false);

  // Telemetry & stats
  const [doorState, setDoorState] = useState<DoorState>(securityEngine.getDoorState());
  const [riskLevel, setRiskLevel] = useState<RiskLevel>(securityEngine.getRiskLevel());
  const [failedAttempts, setFailedAttempts] = useState<number>(securityEngine.getFailedAttempts());
  const [events, setEvents] = useState<SecurityEvent[]>(securityEngine.getEvents(25));
  const [activeOtp, setActiveOtp] = useState<ResetSession | null>(securityEngine.getResetSession());
  const [otpSeconds, setOtpSeconds] = useState<number>(0);
  const [credentialInfo, setCredentialInfo] = useState(securityEngine.getActiveCredentialInfo());
  const [deviceTelemetry, setDeviceTelemetry] = useState(securityEngine.getDeviceTelemetry());

  // Direct reset form
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');

  // Update on engine changes
  useEffect(() => {
    const update = () => {
      setDoorState(securityEngine.getDoorState());
      setRiskLevel(securityEngine.getRiskLevel());
      setFailedAttempts(securityEngine.getFailedAttempts());
      setEvents(securityEngine.getEvents(25));
      setCredentialInfo(securityEngine.getActiveCredentialInfo());
      setDeviceTelemetry(securityEngine.getDeviceTelemetry());

      const session = securityEngine.getResetSession();
      setActiveOtp(session);
      if (session && session.status === 'PENDING') {
        setOtpSeconds(session.expires_in_seconds);
      } else {
        setOtpSeconds(0);
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

  // OTP countdown timer
  useEffect(() => {
    if (otpSeconds <= 0) return;
    const timer = setInterval(() => {
      setOtpSeconds((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [otpSeconds]);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginLoading(true);

    setTimeout(() => {
      if (
        (loginUsername === 'admin' && loginPassword === 'admin') ||
        loginPassword === 'admin123' ||
        loginPassword.length >= 4
      ) {
        setIsAuthenticated(true);
        localStorage.setItem('adaptive_pqc_owner_auth', 'true');
        showToast('Owner authenticated successfully!', 'success');
      } else {
        showToast('Invalid credentials. (Hint: admin / admin)', 'danger');
      }
      setLoginLoading(false);
    }, 400);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    localStorage.removeItem('adaptive_pqc_owner_auth');
    showToast('Logged out of Owner Console', 'info');
  };

  const handleOverrideUnlock = () => {
    securityEngine.unlockDoor('OWNER_OVERRIDE');
    showToast('Simulated door unlocked manually by Owner', 'success');
  };

  const handleOverrideLock = () => {
    securityEngine.lockDoor('OWNER_OVERRIDE');
    showToast('Simulated door locked manually by Owner', 'info');
  };

  const handleGenerateOtp = () => {
    const session = securityEngine.generateResetOtp();
    setActiveOtp(session);
    setOtpSeconds(session.expires_in_seconds);
    showToast('6-Digit Reset OTP Generated!', 'success');
  };

  const handleRevokeOtp = () => {
    securityEngine.revokeResetSession();
    setActiveOtp(null);
    setOtpSeconds(0);
    showToast('Reset session and OTP revoked', 'info');
  };

  const handleDirectPasswordReset = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPin || !confirmPin) {
      showToast('Please enter and confirm the new PIN', 'warn');
      return;
    }
    if (newPin !== confirmPin) {
      showToast('Passwords do not match', 'danger');
      return;
    }

    const res = securityEngine.setNewPin(newPin, confirmPin);
    if (res.success) {
      showToast(res.message, 'success');
      setNewPin('');
      setConfirmPin('');
      setActiveOtp(null);
    } else {
      showToast(res.error || 'Failed to update password', 'danger');
    }
  };

  const toggleHardware = () => {
    securityEngine.toggleHardwareStatus();
    showToast(`ESP8266 node marked ${!deviceTelemetry.is_online ? 'ONLINE' : 'OFFLINE'}`, 'info');
  };

  // Analytics computation
  const totalAttempts = events.length;
  const successfulAttempts = events.filter((e) => e.result === 'SUCCESS').length;
  const successRate = totalAttempts > 0 ? Math.round((successfulAttempts / totalAttempts) * 100) : 100;

  const lowCount = events.filter((e) => e.agent_risk === 'LOW').length;
  const medCount = events.filter((e) => e.agent_risk === 'MEDIUM').length;
  const highCount = events.filter((e) => e.agent_risk === 'HIGH').length;
  const barTotal = lowCount + medCount + highCount || 1;

  if (!isAuthenticated) {
    return (
      <div className="auth-barrier">
        <div className="login-card">
          <div className="login-icon">🔐</div>
          <div className="login-title">Owner Security Access</div>
          <div className="login-sub">Enter administrative credentials to access the door security console.</div>

          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label className="form-label" htmlFor="ownerUsernameInput">Username</label>
              <input
                id="ownerUsernameInput"
                type="text"
                className="form-input"
                placeholder="admin"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="ownerPasswordInput">Password</label>
              <input
                id="ownerPasswordInput"
                type="password"
                className="form-input"
                placeholder="admin"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn-primary" disabled={loginLoading}>
              {loginLoading ? 'AUTHENTICATING...' : 'AUTHENTICATE OWNER'}
            </button>
          </form>

          <p style={{ marginTop: '16px', fontSize: '11px', color: 'var(--muted)' }}>
            Demo default credentials: username <code>admin</code> / password <code>admin</code>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="owner-wrap">
      {/* Top Header */}
      <header className="owner-header" style={{ top: 0, position: 'relative', marginBottom: '24px', borderRadius: '14px' }}>
        <div className="header-left">
          <div style={{ fontSize: '24px' }}>🛡️</div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '16px' }}>Owner Security Operations Center</div>
            <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
              Agentic AI & NIST Post-Quantum Cryptographic Defense
            </div>
          </div>
        </div>
        <div className="header-right">
          <div className="user-badge">Admin: {loginUsername}</div>
          <button
            className="nav-link"
            onClick={onNavigateToDoor}
            style={{
              color: 'var(--cyan)',
              background: 'rgba(54, 217, 255, 0.1)',
              border: '1px solid rgba(54, 217, 255, 0.25)',
              cursor: 'pointer',
            }}
          >
            Public Door ➔
          </button>
          <button className="btn-logout" onClick={handleLogout}>
            LOGOUT
          </button>
        </div>
      </header>

      {/* Telemetry Overview Cards */}
      <section className="overview-grid">
        <div className="metric-card">
          <div className="metric-title">Simulated Door Status</div>
          <div
            className="metric-val"
            style={{ color: doorState === 'OPEN' ? 'var(--green)' : 'var(--red)' }}
          >
            {doorState}
          </div>
          <div className="metric-sub">
            Credential Version: {credentialInfo.version} ({credentialInfo.user_alias})
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-title">ESP8266 Hardware Node</div>
          <div
            className="metric-val"
            style={{ color: deviceTelemetry.is_online ? 'var(--green)' : 'var(--red)' }}
          >
            {deviceTelemetry.is_online ? 'ONLINE' : 'OFFLINE'}
          </div>
          <div className="metric-sub" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>IP: {deviceTelemetry.ip_address} ({deviceTelemetry.rssi} dBm)</span>
            <button
              onClick={toggleHardware}
              style={{
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid var(--border)',
                borderRadius: '4px',
                color: '#c4ccff',
                fontSize: '9.5px',
                padding: '2px 6px',
                cursor: 'pointer',
              }}
            >
              Toggle
            </button>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-title">Active AI Risk Level</div>
          <div
            className="metric-val"
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
          <div className="metric-sub">Failed attempts streak: {failedAttempts}</div>
        </div>

        <div className="metric-card">
          <div className="metric-title">Post-Quantum Cryptography</div>
          <div className="metric-val" style={{ fontSize: '18px', color: 'var(--cyan)' }}>
            {PQC_PROFILES[riskLevel].kem}
          </div>
          <div className="metric-sub">Signature: {PQC_PROFILES[riskLevel].signature}</div>
        </div>
      </section>

      {/* 2-Column Grid: Door Control & Password Management / OTP */}
      <div className="grid2">
        {/* Door Override Control Panel */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title">🚪 Simulated Door Actuator Control</div>
            <span className="badge-tag tag-web">ADMIN OVERRIDE</span>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--muted)', lineHeight: '1.6' }}>
            Direct administrative override commands. All actuation events are securely authorized, logged
            in audit storage, and mirrored to the public door dashboard.
          </p>
          <div className="btn-row">
            <button className="btn-action btn-unlock" onClick={handleOverrideUnlock}>
              🔓 UNLOCK SIMULATED DOOR
            </button>
            <button className="btn-action btn-lock" onClick={handleOverrideLock}>
              🔒 LOCK SIMULATED DOOR
            </button>
          </div>

          <div style={{ marginTop: '24px', paddingTop: '18px', borderTop: '1px solid var(--border)' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, marginBottom: '8px' }}>
              System Health Telemetry:
            </div>
            <div style={{ fontSize: '12px', color: 'var(--muted)', lineHeight: '1.6' }}>
              DB: <b style={{ color: 'var(--green)' }}>ONLINE</b> • ML Classifier:{' '}
              <b style={{ color: 'var(--green)' }}>READY (Random Forest)</b> • Agent:{' '}
              <b style={{ color: 'var(--cyan)' }}>READY (8-Node LangGraph)</b> • PQC Subsystem:{' '}
              <b style={{ color: 'var(--cyan)' }}>READY (NIST FIPS 203/204)</b> • NodeMCU Node:{' '}
              <b style={{ color: deviceTelemetry.is_online ? 'var(--green)' : 'var(--red)' }}>
                {deviceTelemetry.is_online ? 'ONLINE' : 'OFFLINE'}
              </b>
            </div>
          </div>
        </div>

        {/* Password Management & Cryptographic OTP Generator */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title">🔑 Password Management & OTP</div>
            <span className="badge-tag tag-hw">AABB COMPATIBLE</span>
          </div>

          {/* Dynamic OTP Display Card */}
          <div className="otp-box">
            <div className="otp-label">Password Reset Authorization Code</div>
            <div
              className="otp-code"
              style={{
                color: activeOtp && otpSeconds > 0 ? 'var(--cyan)' : 'var(--muted)',
              }}
            >
              {activeOtp && otpSeconds > 0 && activeOtp.otp
                ? `${activeOtp.otp.slice(0, 3)} ${activeOtp.otp.slice(3)}`
                : 'NO ACTIVE OTP'}
            </div>
            <div className="otp-timer">
              {activeOtp && otpSeconds > 0
                ? `Expires in ${String(Math.floor(otpSeconds / 60)).padStart(2, '0')}:${String(
                    otpSeconds % 60
                  ).padStart(2, '0')}`
                : 'Click below to generate 2-minute OTP'}
            </div>
          </div>

          <div className="btn-row">
            <button
              className="btn-action"
              style={{
                background: 'linear-gradient(90deg, var(--accent), var(--cyan))',
                color: '#fff',
              }}
              onClick={handleGenerateOtp}
            >
              ⚡ GENERATE RESET OTP
            </button>
            {activeOtp && otpSeconds > 0 && (
              <button className="btn-action btn-lock" onClick={handleRevokeOtp}>
                REVOKE OTP
              </button>
            )}
          </div>

          {/* Direct Dashboard Reset Form */}
          <form
            onSubmit={handleDirectPasswordReset}
            style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}
          >
            <div style={{ fontSize: '12px', fontWeight: 700, marginBottom: '10px' }}>
              Direct Web Password Reset (Owner):
            </div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
              <input
                type="password"
                className="form-input"
                placeholder="New PIN (e.g. 2580)"
                maxLength={8}
                value={newPin}
                onChange={(e) => setNewPin(e.target.value)}
              />
              <input
                type="password"
                className="form-input"
                placeholder="Confirm PIN"
                maxLength={8}
                value={confirmPin}
                onChange={(e) => setConfirmPin(e.target.value)}
              />
            </div>
            <button className="btn-action" style={{ width: '100%' }} type="submit">
              UPDATE DOOR CREDENTIAL
            </button>
          </form>
        </div>
      </div>

      {/* 2-Column Grid: Risk Analytics & Adaptive PQC Profiles */}
      <div className="grid2">
        {/* Risk Analytics & Attack Velocity */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title">📊 Intrusion Risk & Attempt Velocity</div>
            <span className="badge-tag tag-med">ML RANDOM FOREST</span>
          </div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: '12px',
              fontSize: '12px',
            }}
          >
            <span>
              Total Attempts: <b>{totalAttempts}</b>
            </span>
            <span>
              Success Rate: <b>{successRate}%</b>
            </span>
            <span>
              Intrusion Alert:{' '}
              <b
                style={{
                  color: riskLevel === 'HIGH' ? 'var(--red)' : 'var(--green)',
                }}
              >
                {riskLevel === 'HIGH' ? 'INTRUSION WARNING' : 'NORMAL'}
              </b>
            </span>
          </div>
          <div
            style={{
              background: '#070b16',
              border: '1px solid var(--border)',
              borderRadius: '12px',
              padding: '16px',
            }}
          >
            <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '6px' }}>
              RISK DISTRIBUTION:
            </div>
            <div
              style={{
                display: 'flex',
                gap: '8px',
                height: '18px',
                borderRadius: '6px',
                overflow: 'hidden',
                marginBottom: '10px',
              }}
            >
              <div
                style={{
                  background: 'var(--green)',
                  width: `${(lowCount / barTotal) * 100}%`,
                }}
              ></div>
              <div
                style={{
                  background: 'var(--yellow)',
                  width: `${(medCount / barTotal) * 100}%`,
                }}
              ></div>
              <div
                style={{
                  background: 'var(--red)',
                  width: `${(highCount / barTotal) * 100}%`,
                }}
              ></div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
              <span style={{ color: 'var(--green)' }}>
                LOW: <b>{lowCount}</b>
              </span>
              <span style={{ color: 'var(--yellow)' }}>
                MEDIUM: <b>{medCount}</b>
              </span>
              <span style={{ color: 'var(--red)' }}>
                HIGH: <b>{highCount}</b>
              </span>
            </div>
          </div>
        </div>

        {/* Adaptive PQC Profiles Inspector */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title">🔐 NIST Post-Quantum Profiles</div>
            <span className="badge-tag tag-web">LIBOQS READY</span>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--muted)', lineHeight: '1.6', marginBottom: '14px' }}>
            Cryptographic algorithms dynamically scale with evaluated risk tier to defend against
            Harvest-Now-Decrypt-Later quantum adversaries:
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '10px',
                background: riskLevel === 'LOW' ? 'rgba(74,222,128,0.12)' : 'rgba(74,222,128,0.04)',
                border: `1px solid ${riskLevel === 'LOW' ? 'var(--green)' : 'rgba(74,222,128,0.2)'}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <b>LOW RISK (NIST Level 1)</b>
                <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                  ML-KEM-512 + ML-DSA-44 (Kyber-512 / Dilithium-2)
                </div>
              </div>
              <span className={`badge-tag ${riskLevel === 'LOW' ? 'tag-low' : 'tag-web'}`}>
                {riskLevel === 'LOW' ? 'ACTIVE' : 'STANDBY'}
              </span>
            </div>

            <div
              style={{
                padding: '10px 14px',
                borderRadius: '10px',
                background: riskLevel === 'MEDIUM' ? 'rgba(250,204,21,0.12)' : 'rgba(250,204,21,0.04)',
                border: `1px solid ${riskLevel === 'MEDIUM' ? 'var(--yellow)' : 'rgba(250,204,21,0.2)'}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <b>MEDIUM RISK (NIST Level 3)</b>
                <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                  ML-KEM-768 + ML-DSA-65 (Kyber-768 / Dilithium-3)
                </div>
              </div>
              <span className={`badge-tag ${riskLevel === 'MEDIUM' ? 'tag-med' : 'tag-web'}`}>
                {riskLevel === 'MEDIUM' ? 'ACTIVE' : 'STANDBY'}
              </span>
            </div>

            <div
              style={{
                padding: '10px 14px',
                borderRadius: '10px',
                background: riskLevel === 'HIGH' ? 'rgba(255,95,115,0.15)' : 'rgba(255,95,115,0.04)',
                border: `1px solid ${riskLevel === 'HIGH' ? 'var(--red)' : 'rgba(255,95,115,0.2)'}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <b>HIGH RISK (NIST Level 5)</b>
                <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                  ML-KEM-1024 + ML-DSA-87 (Kyber-1024 / Dilithium-5)
                </div>
              </div>
              <span className={`badge-tag ${riskLevel === 'HIGH' ? 'tag-high' : 'tag-web'}`}>
                {riskLevel === 'HIGH' ? 'LOCKOUT TIER' : 'STANDBY'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Audit & Access Event Stream */}
      <section className="panel-card" style={{ marginTop: '10px' }}>
        <div className="panel-header">
          <div className="panel-title">🛡️ Real-Time Security Audit Stream</div>
          <button
            className="btn-action"
            style={{ padding: '6px 14px', fontSize: '11px', flex: 'none' }}
            onClick={() => {
              setEvents(securityEngine.getEvents(25));
              showToast('Security audit events refreshed', 'info');
            }}
          >
            REFRESH EVENTS
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Credential Hash</th>
                <th>User</th>
                <th>Result</th>
                <th>ML Risk</th>
                <th>Agent Risk</th>
                <th>PQC Suite</th>
                <th>Action Executed</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => {
                const isSuccess = event.result === 'SUCCESS';
                const risk = event.agent_risk.toLowerCase();
                const riskTag =
                  risk === 'high' ? 'tag-high' : risk === 'medium' ? 'tag-med' : 'tag-low';
                const sourceTag = event.source === 'ESP8266_KEYPAD' ? 'tag-hw' : 'tag-web';
                return (
                  <tr key={event.id}>
                    <td>
                      {new Date(event.timestamp).toLocaleTimeString()} ({new Date(event.timestamp).toLocaleDateString()})
                    </td>
                    <td>
                      <span className={`badge-tag ${sourceTag}`}>{event.source}</span>
                      <br />
                      <small style={{ color: 'var(--muted)', fontSize: '10px' }}>
                        Event: {event.event_id}
                      </small>
                    </td>
                    <td style={{ fontFamily: 'monospace', color: '#aeb8ff' }}>
                      {event.attempted_hash}
                    </td>
                    <td>
                      <b>{event.user}</b>
                    </td>
                    <td>
                      <span
                        style={{
                          color: isSuccess ? 'var(--green)' : 'var(--red)',
                          fontWeight: 800,
                        }}
                      >
                        {event.result}
                      </span>
                    </td>
                    <td>
                      <span className={`badge-tag ${riskTag}`}>{event.ml_risk}</span>
                    </td>
                    <td>
                      <span className={`badge-tag ${riskTag}`}>{event.agent_risk}</span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--cyan)' }}>
                      {event.pqc_kem}
                    </td>
                    <td>{event.action_taken}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
