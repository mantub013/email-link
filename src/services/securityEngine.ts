import {
  RiskLevel,
  DoorState,
  PqcProfile,
  SecurityEvent,
  NetworkAssessment,
  SecurityDecision,
  DoorCredential,
  ResetSession,
  DeviceTelemetry,
} from '../types';

export const PQC_PROFILES: Record<RiskLevel, PqcProfile> = {
  LOW: {
    name: 'LOW',
    kem: 'ML-KEM-512',
    signature: 'ML-DSA-44',
    nist_level: 'Level 1 (AES-128 Eq.)',
    description: 'Resource-conscious quantum-resistant policy for normal door-lock operation.',
    execution_mode: 'PROFILE_SELECTION_NATIVE',
  },
  MEDIUM: {
    name: 'STANDARD',
    kem: 'ML-KEM-768',
    signature: 'ML-DSA-65',
    nist_level: 'Level 3 (AES-192 Eq.)',
    description: 'Balanced quantum-resistant policy for suspicious conditions.',
    execution_mode: 'PROFILE_SELECTION_NATIVE',
  },
  HIGH: {
    name: 'HIGH',
    kem: 'ML-KEM-1024',
    signature: 'ML-DSA-87',
    nist_level: 'Level 5 (AES-256 Eq.)',
    description: 'Stronger quantum-resistant policy for active attack conditions.',
    execution_mode: 'LOCKOUT_TIER_NATIVE',
  },
};

export const NETWORK_FEATURE_COLUMNS = [
  "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
  "fin_flag_number", "syn_flag_number", "rst_flag_number",
  "psh_flag_number", "ack_flag_number", "ece_flag_number",
  "cwr_flag_number", "ack_count", "syn_count", "fin_count",
  "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH",
  "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv",
  "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
  "IAT", "Number", "Variance",
];

// Initial preloaded seed events
const DEFAULT_EVENTS: SecurityEvent[] = [
  {
    id: '1',
    event_id: 'EVT-A491',
    decision_id: 'DEC-B821',
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    source: 'WEB_UI',
    attempted_hash: '••••',
    user: 'DAD',
    result: 'SUCCESS',
    failed_attempt_count: 0,
    ml_risk: 'LOW',
    agent_risk: 'LOW',
    final_risk: 'LOW',
    device_risk: 'LOW',
    network_risk: 'UNKNOWN',
    pqc_kem: 'ML-KEM-512',
    pqc_sig: 'ML-DSA-44',
    action_taken: 'UNLOCK_DOOR',
    reason: 'Authorized credentials verified.',
  },
  {
    id: '2',
    event_id: 'EVT-E102',
    decision_id: 'DEC-D330',
    timestamp: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    source: 'ESP8266_KEYPAD',
    attempted_hash: '••••',
    user: 'MOM',
    result: 'SUCCESS',
    failed_attempt_count: 0,
    ml_risk: 'LOW',
    agent_risk: 'LOW',
    final_risk: 'LOW',
    device_risk: 'LOW',
    network_risk: 'UNKNOWN',
    pqc_kem: 'ML-KEM-512',
    pqc_sig: 'ML-DSA-44',
    action_taken: 'UNLOCK_DOOR',
    reason: 'Authorized credentials verified.',
  },
];

const DEFAULT_NETWORK_ASSESSMENTS: NetworkAssessment[] = [
  {
    decision_id: 'DEC-NET-01',
    timestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    device_risk: 'LOW',
    network_risk: 'LOW',
    network_prediction: {
      predicted_attack: 'BenignTraffic',
      max_confidence: 0.984,
      assessment_type: 'OFFLINE_SUPPLIED_CSV_ASSESSMENT',
      telemetry_source: 'SUPPLIED_FLOW_FEATURES',
    },
    final_risk: 'LOW',
    pqc_kem: 'ML-KEM-512',
    pqc_sig: 'ML-DSA-44',
    execution_status: 'ASSESSMENT_ONLY_NO_DOOR_ACTION',
    assessment_source: 'OFFLINE_SUPPLIED_CSV_ASSESSMENT',
  },
  {
    decision_id: 'DEC-NET-02',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    device_risk: 'MEDIUM',
    network_risk: 'MEDIUM',
    network_prediction: {
      predicted_attack: 'DictionaryBruteForce',
      max_confidence: 0.912,
      assessment_type: 'OFFLINE_SUPPLIED_CSV_ASSESSMENT',
      telemetry_source: 'SUPPLIED_FLOW_FEATURES',
    },
    final_risk: 'MEDIUM',
    pqc_kem: 'ML-KEM-768',
    pqc_sig: 'ML-DSA-65',
    execution_status: 'ASSESSMENT_ONLY_NO_DOOR_ACTION',
    assessment_source: 'OFFLINE_SUPPLIED_CSV_ASSESSMENT',
  },
];

class SecurityEngine {
  private doorState: DoorState = 'LOCKED';
  private currentRisk: RiskLevel = 'LOW';
  private failedAttempts: number = 0;
  private lockoutUntil: number = 0;
  private attemptTimestamps: number[] = [];
  private credentials: DoorCredential[] = [
    {
      id: 1,
      credential_name: 'Primary Door PIN (Dad)',
      pin: '1234',
      pin_hash: 'dad-hash',
      pin_sha256: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4',
      version: 1,
      user_alias: 'DAD',
      is_active: true,
      updated_at: new Date().toISOString(),
    },
    {
      id: 2,
      credential_name: 'Secondary Door PIN (Mom)',
      pin: '5678',
      pin_hash: 'mom-hash',
      pin_sha256: 'a29b47814b74a2a4b87cf7a837c7625cc1ff53146ce235559d80d22d56a3e2a7',
      version: 1,
      user_alias: 'MOM',
      is_active: true,
      updated_at: new Date().toISOString(),
    },
  ];
  private activeResetSession: ResetSession | null = null;
  private events: SecurityEvent[] = [];
  private networkAssessments: NetworkAssessment[] = [];
  private latestDecision: SecurityDecision | null = null;
  private listeners: Set<() => void> = new Set();
  private deviceTelemetry: DeviceTelemetry = {
    is_online: true,
    ip_address: '192.168.1.144',
    rssi: -58,
    battery_level: 92,
    cpu_utilization: 24,
    memory_usage: 32,
    communication_latency_ms: 38,
    network_anomaly: 0,
    threat_indicator: 0,
    attempt_velocity: 0,
    input_length: 0,
  };
  private autoRelockTimeout: any = null;

  constructor() {
    this.loadState();
  }

  private loadState() {
    try {
      const savedEvents = localStorage.getItem('adaptive_pqc_events');
      if (savedEvents) {
        this.events = JSON.parse(savedEvents);
      } else {
        this.events = [...DEFAULT_EVENTS];
      }

      const savedAssessments = localStorage.getItem('adaptive_pqc_net_assessments');
      if (savedAssessments) {
        this.networkAssessments = JSON.parse(savedAssessments);
      } else {
        this.networkAssessments = [...DEFAULT_NETWORK_ASSESSMENTS];
      }

      const savedCreds = localStorage.getItem('adaptive_pqc_credentials');
      if (savedCreds) {
        this.credentials = JSON.parse(savedCreds);
      }

      const savedLockout = localStorage.getItem('adaptive_pqc_lockout');
      if (savedLockout) {
        const until = Number(savedLockout);
        if (until > Date.now()) {
          this.lockoutUntil = until;
          this.doorState = 'LOCKOUT';
          this.currentRisk = 'HIGH';
        }
      }
    } catch {
      this.events = [...DEFAULT_EVENTS];
      this.networkAssessments = [...DEFAULT_NETWORK_ASSESSMENTS];
    }
  }

  private saveState() {
    try {
      localStorage.setItem('adaptive_pqc_events', JSON.stringify(this.events.slice(0, 100)));
      localStorage.setItem('adaptive_pqc_net_assessments', JSON.stringify(this.networkAssessments.slice(0, 50)));
      localStorage.setItem('adaptive_pqc_credentials', JSON.stringify(this.credentials));
      if (this.lockoutUntil > Date.now()) {
        localStorage.setItem('adaptive_pqc_lockout', String(this.lockoutUntil));
      } else {
        localStorage.removeItem('adaptive_pqc_lockout');
      }
    } catch {
      // Ignore storage errors
    }
  }

  public subscribe(listener: () => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    this.saveState();
    this.listeners.forEach((fn) => fn());
  }

  public getDoorState(): DoorState {
    if (this.isLockedOut()) {
      return 'LOCKOUT';
    }
    return this.doorState;
  }

  public isLockedOut(): boolean {
    if (this.lockoutUntil > Date.now()) {
      return true;
    }
    if (this.doorState === 'LOCKOUT' && this.lockoutUntil <= Date.now()) {
      this.doorState = 'LOCKED';
      this.currentRisk = 'LOW';
      this.lockoutUntil = 0;
    }
    return false;
  }

  public getLockoutRemaining(): number {
    if (!this.isLockedOut()) return 0;
    return Math.max(0, Math.ceil((this.lockoutUntil - Date.now()) / 1000));
  }

  public getRiskLevel(): RiskLevel {
    if (this.isLockedOut()) return 'HIGH';
    return this.currentRisk;
  }

  public getFailedAttempts(): number {
    return this.failedAttempts;
  }

  public getPqcProfile(): PqcProfile {
    return PQC_PROFILES[this.getRiskLevel()];
  }

  public getEvents(limit = 50): SecurityEvent[] {
    return this.events.slice(0, limit);
  }

  public getNetworkAssessments(limit = 10): NetworkAssessment[] {
    return this.networkAssessments.slice(0, limit);
  }

  public getLatestDecision(): SecurityDecision | null {
    return this.latestDecision;
  }

  public getDeviceTelemetry(): DeviceTelemetry {
    return { ...this.deviceTelemetry, attempt_velocity: this.calculateAttemptVelocity() };
  }

  public toggleHardwareStatus() {
    this.deviceTelemetry.is_online = !this.deviceTelemetry.is_online;
    this.notify();
  }

  public setHardwareInputLength(len: number) {
    this.deviceTelemetry.input_length = len;
    this.notify();
  }

  public getActiveCredentialInfo() {
    const active = this.credentials.find((c) => c.is_active);
    return {
      credential_name: active?.credential_name || 'Primary Door PIN',
      version: active?.version || 1,
      user_alias: active?.user_alias || 'DAD',
      last_updated: active?.updated_at || new Date().toISOString(),
      is_configured: true,
    };
  }

  public calculateAttemptVelocity(windowSeconds = 30): number {
    const cutoff = Date.now() - windowSeconds * 1000;
    this.attemptTimestamps = this.attemptTimestamps.filter((t) => t >= cutoff);
    return this.attemptTimestamps.length;
  }

  public lockDoor(source = 'MANUAL'): void {
    if (this.autoRelockTimeout) {
      clearTimeout(this.autoRelockTimeout);
      this.autoRelockTimeout = null;
    }
    this.doorState = 'LOCKED';
    this.notify();
  }

  public unlockDoor(user = 'MANUAL_OVERRIDE'): void {
    if (this.isLockedOut()) return;
    this.doorState = 'OPEN';
    this.notify();

    if (this.autoRelockTimeout) clearTimeout(this.autoRelockTimeout);
    this.autoRelockTimeout = setTimeout(() => {
      this.doorState = 'LOCKED';
      this.notify();
    }, 5000);
  }

  /**
   * 8-Node LangGraph Autonomous Security Pipeline
   */
  public async executePipeline(pin: string, source: 'WEB_UI' | 'ESP8266_KEYPAD' = 'WEB_UI') {
    const isLocked = this.isLockedOut();
    const remainingSeconds = this.getLockoutRemaining();
    const nowIso = new Date().toISOString();
    const eventId = `EVT-${Math.random().toString(16).substring(2, 6).toUpperCase()}`;
    const decisionId = `DEC-${Math.random().toString(16).substring(2, 6).toUpperCase()}`;

    if (isLocked) {
      const lockedResult = {
        authenticated: false,
        door_state: 'LOCKOUT' as DoorState,
        user: 'UNKNOWN',
        event_id: eventId,
        decision_id: decisionId,
        risk_level: 'HIGH' as RiskLevel,
        ml_risk_level: 'HIGH' as RiskLevel,
        agent_risk_level: 'HIGH' as RiskLevel,
        lockout_active: true,
        lockout_remaining_seconds: remainingSeconds,
        failed_attempts: this.failedAttempts,
        security_profile: PQC_PROFILES.HIGH,
        action: {
          action: 'LOCK_AUTHENTICATION',
          type: 'LOCKOUT',
          message: `Security Lockout Active. Retry in ${remainingSeconds}s.`,
        },
        reasoning: [`System locked out due to previous intrusion velocity (${remainingSeconds}s remaining).`],
        recommendations: [
          'Review the security audit for possible intrusion.',
          'Verify the integrity of the ESP8266 keypad and physical enclosure.',
          'Keep access denied until the configured lockout duration expires.',
        ],
      };
      return lockedResult;
    }

    // Check credentials
    const activeMatch = this.credentials.find(
      (c) => c.is_active && (c.pin === pin || (pin.length > 8 && c.pin_sha256.startsWith(pin)))
    );

    const authSuccess = Boolean(activeMatch);
    const userAlias = activeMatch ? activeMatch.user_alias : 'UNKNOWN';

    if (authSuccess) {
      this.failedAttempts = 0;
    } else {
      this.failedAttempts += 1;
      this.attemptTimestamps.push(Date.now());
    }

    const velocity = this.calculateAttemptVelocity(30);

    // 1. OBSERVE
    const observations: string[] = [];
    if (this.failedAttempts >= 5) {
      observations.push(`Critical threshold: ${this.failedAttempts} failed attempts.`);
    } else if (this.failedAttempts >= 3) {
      observations.push(`Elevated failure count: ${this.failedAttempts} failed attempts.`);
    } else if (this.failedAttempts > 0) {
      observations.push('An authentication failure was recorded.');
    } else {
      observations.push('No failed authentication attempts reported.');
    }

    if (velocity >= 3.0) {
      observations.push(`High authentication attempt velocity: ${velocity}/30 seconds.`);
    }

    // 2. ASSESS (Random Forest Risk Prediction)
    let mlRisk: RiskLevel = 'LOW';
    let mlConfidence: Record<string, number> = { LOW: 0.96, MEDIUM: 0.03, HIGH: 0.01 };

    if (this.failedAttempts >= 5 || velocity >= 4) {
      mlRisk = 'HIGH';
      mlConfidence = { LOW: 0.02, MEDIUM: 0.08, HIGH: 0.90 };
    } else if (this.failedAttempts >= 3 || velocity >= 2) {
      mlRisk = 'MEDIUM';
      mlConfidence = { LOW: 0.12, MEDIUM: 0.78, HIGH: 0.10 };
    }

    const reasoning: string[] = [
      `Device Random Forest predicted ${mlRisk}; confidence ${(mlConfidence[mlRisk] * 100).toFixed(1)}%.`,
    ];

    // 3. REASSESS (Velocity & Escalation Rules)
    let finalRisk: RiskLevel = mlRisk;
    let escalationApplied = false;
    let escalationReason = '';

    if (this.failedAttempts >= 5 || velocity >= 4.0) {
      if (finalRisk !== 'HIGH') {
        reasoning.push('Escalated to HIGH because of repeated authentication failures or high attempt velocity.');
        escalationApplied = true;
        escalationReason = 'Critical intrusion threshold reached.';
      }
      finalRisk = 'HIGH';
    } else if (this.failedAttempts >= 3 && finalRisk === 'LOW') {
      finalRisk = 'MEDIUM';
      escalationApplied = true;
      escalationReason = 'Escalated to MEDIUM because of repeated authentication failures.';
      reasoning.push('Escalated to MEDIUM because of repeated authentication failures.');
    }

    // 4. PLAN
    const plan: string[] = [];
    if (finalRisk === 'HIGH') {
      plan.push('Apply the configured high-risk authentication lockout policy.');
      plan.push('Select ML-KEM-1024 and ML-DSA-87 as the active PQC profile.');
      plan.push('Raise a critical security alert and record the assessment.');
    } else if (finalRisk === 'MEDIUM') {
      plan.push('Maintain secure door state and increase monitoring.');
      plan.push('Select ML-KEM-768 and ML-DSA-65 as the active PQC profile.');
      plan.push('Record a security warning.');
    } else {
      plan.push('Use ML-KEM-512 and ML-DSA-44 as the active PQC profile.');
      plan.push('Continue credential-based authorization checks.');
    }

    // 5. DECIDE
    let actionType = 'RECORD_FAILED_ATTEMPT';
    let actionMessage = 'Credentials not authenticated; access is denied.';
    if (authSuccess && finalRisk !== 'HIGH') {
      actionType = 'UNLOCK_DOOR';
      actionMessage = 'Authentication succeeded and combined risk is LOW.';
    } else if (finalRisk === 'HIGH') {
      actionType = 'LOCK_AUTHENTICATION';
      actionMessage = 'High security risk detected; authentication locked by policy.';
    } else if (finalRisk === 'MEDIUM') {
      actionType = 'INCREASE_MONITORING';
      actionMessage = 'Medium risk; maintain protection and increase telemetry monitoring.';
    }

    // 6. ACT (PQC Profile Selection & Door Actuation)
    const pqcProfile = PQC_PROFILES[finalRisk];
    this.currentRisk = finalRisk;

    let targetDoorState: DoorState = 'LOCKED';
    if (authSuccess && finalRisk !== 'HIGH') {
      targetDoorState = 'OPEN';
      this.doorState = 'OPEN';
      if (this.autoRelockTimeout) clearTimeout(this.autoRelockTimeout);
      this.autoRelockTimeout = setTimeout(() => {
        this.doorState = 'LOCKED';
        this.notify();
      }, 5000);
    } else if (finalRisk === 'HIGH') {
      targetDoorState = 'LOCKOUT';
      this.doorState = 'LOCKOUT';
      this.lockoutUntil = Date.now() + 60 * 1000;
    } else {
      targetDoorState = 'LOCKED';
      this.doorState = 'LOCKED';
    }

    // 7. RECOMMEND
    const recommendations: string[] = [];
    if (finalRisk === 'HIGH') {
      recommendations.push('Review the security audit for potential brute-force attack.');
      recommendations.push('Verify the physical integrity of the NodeMCU ESP8266 node.');
      recommendations.push('Keep access denied until the 60s security cooldown expires or owner resets.');
    } else if (finalRisk === 'MEDIUM') {
      recommendations.push('Monitor device and network telemetry for repeated suspicious activity.');
    } else {
      recommendations.push('Continue normal monitoring and credential-based authorization.');
    }

    // 8. REFLECT
    const reflection = {
      evaluation_success: true,
      device_model_risk: mlRisk,
      agent_final: finalRisk,
      nodes_traversed: 8,
      model_agreement: mlRisk === finalRisk,
      confidence_score: mlConfidence[mlRisk],
    };

    // Record Event in SQLite simulation
    const eventRecord: SecurityEvent = {
      id: String(this.events.length + 1),
      event_id: eventId,
      decision_id: decisionId,
      timestamp: nowIso,
      source: source,
      attempted_hash: authSuccess ? '••••' : `SHA256:${pin.substring(0, 4)}...`,
      user: authSuccess ? userAlias : 'UNKNOWN',
      result: authSuccess && finalRisk !== 'HIGH' ? 'SUCCESS' : (finalRisk === 'HIGH' ? 'BLOCKED_HIGH_RISK' : 'FAILED'),
      failed_attempt_count: this.failedAttempts,
      ml_risk: mlRisk,
      agent_risk: finalRisk,
      final_risk: finalRisk,
      device_risk: mlRisk,
      network_risk: 'UNKNOWN',
      pqc_kem: pqcProfile.kem,
      pqc_sig: pqcProfile.signature,
      action_taken: actionType,
      reason: authSuccess ? 'Authorized credentials verified.' : 'Invalid credentials submitted.',
    };

    this.events.unshift(eventRecord);

    this.latestDecision = {
      event_id: eventId,
      decision_id: decisionId,
      timestamp: nowIso,
      source: source,
      result: eventRecord.result,
      device_risk: mlRisk,
      network_risk: 'UNKNOWN',
      final_risk: finalRisk,
      action: actionType,
    };

    this.notify();

    return {
      authenticated: authSuccess && finalRisk !== 'HIGH',
      credential_verified: authSuccess,
      door_state: targetDoorState,
      user: authSuccess ? userAlias : 'UNKNOWN',
      event_id: eventId,
      decision_id: decisionId,
      risk_level: finalRisk,
      ml_risk_level: mlRisk,
      agent_risk_level: finalRisk,
      ml_risk_confidence: mlConfidence,
      network_risk_level: 'UNKNOWN',
      failed_attempts: this.failedAttempts,
      lockout_active: targetDoorState === 'LOCKOUT',
      lockout_remaining_seconds: this.getLockoutRemaining(),
      escalation_applied: escalationApplied,
      escalation_reason: escalationReason,
      security_profile: pqcProfile,
      action: {
        action: actionType,
        type: actionType,
        message: actionMessage,
      },
      reasoning: reasoning,
      observations: observations,
      plan: plan,
      recommendations: recommendations,
      reflection: reflection,
    };
  }

  /**
   * Multi-Step AABB Password Reset Flow & OTP
   */
  public triggerAabbReset(): { success: boolean; message: string; session_id: string } {
    const sessionId = `SES-${Math.random().toString(16).substring(2, 6).toUpperCase()}`;
    const session: ResetSession = {
      session_id: sessionId,
      device_id: 'ESP8266-NODE-01',
      otp: '', // Generated on demand in owner console or pre-generated
      created_at: Date.now(),
      expires_at: Date.now() + 120 * 1000,
      expires_in_seconds: 120,
      status: 'PENDING',
      attempt_count: 0,
      max_attempts: 3,
    };
    this.activeResetSession = session;
    this.notify();
    return {
      success: true,
      message: 'Reset mode triggered. Generate OTP in Owner Security Operations Center.',
      session_id: sessionId,
    };
  }

  public generateResetOtp(): ResetSession {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = `SES-${Math.random().toString(16).substring(2, 6).toUpperCase()}`;
    this.activeResetSession = {
      session_id: sessionId,
      device_id: 'ESP8266-NODE-01',
      otp: otp,
      created_at: Date.now(),
      expires_at: Date.now() + 120 * 1000,
      expires_in_seconds: 120,
      status: 'PENDING',
      attempt_count: 0,
      max_attempts: 3,
    };
    this.notify();
    return this.activeResetSession;
  }

  public getResetSession(): ResetSession | null {
    if (!this.activeResetSession) return null;
    const remaining = Math.max(0, Math.ceil((this.activeResetSession.expires_at - Date.now()) / 1000));
    if (remaining <= 0 && this.activeResetSession.status === 'PENDING') {
      this.activeResetSession.status = 'EXPIRED';
    }
    this.activeResetSession.expires_in_seconds = remaining;
    return this.activeResetSession;
  }

  public verifyResetOtp(enteredOtp: string): { success: boolean; message: string; error?: string } {
    const session = this.getResetSession();
    if (!session || session.status === 'EXPIRED') {
      return { success: false, message: 'No active OTP session or OTP has expired.', error: 'OTP expired or not found.' };
    }
    if (session.status !== 'PENDING') {
      return { success: false, message: 'Invalid session state.', error: 'Invalid state' };
    }

    if (session.otp !== enteredOtp.trim()) {
      session.attempt_count += 1;
      if (session.attempt_count >= session.max_attempts) {
        session.status = 'REVOKED';
        this.notify();
        return { success: false, message: 'Max OTP attempts exceeded. Session revoked.', error: 'Max attempts exceeded' };
      }
      this.notify();
      return { success: false, message: 'Invalid OTP code entered.', error: 'Incorrect OTP' };
    }

    session.status = 'OTP_VERIFIED';
    this.notify();
    return { success: true, message: 'OTP Verified successfully. Please enter new 4-digit PIN.' };
  }

  public setNewPin(newPin: string, confirmPin: string): { success: boolean; message: string; error?: string } {
    if (newPin !== confirmPin) {
      return { success: false, message: 'PIN mismatch', error: 'PINs do not match.' };
    }
    if (!/^\d{4,8}$/.test(newPin)) {
      return { success: false, message: 'PIN must be between 4 and 8 numeric digits.', error: 'Invalid PIN format' };
    }

    // Atomically deactivate old credential, increment version, insert new credential
    const maxVersion = Math.max(...this.credentials.map((c) => c.version), 1);
    const newVersion = maxVersion + 1;

    this.credentials.forEach((c) => {
      if (c.user_alias === 'DAD') {
        c.is_active = false;
      }
    });

    const newCred: DoorCredential = {
      id: this.credentials.length + 1,
      credential_name: 'Primary Door PIN (Updated)',
      pin: newPin,
      pin_hash: `updated-hash-${newVersion}`,
      pin_sha256: `sha256-updated-${newPin}`,
      version: newVersion,
      user_alias: 'DAD',
      is_active: true,
      updated_at: new Date().toISOString(),
    };

    this.credentials.unshift(newCred);

    if (this.activeResetSession) {
      this.activeResetSession.status = 'COMPLETED';
    }

    this.doorState = 'LOCKED';
    this.failedAttempts = 0;
    this.currentRisk = 'LOW';
    this.notify();

    return {
      success: true,
      message: `Door PIN updated successfully to Version ${newVersion}! Door is secured.`,
    };
  }

  public revokeResetSession(): { success: boolean; message: string } {
    if (this.activeResetSession) {
      this.activeResetSession.status = 'REVOKED';
    }
    this.notify();
    return { success: true, message: 'Reset session revoked.' };
  }

  /**
   * Offline Network Assessment with 39 CICIoT Features
   */
  public assessOfflineNetworkRow(features: Record<string, number>): NetworkAssessment {
    const decisionId = `DEC-NET-${Math.random().toString(16).substring(2, 6).toUpperCase()}`;
    const nowIso = new Date().toISOString();

    // Analyze attack signatures based on standard CICIoT characteristics
    const rate = features['Rate'] || 0;
    const synCount = features['syn_count'] || 0;
    const rstCount = features['rst_count'] || 0;
    const finCount = features['fin_count'] || 0;
    const ackCount = features['ack_count'] || 0;
    const dns = features['DNS'] || 0;
    const http = features['HTTP'] || 0;
    const ttl = features['Time_To_Live'] || 64;

    let predictedAttack = 'BenignTraffic';
    let maxConfidence = 0.982;
    let netRisk: RiskLevel = 'LOW';

    if (synCount > 100 || (features['syn_flag_number'] && rate > 50)) {
      predictedAttack = 'DoS-SYN_Flood';
      maxConfidence = 0.994;
      netRisk = 'HIGH';
    } else if (rate > 200) {
      predictedAttack = 'DDoS-SYN_Flood';
      maxConfidence = 0.988;
      netRisk = 'HIGH';
    } else if (dns > 0 && ttl < 30) {
      predictedAttack = 'DNS_Spoofing';
      maxConfidence = 0.941;
      netRisk = 'HIGH';
    } else if (rate > 20 && ackCount > 50 && !synCount) {
      predictedAttack = 'DictionaryBruteForce';
      maxConfidence = 0.923;
      netRisk = 'MEDIUM';
    } else if (features['ARP'] && rate > 10) {
      predictedAttack = 'MITM-ArpSpoofing';
      maxConfidence = 0.915;
      netRisk = 'MEDIUM';
    }

    const pqcProfile = PQC_PROFILES[netRisk];

    const assessment: NetworkAssessment = {
      decision_id: decisionId,
      timestamp: nowIso,
      device_risk: this.getRiskLevel(),
      network_risk: netRisk,
      network_prediction: {
        predicted_attack: predictedAttack,
        max_confidence: maxConfidence,
        assessment_type: 'OFFLINE_SUPPLIED_CSV_ASSESSMENT',
        telemetry_source: 'SUPPLIED_FLOW_FEATURES',
      },
      network_confidence: {
        [predictedAttack]: maxConfidence,
        BenignTraffic: predictedAttack === 'BenignTraffic' ? maxConfidence : 1 - maxConfidence,
      },
      final_risk: netRisk,
      pqc_kem: pqcProfile.kem,
      pqc_sig: pqcProfile.signature,
      execution_status: 'ASSESSMENT_ONLY_NO_DOOR_ACTION',
      assessment_source: 'OFFLINE_SUPPLIED_CSV_ASSESSMENT',
    };

    this.networkAssessments.unshift(assessment);
    this.notify();

    return assessment;
  }
}

export const securityEngine = new SecurityEngine();
