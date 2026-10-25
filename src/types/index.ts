export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export type DoorState = 'LOCKED' | 'OPEN' | 'LOCKOUT';

export type ResetState = 'NORMAL' | 'RESET_WAITING_OTP' | 'RESET_NEW_PIN' | 'RESET_CONFIRM_PIN';

export interface PqcProfile {
  name: string;
  kem: string;
  signature: string;
  nist_level: string;
  description?: string;
  execution_mode?: string;
}

export interface SecurityEvent {
  id: string;
  event_id: string;
  decision_id: string;
  timestamp: string;
  source: 'WEB_UI' | 'ESP8266_KEYPAD' | 'OFFLINE_CSV' | 'OWNER_CONSOLE';
  attempted_hash: string;
  user: string;
  result: 'SUCCESS' | 'FAILED' | 'BLOCKED_HIGH_RISK';
  failed_attempt_count: number;
  ml_risk: RiskLevel;
  agent_risk: RiskLevel;
  final_risk?: RiskLevel;
  device_risk?: RiskLevel;
  network_risk?: string;
  network_attack?: string;
  network_confidence?: Record<string, number>;
  pqc_kem: string;
  pqc_sig: string;
  action_taken: string;
  reason: string;
}

export interface NetworkAssessment {
  decision_id: string;
  timestamp: string;
  device_risk: string;
  network_risk: string;
  network_prediction: {
    predicted_attack?: string;
    max_confidence?: number;
    assessment_type?: string;
    telemetry_source?: string;
    network_evidence_status?: string;
    model_inference_status?: string;
    confidence?: Record<string, number>;
  };
  network_confidence?: Record<string, number>;
  final_risk: string;
  pqc_kem: string;
  pqc_sig: string;
  execution_status: string;
  assessment_source: string;
}

export interface SecurityDecision {
  event_id?: string;
  decision_id: string;
  timestamp: string;
  source: string;
  result: string;
  device_risk: string;
  network_risk: string;
  final_risk: string;
  action: string;
}

export interface DoorCredential {
  id: number;
  credential_name: string;
  pin: string;
  pin_hash: string;
  pin_sha256: string;
  version: number;
  user_alias: string;
  is_active: boolean;
  updated_at: string;
}

export interface ResetSession {
  session_id: string;
  device_id: string;
  otp: string;
  created_at: number;
  expires_at: number;
  expires_in_seconds: number;
  status: 'PENDING' | 'OTP_VERIFIED' | 'COMPLETED' | 'REVOKED' | 'EXPIRED';
  attempt_count: number;
  max_attempts: number;
}

export interface DeviceTelemetry {
  is_online: boolean;
  ip_address: string;
  rssi: number;
  battery_level: number;
  cpu_utilization: number;
  memory_usage: number;
  communication_latency_ms: number;
  network_anomaly: number;
  threat_indicator: number;
  attempt_velocity: number;
  input_length: number;
}
