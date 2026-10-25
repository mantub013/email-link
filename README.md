# Agentic AI • Adaptive PQC Smart Door Lock

A modern React + TypeScript web application providing an autonomous quantum-resistant smart door lock security console, powered by an 8-node LangGraph agent, Random Forest intrusion classification, and adaptive NIST Post-Quantum Cryptography (PQC).

## Core Features

- **Autonomous Quantum-Resistant Door Control**:
  - Interactive 3D simulated door visualizer with dynamic lock/unlock states, open leaf rotation, status pills, and actuator overrides.
  - 4x4 matrix virtual keypad with end-to-end masked PIN display (`●`/`○`), physical keyboard listener, and quick simulation triggers.
  - Multi-step **AABB Password Reset Sequence**: Enter `AABB` or trigger reset -> awaits 6-digit Owner OTP -> verifies OTP -> sets and confirms new 4-digit PIN with credential versioning.
  - Default authorized credentials:
    - `1234` -> DAD
    - `5678` -> MOM
- **8-Node LangGraph Autonomous Security Pipeline**:
  - `OBSERVE`: Scans device telemetry, failure counters, velocity, and network anomaly flags.
  - `ASSESS`: Runs Random Forest risk perception and confidence scoring.
  - `REASSESS`: Applies attempt velocity and progressive escalation thresholds.
  - `PLAN`: Selects optimal strategy matrix and NIST PQC suite.
  - `DECIDE`: Issues definitive authorization decisions (`ALLOW`, `DENY`, `LOCKOUT`).
  - `ACT`: Activates the selected PQC profile and actuation policies.
  - `RECOMMEND`: Generates advisories and incident mitigation guidance.
  - `REFLECT`: Validates cycle closure, model agreement, and 8-node traversal.
- **Adaptive NIST Post-Quantum Cryptography**:
  - **LOW RISK (Level 1)**: ML-KEM-512 + ML-DSA-44 (Kyber-512 / Dilithium-2)
  - **MEDIUM RISK (Level 3)**: ML-KEM-768 + ML-DSA-65 (Kyber-768 / Dilithium-3)
  - **HIGH RISK (Level 5)**: ML-KEM-1024 + ML-DSA-87 (Kyber-1024 / Dilithium-5)
- **Owner Security Operations Center**:
  - Authentication barrier (default admin / admin)
  - Overview telemetry cards (Actuator State, Hardware Node status, AI Risk Level, Active PQC Suite)
  - Door actuator overrides (Force Unlock / Lock) and subsystem health telemetry
  - Cryptographic 6-digit OTP generator with live 120s countdown timer and revocation
  - Direct web password reset form
  - Risk analytics and intrusion velocity metrics with interactive risk distribution bars
  - Real-time immutable security audit stream table
- **CICIoT Network Assessment**:
  - Analysis against the 39-feature CICIoT2023 schema with preset attack vectors (Benign, DoS-SYN_Flood, DDoS, DictionaryBruteForce, DNS_Spoofing, MITM-ArpSpoofing)
  - Historical network assessment logging

## Running the Application

```bash
# Install dependencies
npm install

# Start development server on port 3000
npm run dev

# Production build
npm run build
```
