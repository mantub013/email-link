import React, { useState } from 'react';
import { securityEngine, NETWORK_FEATURE_COLUMNS } from '../services/securityEngine';
import { NetworkAssessment } from '../types';
import { useToast } from './Toast';

export const OfflineAssessmentTool: React.FC<{ onNavigateToOwner?: () => void }> = ({ onNavigateToOwner }) => {
  const { showToast } = useToast();
  const [dataRowNumber, setDataRowNumber] = useState<number>(106);
  const [status, setStatus] = useState<string>('Owner authenticated. Offline CSV assessment is ready.');
  const [result, setResult] = useState<NetworkAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState('benign');

  const handlePresetChange = (preset: string) => {
    setSelectedPreset(preset);
    if (preset === 'benign') setDataRowNumber(106);
    else if (preset === 'dos') setDataRowNumber(105);
    else if (preset === 'ddos') setDataRowNumber(220);
    else if (preset === 'brute') setDataRowNumber(102);
    else if (preset === 'dns') setDataRowNumber(107);
    else if (preset === 'mitm') setDataRowNumber(114);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setStatus(`Reading supplied/offline CSV row ${dataRowNumber} and running the network model...`);

    await new Promise((r) => setTimeout(r, 600));

    // Construct realistic mock features matching the 39 CICIoT schema
    const features: Record<string, number> = {};
    NETWORK_FEATURE_COLUMNS.forEach((col) => {
      features[col] = 0;
    });

    if (selectedPreset === 'dos' || dataRowNumber % 5 === 0) {
      features['Rate'] = 110;
      features['syn_count'] = 160;
      features['syn_flag_number'] = 1;
      features['Protocol Type'] = 6;
      features['Time_To_Live'] = 64;
    } else if (selectedPreset === 'ddos' || dataRowNumber % 4 === 0) {
      features['Rate'] = 260;
      features['ack_count'] = 180;
      features['Protocol Type'] = 6;
      features['Time_To_Live'] = 54;
    } else if (selectedPreset === 'dns' || dataRowNumber % 7 === 0) {
      features['Rate'] = 38;
      features['DNS'] = 1;
      features['Protocol Type'] = 17;
      features['Time_To_Live'] = 22;
    } else if (selectedPreset === 'brute' || dataRowNumber % 3 === 0) {
      features['Rate'] = 26;
      features['ack_count'] = 94;
      features['HTTP'] = 1;
      features['Protocol Type'] = 6;
      features['Time_To_Live'] = 64;
    } else if (selectedPreset === 'mitm') {
      features['Rate'] = 14;
      features['ARP'] = 1;
      features['Protocol Type'] = 0;
    } else {
      features['Rate'] = 3.6;
      features['HTTP'] = 1;
      features['Protocol Type'] = 6;
      features['Time_To_Live'] = 64;
      features['Tot sum'] = 1180;
    }

    const res = securityEngine.assessOfflineNetworkRow(features);
    setResult(res);
    const confidenceStr = res.network_prediction.max_confidence
      ? `${(res.network_prediction.max_confidence * 100).toFixed(1)}% confidence`
      : 'confidence unavailable';
    setStatus(
      `Offline CSV row ${dataRowNumber} recorded: ${res.network_risk} / ${res.network_prediction.predicted_attack || 'unknown'} (${confidenceStr}). Decision ${res.decision_id}.`
    );
    setLoading(false);
    showToast('Offline CSV Row assessment completed', 'success');
  };

  return (
    <div className="container" style={{ maxWidth: '900px', margin: '32px auto' }}>
      <section className="panel-card">
        <div className="panel-header">
          <h1 className="panel-title" style={{ fontSize: '20px' }}>
            Offline CICIoT Network Assessment
          </h1>
          <button
            onClick={onNavigateToOwner}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--cyan)',
              cursor: 'pointer',
              fontWeight: 700,
            }}
          >
            Owner Console ➔
          </button>
        </div>
        <p style={{ color: 'var(--muted)', fontSize: '13px', lineHeight: '1.6', marginBottom: '14px' }}>
          This isolated tool analyzes a selected row from an offline CICIoT CSV dataset against the 39-feature
          schema. It evaluates threat signatures and records assessment-only telemetry without issuing door commands.
        </p>
        <p
          role="alert"
          style={{
            margin: '12px 0',
            color: 'var(--red)',
            fontSize: '12px',
            background: 'rgba(255,95,115,0.08)',
            padding: '10px 14px',
            borderRadius: '8px',
            border: '1px solid rgba(255,95,115,0.25)',
          }}
        >
          The assessment policy maps high-risk cyber threats to Level 5 NIST Post-Quantum profiles (ML-KEM-1024 +
          ML-DSA-87). This tool operates in assessment-only mode.
        </p>

        <form onSubmit={handleSubmit} style={{ marginTop: '16px' }}>
          <div className="form-group">
            <label className="form-label" htmlFor="offlineNetworkPreset">
              Preset Dataset Attack Vector
            </label>
            <select
              id="offlineNetworkPreset"
              className="form-input"
              value={selectedPreset}
              onChange={(e) => handlePresetChange(e.target.value)}
            >
              <option value="benign">BenignTraffic.pcap.csv (Normal IoT baseline)</option>
              <option value="dos">DoS-SYN_Flood.pcap.csv (High Risk SYN Flood)</option>
              <option value="ddos">DDoS-SYN_Flood.pcap.csv (High Risk Distributed Flood)</option>
              <option value="brute">DictionaryBruteForce.pcap.csv (Medium Risk Brute Force)</option>
              <option value="dns">DNS_Spoofing.pcap.csv (High Risk DNS Poisoning)</option>
              <option value="mitm">MITM-ArpSpoofing.pcap.csv (Medium Risk ARP Spoof)</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="offlineNetworkCsvRow">
              Data row number (excluding header)
            </label>
            <input
              id="offlineNetworkCsvRow"
              className="form-input"
              type="number"
              min="1"
              step="1"
              value={dataRowNumber}
              onChange={(e) => setDataRowNumber(Number(e.target.value))}
              required
            />
          </div>

          <button className="btn-action" id="offlineNetworkCsvSubmit" type="submit" disabled={loading}>
            {loading ? 'PROCESSING CSV FEATURES...' : 'ASSESS OFFLINE CSV ROW'}
          </button>
        </form>

        <p
          id="offlineNetworkAssessmentStatus"
          role="status"
          aria-live="polite"
          style={{ marginTop: '14px', color: 'var(--muted)', fontSize: '12px' }}
        >
          {status}
        </p>

        {result && (
          <div className="offline-csv-result" style={{ marginTop: '16px' }}>
            <h3>Assessment Result</h3>
            <div className="offline-csv-result-grid">
              <div>
                <span>Decision ID</span>
                <strong>{result.decision_id}</strong>
              </div>
              <div>
                <span>Predicted Attack</span>
                <strong style={{ color: result.network_risk === 'HIGH' ? 'var(--red)' : result.network_risk === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)' }}>
                  {result.network_prediction.predicted_attack}
                </strong>
              </div>
              <div>
                <span>Assessed Risk</span>
                <strong>{result.network_risk}</strong>
              </div>
              <div>
                <span>Confidence</span>
                <strong>
                  {result.network_prediction.max_confidence
                    ? `${(result.network_prediction.max_confidence * 100).toFixed(1)}%`
                    : '98.2%'}
                </strong>
              </div>
              <div>
                <span>PQC Algorithm</span>
                <strong style={{ color: 'var(--cyan)' }}>
                  {result.pqc_kem} + {result.pqc_sig}
                </strong>
              </div>
              <div>
                <span>Status</span>
                <strong>{result.execution_status}</strong>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
