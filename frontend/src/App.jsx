import React, { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, Search, Download, FileText,
  Activity, Layers, BarChart2, BookOpen, Settings, RefreshCw,
  ExternalLink, Lock, Globe, Server, Check, HelpCircle
} from 'lucide-react';

// Default Render Backend URL (Falls back to local if unset, or user configurable)
const DEFAULT_API_BASE = import.meta.env.VITE_API_URL || (window.location.hostname === 'localhost' ? 'http://localhost:8000' : '');

export default function App() {
  const [activeTab, setActiveTab] = useState('home');
  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_API_BASE);
  const [showSettings, setShowSettings] = useState(false);
  const [backendStatus, setBackendStatus] = useState('checking'); // 'online' | 'offline' | 'checking'
  
  // Scan state
  const [inputUrl, setInputUrl] = useState('');
  const [selectedPreset, setSelectedPreset] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState('');
  const [isExportingPdf, setIsExportingPdf] = useState(false);

  // Model comparison benchmarks state
  const [modelData, setModelData] = useState(null);
  const [selectedStage, setSelectedStage] = useState(1);

  // Demo Presets
  const presets = [
    { label: "-- Choose a demo URL to test --", url: "" },
    { label: "Legitimate: Google Search (Safe query)", url: "https://www.google.com/search?q=machine+learning+tutorial" },
    { label: "Legitimate: Wikipedia Article (Clean)", url: "https://en.wikipedia.org/wiki/Phishing" },
    { label: "Legitimate: GitHub Repository (Standard repo)", url: "https://github.com/scikit-learn/scikit-learn" },
    { label: "Legitimate: Amazon Store (Standard e-commerce)", url: "https://www.amazon.com/gp/bestsellers" },
    { label: "Phishing: IP Literal Host (Evades domain filters)", url: "http://192.168.1.105/webscr/login.php?cmd=login_submit" },
    { label: "Phishing: Hyphenated Apple Spoof (Typosquatting)", url: "http://apple-id-verify-account.support-service.net/auth/" },
    { label: "Phishing: Subdomain Chaining (Hides real domain)", url: "http://login.verification.secure.banking.paypal.com.fraudulent-host.org/webscr" },
    { label: "Phishing: Userinfo @ Spoof (Redirect trick)", url: "http://legit-service.com@attacker-site.com/steal-login?user=victim" },
    { label: "Phishing: URL Shortener Mask (Concealed destination)", url: "http://bit.ly/secure-paypal-login-verify" },
    { label: "Phishing: Non-Standard Port (Rogue web server)", url: "http://45.142.214.88:8080/secure-update/account-verify/" }
  ];

  // Check backend health on mount and when apiBaseUrl changes
  useEffect(() => {
    checkBackendHealth();
    fetchModelBenchmarks();
  }, [apiBaseUrl]);

  const checkBackendHealth = async () => {
    setBackendStatus('checking');
    try {
      const url = apiBaseUrl ? `${apiBaseUrl}/api/health` : '/api/health';
      const res = await fetch(url);
      if (res.ok) {
        setBackendStatus('online');
      } else {
        setBackendStatus('offline');
      }
    } catch {
      setBackendStatus('offline');
    }
  };

  const fetchModelBenchmarks = async () => {
    try {
      const url = apiBaseUrl ? `${apiBaseUrl}/api/models` : '/api/models';
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setModelData(data);
      }
    } catch (err) {
      console.warn("Could not load backend benchmarks, using pre-calculated held-out metrics", err);
    }
  };

  const handleScan = async (targetUrl = inputUrl) => {
    const urlToTest = targetUrl.trim();
    if (!urlToTest) {
      setScanError("Please enter a website URL or select a demo preset.");
      return;
    }
    setScanError('');
    setIsLoading(true);

    try {
      const endpoint = apiBaseUrl ? `${apiBaseUrl}/api/scan` : '/api/scan';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToTest })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Scan request failed with HTTP ${res.status}`);
      }

      const data = await res.json();
      if (!data.is_valid) {
        setScanError(data.error_message || "Invalid URL syntax.");
        setScanResult(null);
      } else {
        setScanResult(data);
      }
    } catch (err) {
      setScanError(err.message || "Failed to communicate with Render backend. Check Render URL in Settings.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!scanResult || !scanResult.normalized_url) return;
    setIsExportingPdf(true);

    try {
      const endpoint = apiBaseUrl ? `${apiBaseUrl}/api/report` : '/api/report';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanResult.normalized_url })
      });

      if (!res.ok) throw new Error("PDF report generation failed on server.");

      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `PhishGuard_Report_${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      alert("Error downloading PDF report: " + err.message);
    } finally {
      setIsExportingPdf(false);
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div style={{ padding: '24px 20px 16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ background: '#0EA5E9', padding: '8px', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={24} color="#0B1120" strokeWidth={2.5} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#F8FAFC', letterSpacing: '-0.3px', margin: 0 }}>PhishGuard AI</h2>
              <div style={{ fontSize: '0.7rem', color: '#0EA5E9', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Detect Phishing. Browse Safely.
              </div>
            </div>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '10px' }}>
            Supervised ML: Decision Tree & Random Forest
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ padding: '16px 12px', flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {[
            { id: 'home', label: 'Home', icon: Shield },
            { id: 'analysis', label: 'URL Analysis', icon: Activity },
            { id: 'process', label: 'Analysis Process', icon: Layers },
            { id: 'comparison', label: 'Model Comparison', icon: BarChart2 },
            { id: 'about', label: 'About Project', icon: BookOpen }
          ].map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  width: '100%',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  border: 'none',
                  background: isActive ? 'rgba(14, 165, 233, 0.15)' : 'transparent',
                  color: isActive ? '#38BDF8' : '#94A3B8',
                  fontWeight: isActive ? 600 : 500,
                  fontSize: '0.92rem',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={18} color={isActive ? '#38BDF8' : '#64748B'} />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Active Scan Context & Backend Status */}
        <div style={{ padding: '16px', borderTop: '1px solid var(--border-subtle)', background: 'rgba(0,0,0,0.2)' }}>
          {scanResult ? (
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '0.72rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700 }}>Current URL</div>
              <div style={{ fontSize: '0.8rem', color: '#0EA5E9', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {scanResult.normalized_url}
              </div>
              <div style={{ marginTop: '4px' }}>
                <span className={scanResult.prediction_result?.final_prediction_name === 'Phishing' ? 'badge badge-phish' : 'badge badge-safe'}>
                  {scanResult.prediction_result?.final_prediction_name?.toUpperCase()}
                </span>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: '0.78rem', color: '#64748B', marginBottom: '12px' }}>
              No URL scanned yet. Enter a link on <strong>Home</strong> to evaluate.
            </div>
          )}

          {/* Backend Status Pill */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: backendStatus === 'online' ? '#10B981' : backendStatus === 'checking' ? '#F59E0B' : '#EF4444'
              }}></span>
              <span style={{ fontSize: '0.75rem', color: '#94A3B8' }}>
                Render API: {backendStatus === 'online' ? 'Connected' : backendStatus === 'checking' ? 'Connecting...' : 'Disconnected'}
              </span>
            </div>
            <button
              onClick={() => setShowSettings(!showSettings)}
              style={{ background: 'transparent', border: 'none', color: '#64748B', cursor: 'pointer', padding: '2px' }}
              title="Configure Backend API URL"
            >
              <Settings size={14} />
            </button>
          </div>

          {/* Settings Popover */}
          {showSettings && (
            <div style={{ marginTop: '10px', background: '#131C31', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.75rem', color: '#F8FAFC', marginBottom: '4px', fontWeight: 600 }}>Render Backend URL</div>
              <input
                type="text"
                value={apiBaseUrl}
                onChange={(e) => setApiBaseUrl(e.target.value)}
                placeholder="https://your-api.onrender.com"
                style={{ width: '100%', fontSize: '0.75rem', padding: '6px 8px', background: '#0B1120', border: '1px solid rgba(255,255,255,0.2)', color: '#FFF', borderRadius: '4px', marginBottom: '6px' }}
              />
              <button
                onClick={() => { setShowSettings(false); checkBackendHealth(); }}
                style={{ width: '100%', fontSize: '0.75rem', padding: '4px', background: '#0EA5E9', border: 'none', color: '#FFF', borderRadius: '4px', cursor: 'pointer' }}
              >
                Save & Reconnect
              </button>
            </div>
          )}

          <div style={{ fontSize: '0.7rem', color: '#475569', marginTop: '10px', lineHeight: 1.3 }}>
            🛡️ <strong>Zero-Network Parsing:</strong> Analyzed statically in-memory. Zero target websites contacted.
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {activeTab === 'home' && renderHomeTab()}
        {activeTab === 'analysis' && renderAnalysisTab()}
        {activeTab === 'process' && renderProcessTab()}
        {activeTab === 'comparison' && renderComparisonTab()}
        {activeTab === 'about' && renderAboutTab()}
      </main>
    </div>
  );

  // ==========================================
  // TAB 1: HOME PAGE
  // ==========================================
  function renderHomeTab() {
    return (
      <div>
        {/* Hero Header */}
        <div className="glass-card" style={{ marginBottom: '20px', padding: '22px 26px', borderLeft: '4px solid #0EA5E9' }}>
          <div style={{ color: '#0EA5E9', fontSize: '0.82rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
            Detect Phishing. Browse Safely.
          </div>
          <h1 style={{ fontSize: '1.85rem', fontWeight: 800, color: '#F8FAFC', margin: '0 0 6px 0', letterSpacing: '-0.5px' }}>
            PhishGuard AI
          </h1>
          <div style={{ color: '#38BDF8', fontSize: '0.98rem', fontWeight: 600, marginBottom: '6px' }}>
            Phishing Website Detection Using URL-Based Feature Extraction with Decision Tree and Random Forest Algorithms
          </div>
          <div style={{ color: '#94A3B8', fontSize: '0.88rem' }}>
            PhishGuard AI evaluates website URLs using 18 static lexical features to detect potential phishing threats without ever contacting, crawling, or downloading the destination website.
          </div>
        </div>

        {/* Input & Demo Selector Section */}
        <div className="glass-card" style={{ marginBottom: '20px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '14px' }}>
            {/* Demo Presets Dropdown */}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', color: '#94A3B8', fontWeight: 600, marginBottom: '6px' }}>
                Quick Demo Presets (Examples only):
              </label>
              <select
                className="select-input"
                value={selectedPreset}
                onChange={(e) => {
                  setSelectedPreset(e.target.value);
                  if (e.target.value) {
                    setInputUrl(e.target.value);
                    handleScan(e.target.value);
                  }
                }}
              >
                {presets.map((p, idx) => (
                  <option key={idx} value={p.url}>{p.label}</option>
                ))}
              </select>
            </div>

            {/* URL Input Box */}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', color: '#94A3B8', fontWeight: 600, marginBottom: '6px' }}>
                Target Website URL:
              </label>
              <input
                type="text"
                className="text-input"
                placeholder="e.g. paypal-security-update.com/login.php or https://example.com"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <button
              className="btn-primary"
              onClick={() => handleScan()}
              disabled={isLoading}
              style={{ flex: 1, justifyContent: 'center' }}
            >
              {isLoading ? (
                <>
                  <RefreshCw size={18} className="spinner" />
                  Analyzing 18 Lexical Features & Running ML Classifiers...
                </>
              ) : (
                <>
                  <Search size={18} />
                  Check URL Safety
                </>
              )}
            </button>
            {inputUrl && (
              <button
                className="btn-secondary"
                onClick={() => { setInputUrl(''); setScanResult(null); setScanError(''); }}
              >
                Clear
              </button>
            )}
          </div>

          {scanError && (
            <div style={{ marginTop: '14px', padding: '12px 16px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', color: '#EF4444', fontSize: '0.88rem' }}>
              ⚠️ {scanError}
            </div>
          )}
        </div>

        {/* Scan Results Display */}
        {scanResult && (
          <div>
            {/* Visual Summary Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', marginBottom: '18px' }}>
              <div className="glass-card" style={{ padding: '14px 18px' }}>
                <div style={{ fontSize: '0.75rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700 }}>Input Status</div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#10B981', margin: '4px 0' }}>Valid URL String</div>
                <div style={{ fontSize: '0.78rem', color: '#64748B' }}>Length: {scanResult.normalized_url.length} chars</div>
              </div>

              <div className="glass-card" style={{ padding: '14px 18px' }}>
                <div style={{ fontSize: '0.75rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700 }}>Protocol Scheme</div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#0EA5E9', margin: '4px 0' }}>
                  {scanResult.parsed_components?.scheme?.toUpperCase() || 'HTTPS'}
                </div>
                <div style={{ fontSize: '0.78rem', color: '#64748B' }}>Normalized for lexical parsing</div>
              </div>

              <div className="glass-card" style={{ padding: '14px 18px' }}>
                <div style={{ fontSize: '0.75rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700 }}>Features Extracted</div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#F8FAFC', margin: '4px 0' }}>
                  {Object.keys(scanResult.features_dict || {}).length} / 18 Features
                </div>
                <div style={{ fontSize: '0.78rem', color: '#64748B' }}>Zero network requests made</div>
              </div>

              <div className="glass-card" style={{ padding: '14px 18px' }}>
                <div style={{ fontSize: '0.75rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700 }}>Model Consensus</div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, color: scanResult.prediction_result?.consensus ? '#10B981' : '#F59E0B', margin: '4px 0' }}>
                  {scanResult.prediction_result?.consensus ? 'Agreed (Unanimous)' : 'Disagreement'}
                </div>
                <div style={{ fontSize: '0.78rem', color: '#64748B' }}>DT vs. RF validation</div>
              </div>
            </div>

            {/* Dual Model Prediction Cards */}
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC', marginBottom: '12px' }}>
              🤖 Supervised Classifier Predictions
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginBottom: '18px' }}>
              {/* Decision Tree Card */}
              {scanResult.prediction_result?.dt && (
                <div className="glass-card" style={{ borderTop: `4px solid ${scanResult.prediction_result.dt.prediction_name === 'Phishing' ? '#EF4444' : '#10B981'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '0.78rem', color: '#14B8A6', fontWeight: 700, textTransform: 'uppercase' }}>MODEL 1</span>
                    <span className={scanResult.prediction_result.dt.prediction_name === 'Phishing' ? 'badge badge-phish' : 'badge badge-safe'}>
                      {scanResult.prediction_result.dt.prediction_name === 'Phishing' ? 'POTENTIAL PHISHING' : 'LIKELY LEGITIMATE'}
                    </span>
                  </div>
                  <h4 style={{ fontSize: '1.15rem', color: '#F8FAFC', margin: '0 0 4px 0' }}>Decision Tree Classifier</h4>
                  <p style={{ fontSize: '0.82rem', color: '#94A3B8', margin: '0 0 12px 0' }}>
                    Rule-based CART algorithm with explainable if-then paths.
                  </p>
                  
                  {/* Probability Bar */}
                  <div style={{ marginBottom: '10px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '4px' }}>
                      <span style={{ color: '#94A3B8' }}>Model Estimate:</span>
                      <strong style={{ color: '#F8FAFC' }}>{(scanResult.prediction_result.dt.confidence * 100).toFixed(1)}%</strong>
                    </div>
                    <div style={{ width: '100%', height: '8px', background: '#0B1120', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${scanResult.prediction_result.dt.confidence * 100}%`,
                        height: '100%',
                        background: scanResult.prediction_result.dt.prediction_name === 'Phishing' ? '#EF4444' : '#10B981',
                        borderRadius: '4px'
                      }}></div>
                    </div>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#64748B' }}>
                    Latency: {scanResult.prediction_result.dt.latency_ms?.toFixed(2)} ms
                  </div>
                </div>
              )}

              {/* Random Forest Card */}
              {scanResult.prediction_result?.rf && (
                <div className="glass-card" style={{ borderTop: `4px solid ${scanResult.prediction_result.rf.prediction_name === 'Phishing' ? '#EF4444' : '#10B981'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '0.78rem', color: '#0EA5E9', fontWeight: 700, textTransform: 'uppercase' }}>MODEL 2 (RECOMMENDED)</span>
                    <span className={scanResult.prediction_result.rf.prediction_name === 'Phishing' ? 'badge badge-phish' : 'badge badge-safe'}>
                      {scanResult.prediction_result.rf.prediction_name === 'Phishing' ? 'POTENTIAL PHISHING' : 'LIKELY LEGITIMATE'}
                    </span>
                  </div>
                  <h4 style={{ fontSize: '1.15rem', color: '#F8FAFC', margin: '0 0 4px 0' }}>Random Forest Classifier</h4>
                  <p style={{ fontSize: '0.82rem', color: '#94A3B8', margin: '0 0 12px 0' }}>
                    150-tree bagging ensemble reducing single-tree variance.
                  </p>
                  
                  {/* Probability Bar */}
                  <div style={{ marginBottom: '10px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '4px' }}>
                      <span style={{ color: '#94A3B8' }}>Model Estimate:</span>
                      <strong style={{ color: '#F8FAFC' }}>{(scanResult.prediction_result.rf.confidence * 100).toFixed(1)}%</strong>
                    </div>
                    <div style={{ width: '100%', height: '8px', background: '#0B1120', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${scanResult.prediction_result.rf.confidence * 100}%`,
                        height: '100%',
                        background: scanResult.prediction_result.rf.prediction_name === 'Phishing' ? '#EF4444' : '#10B981',
                        borderRadius: '4px'
                      }}></div>
                    </div>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#64748B' }}>
                    Latency: {scanResult.prediction_result.rf.latency_ms?.toFixed(2)} ms
                  </div>
                </div>
              )}
            </div>

            {/* Final Classification Verdict Banner */}
            {scanResult.prediction_result && (
              <div
                className="glass-card"
                style={{
                  marginBottom: '18px',
                  borderLeft: `6px solid ${scanResult.prediction_result.final_prediction_name === 'Phishing' ? '#EF4444' : '#10B981'}`,
                  padding: '22px 26px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '14px' }}>
                  <div>
                    <div style={{ fontSize: '0.78rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700 }}>
                      FINAL CLASSIFICATION VERDICT
                    </div>
                    <h2 style={{
                      fontSize: '1.8rem',
                      fontWeight: 800,
                      color: scanResult.prediction_result.final_prediction_name === 'Phishing' ? '#EF4444' : '#10B981',
                      margin: '4px 0 8px 0',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px'
                    }}>
                      {scanResult.prediction_result.final_prediction_name === 'Phishing' ? (
                        <>🚨 POTENTIAL PHISHING</>
                      ) : (
                        <>🛡️ LIKELY LEGITIMATE</>
                      )}
                    </h2>
                    <p style={{ color: '#CBD5E1', fontSize: '0.92rem', margin: '0 0 6px 0', maxWidth: '700px', lineHeight: 1.5 }}>
                      {scanResult.prediction_result.summary_explanation}
                    </p>
                    <div style={{ fontSize: '0.85rem', color: scanResult.prediction_result.consensus ? '#10B981' : '#F59E0B' }}>
                      {scanResult.prediction_result.consensus
                        ? '✅ Model Consensus: Both Decision Tree and Random Forest reached identical conclusions.'
                        : '⚠️ Model Disagreement: Classifiers produced differing outputs. Defaulting to Random Forest due to ensemble variance reduction.'}
                    </div>
                  </div>

                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.78rem', color: '#94A3B8' }}>Selected Primary Model</div>
                    <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#0EA5E9' }}>
                      {scanResult.prediction_result.selected_model}
                    </div>
                    <div style={{ fontSize: '0.85rem', color: '#CBD5E1', marginTop: '4px' }}>
                      Confidence: <strong>{(scanResult.prediction_result.final_confidence * 100).toFixed(1)}%</strong>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Download PDF Report Action */}
            <div className="glass-card" style={{ marginBottom: '18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <h4 style={{ fontSize: '1.05rem', color: '#F8FAFC', margin: '0 0 4px 0' }}>
                  📄 Export Security Intelligence Report
                </h4>
                <div style={{ fontSize: '0.85rem', color: '#94A3B8' }}>
                  Generates an audit-ready cybersecurity PDF report from the actual scan data.
                </div>
              </div>
              <button
                className="btn-primary"
                onClick={handleDownloadPdf}
                disabled={isExportingPdf}
              >
                {isExportingPdf ? (
                  <>
                    <RefreshCw size={18} className="spinner" />
                    Generating PDF...
                  </>
                ) : (
                  <>
                    <Download size={18} />
                    Download Scan Report (PDF)
                  </>
                )}
              </button>
            </div>

            {/* Key Structural Risk Indicators */}
            {scanResult.risk_indicators && scanResult.risk_indicators.length > 0 && (
              <div style={{ marginBottom: '18px' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC', marginBottom: '12px' }}>
                  ⚠️ Key Structural Risk Indicators
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
                  {scanResult.risk_indicators.map((ind, i) => {
                    const borderCol = ind.severity === 'High' ? '#EF4444' : ind.severity === 'Medium' ? '#F59E0B' : '#10B981';
                    return (
                      <div key={i} className="glass-card" style={{ borderLeft: `4px solid ${borderCol}`, padding: '14px 18px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <strong style={{ fontSize: '0.92rem', color: '#F8FAFC' }}>{ind.display_title}</strong>
                          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: borderCol }}>{ind.severity} Severity</span>
                        </div>
                        <div style={{ fontSize: '0.85rem', color: '#0EA5E9', fontFamily: 'monospace', marginBottom: '6px' }}>
                          Value: {ind.value}
                        </div>
                        <div style={{ fontSize: '0.82rem', color: '#94A3B8', lineHeight: 1.4 }}>
                          {ind.explanation}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Disclaimer */}
            <div style={{ fontSize: '0.82rem', color: '#64748B', fontStyle: 'italic', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
              🛡️ {scanResult.disclaimer}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ==========================================
  // TAB 2: URL ANALYSIS
  // ==========================================
  function renderAnalysisTab() {
    if (!scanResult) {
      return (
        <div className="glass-card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <Activity size={48} color="#64748B" style={{ margin: '0 auto 16px auto' }} />
          <h3 style={{ fontSize: '1.3rem', color: '#F8FAFC', marginBottom: '8px' }}>No Active URL Scan Found</h3>
          <p style={{ color: '#94A3B8', maxWidth: '500px', margin: '0 auto 20px auto', fontSize: '0.92rem' }}>
            To inspect extracted structural features and URL anatomy, please enter a website address on the <strong>Home</strong> page and click <strong>Check URL</strong>.
          </p>
          <button className="btn-primary" onClick={() => setActiveTab('home')}>Go to Home</button>
        </div>
      );
    }

    const parsed = scanResult.parsed_components || {};
    const feats = scanResult.features_dict || {};

    const featureCards = [
      { key: "url_length", title: "URL Length", icon: "📏", desc: "Total characters in the URL string", status: (v) => v > 85 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "hostname_length", title: "Hostname Length", icon: "🌐", desc: "Character count of the domain name", status: (v) => v > 32 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "path_length", title: "Path Length", icon: "📂", desc: "Character count of directory path segments", status: (v) => v > 45 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "query_length", title: "Query Length", icon: "❓", desc: "Character count of parameter query string", status: (v) => v > 40 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "count_dots", title: "Dot Count", icon: "⚪", desc: "Frequency of '.' characters in URL", status: (v) => v >= 4 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "count_hyphens", title: "Hyphen Count", icon: "➖", desc: "Frequency of '-' characters (brand typosquatting)", status: (v) => v >= 2 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "count_at", title: "Userinfo Symbol (@)", icon: "📧", desc: "Userinfo redirection marker in host string", status: (v) => v > 0 ? ["Unusual indicator", "#EF4444"] : ["Not detected", "#64748B"] },
      { key: "count_digits", title: "Digit Count", icon: "🔢", desc: "Numerical digit frequency throughout URL", status: (v) => v > 8 ? ["Unusual indicator", "#F59E0B"] : ["Normal indicator", "#10B981"] },
      { key: "count_subdomains", title: "Subdomain Depth", icon: "🏢", desc: "Hierarchy levels preceding base domain", status: (v) => v >= 3 ? ["Unusual indicator", "#EF4444"] : ["Normal indicator", "#10B981"] },
      { key: "is_ip_address", title: "Raw IP Literal", icon: "💻", desc: "Host is IPv4/IPv6 address instead of domain", status: (v) => v === 1 ? ["Unusual indicator", "#EF4444"] : ["Not detected", "#64748B"] },
      { key: "is_https", title: "HTTPS Protocol", icon: "🔒", desc: "Encrypted scheme (HTTPS ≠ legitimacy)", status: (v) => v === 1 ? ["Normal indicator", "#10B981"] : ["Unusual indicator", "#F59E0B"] },
      { key: "is_shortener", title: "URL Shortener", icon: "✂️", desc: "Matches known URL shortener service", status: (v) => v === 1 ? ["Unusual indicator", "#F59E0B"] : ["Not detected", "#64748B"] },
      { key: "has_suspicious_keyword", title: "Sensitive Keywords", icon: "🔑", desc: "Tokens: login, verify, banking, update", status: (v) => v === 1 ? ["Unusual indicator", "#EF4444"] : ["Not detected", "#64748B"] },
      { key: "has_unusual_port", title: "Unusual Port", icon: "🚪", desc: "Port outside standard HTTP(80) / HTTPS(443)", status: (v) => v === 1 ? ["Unusual indicator", "#EF4444"] : ["Not detected", "#64748B"] },
      { key: "count_percent", title: "Percent Obfuscation", icon: "🔣", desc: "Hex percent-encoding markers (%20, %2E)", status: (v) => v > 0 ? ["Unusual indicator", "#EF4444"] : ["Not detected", "#64748B"] },
      { key: "count_question", title: "Question Marks", icon: "❔", desc: "Query delimiter symbol count", status: (v) => v <= 1 ? ["Normal indicator", "#10B981"] : ["Unusual indicator", "#F59E0B"] },
      { key: "count_equal", title: "Equals Symbols", icon: "🟰", desc: "Parameter assignment symbol count", status: (v) => v <= 3 ? ["Normal indicator", "#10B981"] : ["Unusual indicator", "#F59E0B"] },
      { key: "count_ampersand", title: "Ampersand Symbols", icon: "🔗", desc: "Parameter concatenation symbol count", status: (v) => v <= 3 ? ["Normal indicator", "#10B981"] : ["Unusual indicator", "#F59E0B"] },
    ];

    return (
      <div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#F8FAFC', marginBottom: '6px' }}>🔬 URL Analysis</h2>
        <p style={{ color: '#94A3B8', fontSize: '0.92rem', marginBottom: '20px' }}>
          Deep-dive inspection of 18 static lexical and structural characteristics extracted from the target URL.
        </p>

        {/* Parsed Anatomy Card */}
        <div className="glass-card" style={{ marginBottom: '20px' }}>
          <h3 style={{ fontSize: '1.1rem', color: '#0EA5E9', marginBottom: '12px' }}>
            🧩 Parsed URL Structural Anatomy (RFC 3986 Components)
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px', marginBottom: '14px' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Protocol Scheme</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#F8FAFC' }}>{parsed.scheme?.toUpperCase() || 'HTTPS'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Target Hostname</div>
              <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#0EA5E9', fontFamily: 'monospace' }}>{parsed.hostname || 'N/A'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Destination Port</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#F8FAFC' }}>{parsed.port || 'Standard (80/443)'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Query Parameters</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: parsed.has_query ? '#F59E0B' : '#10B981' }}>
                {parsed.has_query ? 'Present' : 'None'}
              </div>
            </div>
          </div>
          <div style={{ fontSize: '0.82rem', color: '#64748B' }}>
            Path: <code style={{ color: '#CBD5E1' }}>{parsed.path || '/'}</code>
          </div>
        </div>

        {/* 18 Features Responsive Grid */}
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC', marginBottom: '14px' }}>
          📊 Canonical 18-Dimensional Feature Matrix
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
          {featureCards.map((f, idx) => {
            const rawVal = feats[f.key] ?? 0;
            const [statusText, statusCol] = f.status(rawVal);
            const displayVal = (f.key.startsWith('is_') || f.key.startsWith('has_'))
              ? (rawVal === 1 ? 'Active (Yes)' : 'Inactive (No)')
              : rawVal;

            return (
              <div key={idx} className="glass-card" style={{ borderLeft: `3px solid ${statusCol}`, padding: '14px 16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.92rem', fontWeight: 600, color: '#F8FAFC' }}>{f.icon} {f.title}</span>
                  <span style={{ fontSize: '0.72rem', fontWeight: 700, color: statusCol, padding: '2px 8px', borderRadius: '10px', background: 'rgba(255,255,255,0.04)', border: `1px solid ${statusCol}` }}>
                    {statusText}
                  </span>
                </div>
                <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#0EA5E9', margin: '4px 0' }}>
                  {displayVal}
                </div>
                <div style={{ fontSize: '0.78rem', color: '#94A3B8', lineHeight: 1.3 }}>
                  {f.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  // ==========================================
  // TAB 3: ANALYSIS PROCESS
  // ==========================================
  function renderProcessTab() {
    const stages = [
      {
        num: 1,
        title: "URL Validation",
        status: scanResult ? "COMPLETED" : "WAITING",
        desc: "Sanitizes raw string, checks length bounds (<= 2048 chars), and rejects unprintable control characters.",
        detail: scanResult ? `Target passed validation with ${scanResult.normalized_url?.length} characters.` : "Awaiting user URL input on Home."
      },
      {
        num: 2,
        title: "URL Parsing",
        status: scanResult ? "COMPLETED" : "WAITING",
        desc: "Decomposes string into RFC 3986 components (Scheme, Hostname, Port, Path, Query, Fragment).",
        detail: scanResult ? `Scheme: ${scanResult.parsed_components?.scheme?.toUpperCase()}, Host: ${scanResult.parsed_components?.hostname}. Done in-memory (0 network).` : "Awaiting parsed components."
      },
      {
        num: 3,
        title: "Feature Extraction",
        status: scanResult ? "18/18 EXTRACTED" : "WAITING",
        desc: "Computes canonical 18-dimensional feature vector (lengths, delimiters, IPs, keywords, ports).",
        detail: scanResult ? `Extracted 18 structural and lexical measurements strictly aligned with trained models.` : "Awaiting feature vector extraction."
      },
      {
        num: 4,
        title: "Decision Tree (CART)",
        status: scanResult ? scanResult.prediction_result?.dt?.prediction_name?.toUpperCase() : "WAITING",
        desc: "Single CART decision tree evaluates feature split thresholds along its trained paths.",
        detail: scanResult ? `Confidence: ${(scanResult.prediction_result?.dt?.confidence * 100).toFixed(1)}%. Latency: ${scanResult.prediction_result?.dt?.latency_ms?.toFixed(2)} ms.` : "Awaiting CART inference."
      },
      {
        num: 5,
        title: "Random Forest (RF)",
        status: scanResult ? scanResult.prediction_result?.rf?.prediction_name?.toUpperCase() : "WAITING",
        desc: "150 decorrelated decision trees aggregate votes across random feature subspaces.",
        detail: scanResult ? `Confidence: ${(scanResult.prediction_result?.rf?.confidence * 100).toFixed(1)}%. Multi-tree bagging eliminates single-tree variance.` : "Awaiting ensemble voting."
      },
      {
        num: 6,
        title: "Final Classification",
        status: scanResult ? scanResult.prediction_result?.final_prediction_name?.toUpperCase() : "WAITING",
        desc: "Evaluates consensus between DT and RF; defaults to RF on disagreement via variance policy.",
        detail: scanResult ? `Verdict: ${scanResult.prediction_result?.final_prediction_name}. Consensus: ${scanResult.prediction_result?.consensus ? 'Unanimous' : 'Disagreement'}.` : "Awaiting verdict synthesis."
      }
    ];

    return (
      <div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#F8FAFC', marginBottom: '6px' }}>⚙️ Analysis Process</h2>
        <p style={{ color: '#94A3B8', fontSize: '0.92rem', marginBottom: '24px' }}>
          Interactive demonstration showing the 6 sequential stages executed during URL risk evaluation.
        </p>

        {/* 6 Stage Timeline Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          {stages.map((s) => {
            const isSelected = selectedStage === s.num;
            const isCompleted = s.status !== 'WAITING';
            return (
              <div
                key={s.num}
                className="glass-card"
                onClick={() => setSelectedStage(s.num)}
                style={{
                  cursor: 'pointer',
                  borderTop: `4px solid ${isSelected ? '#0EA5E9' : isCompleted ? '#10B981' : '#64748B'}`,
                  background: isSelected ? '#1A2642' : 'var(--bg-card)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  minHeight: '190px'
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '0.78rem', color: '#94A3B8', fontWeight: 700 }}>STAGE {s.num}</span>
                    <span style={{
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      color: isCompleted ? '#10B981' : '#94A3B8',
                      border: `1px solid ${isCompleted ? '#10B981' : '#94A3B8'}`,
                      padding: '2px 8px',
                      borderRadius: '10px'
                    }}>
                      {s.status}
                    </span>
                  </div>
                  <h4 style={{ fontSize: '1.05rem', color: '#F8FAFC', margin: '0 0 6px 0' }}>{s.title}</h4>
                  <p style={{ fontSize: '0.82rem', color: '#CBD5E1', lineHeight: 1.4 }}>{s.desc}</p>
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748B', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '8px' }}>
                  {s.detail}
                </div>
              </div>
            );
          })}
        </div>

        {/* Interactive Detailed Stage Viewer */}
        <div className="glass-card">
          <h3 style={{ fontSize: '1.15rem', color: '#0EA5E9', marginBottom: '8px' }}>
            🔍 Stage {selectedStage} Deep-Dive Inspector
          </h3>
          <p style={{ color: '#CBD5E1', fontSize: '0.9rem', lineHeight: 1.5 }}>
            {selectedStage === 1 && "Stage 1 validates untrusted input before processing. Enforces a 2,048-character length limit, strips dangerous unprintable ASCII characters, and prepares the string for safe lexical parsing."}
            {selectedStage === 2 && "Stage 2 decomposes the URL string strictly according to RFC 3986 into scheme, authority, path, query, and fragment. All operations execute strictly in-memory without DNS queries or network requests."}
            {selectedStage === 3 && "Stage 3 transforms raw URL morphology into an 18-dimensional numeric feature vector. Captures domain length, delimiter frequencies (dots, hyphens, @), IP literals, shorteners, and credential tokens."}
            {selectedStage === 4 && "Stage 4 feeds the standardized feature vector into the CART Decision Tree classifier. It traverses binary decision splits using Gini Impurity to generate an explainable if-then classification."}
            {selectedStage === 5 && "Stage 5 executes the Random Forest ensemble of 150 decorrelated decision trees. Each tree votes independently based on random feature bagging, reducing single-tree variance and preventing overfitting."}
            {selectedStage === 6 && "Stage 6 compares predictions from both models. If they agree, unanimous consensus is confirmed. If they disagree, the ensemble Random Forest decision is applied as default based on held-out benchmark accuracy."}
          </p>
        </div>
      </div>
    );
  }

  // ==========================================
  // TAB 4: MODEL COMPARISON
  // ==========================================
  function renderComparisonTab() {
    return (
      <div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#F8FAFC', marginBottom: '6px' }}>📊 Model Comparison</h2>
        <p style={{ color: '#94A3B8', fontSize: '0.92rem', marginBottom: '20px' }}>
          Fair, held-out empirical comparison of the two primary supervised classifiers: Decision Tree (DT) vs. Random Forest (RF).
        </p>

        {/* Benchmark Metric Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px', marginBottom: '20px' }}>
          <div className="glass-card" style={{ padding: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>TEST SAMPLES</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#0EA5E9', margin: '4px 0' }}>63 Samples</div>
            <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Stratified 20% test split</div>
          </div>
          <div className="glass-card" style={{ padding: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>DT TEST ACCURACY</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#14B8A6', margin: '4px 0' }}>96.8%</div>
            <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Single CART tree</div>
          </div>
          <div className="glass-card" style={{ padding: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>RF TEST ACCURACY</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#10B981', margin: '4px 0' }}>100.0%</div>
            <div style={{ fontSize: '0.75rem', color: '#64748B' }}>150-tree bagging ensemble</div>
          </div>
          <div className="glass-card" style={{ padding: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>RF MACRO F1</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#38BDF8', margin: '4px 0' }}>1.0000</div>
            <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Harmonic mean P & R</div>
          </div>
          <div className="glass-card" style={{ padding: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>RECOMMENDED MODEL</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800, color: '#F8FAFC', margin: '4px 0' }}>Random Forest</div>
            <div style={{ fontSize: '0.75rem', color: '#64748B' }}>Variance reduction</div>
          </div>
        </div>

        {/* Detailed Metrics Table */}
        <div className="glass-card" style={{ marginBottom: '20px' }}>
          <h3 style={{ fontSize: '1.1rem', color: '#F8FAFC', marginBottom: '14px' }}>📋 Comprehensive Benchmark Metrics</h3>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: '#94A3B8' }}>
                  <th style={{ padding: '10px 14px' }}>Metric</th>
                  <th style={{ padding: '10px 14px', color: '#14B8A6' }}>Decision Tree (DT)</th>
                  <th style={{ padding: '10px 14px', color: '#0EA5E9' }}>Random Forest (RF)</th>
                  <th style={{ padding: '10px 14px' }}>Cybersecurity Significance</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { m: "Test Accuracy", dt: "96.83%", rf: "100.0%", sig: "Overall proportion of correct classifications across both classes." },
                  { m: "Macro Precision", dt: "0.9706", rf: "1.0000", sig: "Minimizes false alarms (legitimate websites mistakenly blocked)." },
                  { m: "Macro Recall", dt: "0.9677", rf: "1.0000", sig: "Detection rate of genuine phishing attacks (critical to avoid breaches)." },
                  { m: "Macro F1-Score", dt: "0.9682", rf: "1.0000", sig: "Harmonic balance between precision and recall across both classes." },
                  { m: "Inference Latency", dt: "0.015 ms / sample", rf: "0.770 ms / sample", sig: "Sub-millisecond static execution speed per URL." }
                ].map((row, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '10px 14px', fontWeight: 600, color: '#F8FAFC' }}>{row.m}</td>
                    <td style={{ padding: '10px 14px', color: '#14B8A6', fontFamily: 'monospace' }}>{row.dt}</td>
                    <td style={{ padding: '10px 14px', color: '#0EA5E9', fontFamily: 'monospace', fontWeight: 700 }}>{row.rf}</td>
                    <td style={{ padding: '10px 14px', color: '#94A3B8' }}>{row.sig}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Confusion Matrices */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginBottom: '20px' }}>
          {/* DT Confusion Matrix */}
          <div className="glass-card">
            <h4 style={{ fontSize: '1.05rem', color: '#14B8A6', marginBottom: '10px' }}>Decision Tree Confusion Matrix</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr 1fr', gap: '6px', textAlign: 'center', fontSize: '0.82rem' }}>
              <div></div>
              <div style={{ color: '#94A3B8', fontWeight: 600 }}>Pred Legit</div>
              <div style={{ color: '#94A3B8', fontWeight: 600 }}>Pred Phish</div>
              <div style={{ color: '#94A3B8', fontWeight: 600, textAlign: 'right', paddingRight: '8px' }}>True Legit</div>
              <div style={{ background: 'rgba(20, 184, 166, 0.4)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>29</div>
              <div style={{ background: 'rgba(239, 68, 68, 0.3)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>2</div>
              <div style={{ color: '#94A3B8', fontWeight: 600, textAlign: 'right', paddingRight: '8px' }}>True Phish</div>
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>0</div>
              <div style={{ background: 'rgba(20, 184, 166, 0.4)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>32</div>
            </div>
          </div>

          {/* RF Confusion Matrix */}
          <div className="glass-card">
            <h4 style={{ fontSize: '1.05rem', color: '#0EA5E9', marginBottom: '10px' }}>Random Forest Confusion Matrix</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr 1fr', gap: '6px', textAlign: 'center', fontSize: '0.82rem' }}>
              <div></div>
              <div style={{ color: '#94A3B8', fontWeight: 600 }}>Pred Legit</div>
              <div style={{ color: '#94A3B8', fontWeight: 600 }}>Pred Phish</div>
              <div style={{ color: '#94A3B8', fontWeight: 600, textAlign: 'right', paddingRight: '8px' }}>True Legit</div>
              <div style={{ background: 'rgba(14, 165, 233, 0.45)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>31</div>
              <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>0</div>
              <div style={{ color: '#94A3B8', fontWeight: 600, textAlign: 'right', paddingRight: '8px' }}>True Phish</div>
              <div style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>0</div>
              <div style={{ background: 'rgba(14, 165, 233, 0.45)', padding: '16px', borderRadius: '6px', fontWeight: 700, fontSize: '1.2rem', color: '#FFF' }}>32</div>
            </div>
          </div>
        </div>

        {/* Feature Importances (Random Forest Gini Impurity) */}
        <div className="glass-card">
          <h4 style={{ fontSize: '1.05rem', color: '#0EA5E9', marginBottom: '12px' }}>
            🌳 Random Forest Gini Feature Importances
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {[
              { name: "has_suspicious_keyword", val: 0.2353, label: "Sensitive Credential Tokens (login, verify, bank)" },
              { name: "hostname_length", val: 0.1931, label: "Domain Character Count" },
              { name: "url_length", val: 0.1859, label: "Total URL Character Length" },
              { name: "count_hyphens", val: 0.1386, label: "Hyphen Frequency (Typosquatting Lures)" },
              { name: "is_https", val: 0.0838, label: "Protocol Indicator" },
              { name: "count_dots", val: 0.0542, label: "Dot Frequency / Subdomains" },
              { name: "is_ip_address", val: 0.0412, label: "Raw IP Host Literal" }
            ].map((f, i) => (
              <div key={i}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '3px' }}>
                  <span style={{ color: '#CBD5E1', fontFamily: 'monospace' }}>{f.name} <span style={{ color: '#64748B' }}>({f.label})</span></span>
                  <strong style={{ color: '#38BDF8' }}>{(f.val * 100).toFixed(2)}%</strong>
                </div>
                <div style={{ width: '100%', height: '6px', background: '#0B1120', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${(f.val / 0.25) * 100}%`, height: '100%', background: '#0EA5E9', borderRadius: '3px' }}></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // ==========================================
  // TAB 5: ABOUT PROJECT
  // ==========================================
  function renderAboutTab() {
    return (
      <div>
        <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#F8FAFC', marginBottom: '6px' }}>📖 About PhishGuard AI</h2>
        <div style={{ color: '#0EA5E9', fontSize: '0.98rem', fontWeight: 600, marginBottom: '20px' }}>
          Phishing Website Detection Using URL-Based Feature Extraction with Decision Tree and Random Forest Algorithms
        </div>

        {/* Overview & Problem Statement Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginBottom: '20px' }}>
          <div className="glass-card" style={{ borderLeft: '4px solid #0EA5E9' }}>
            <h4 style={{ fontSize: '1.05rem', color: '#0EA5E9', margin: '0 0 8px 0' }}>🎯 Project Overview</h4>
            <p style={{ color: '#CBD5E1', fontSize: '0.9rem', lineHeight: 1.5, margin: 0 }}>
              PhishGuard AI is an automated cybersecurity machine learning web application developed for <em>Fundamentals of Machine Learning</em>. It detects phishing websites exclusively through <strong>static URL structural and lexical feature extraction</strong> without ever visiting, crawling, or downloading the destination website.
            </p>
          </div>

          <div className="glass-card" style={{ borderLeft: '4px solid #14B8A6' }}>
            <h4 style={{ fontSize: '1.05rem', color: '#14B8A6', margin: '0 0 8px 0' }}>🛡️ Problem Statement & Objective</h4>
            <p style={{ color: '#CBD5E1', fontSize: '0.9rem', lineHeight: 1.5, margin: 0 }}>
              Phishing attacks cause billions of dollars in annual fraud. Traditional blacklists fail against ephemeral zero-day domains, while live crawling poses security hazards. <strong>Objective:</strong> Accurately classify URLs as Legitimate or Phishing using an 18-dimensional lexical feature schema and two primary supervised classifiers: Decision Tree (DT) and Random Forest (RF).
            </p>
          </div>
        </div>

        {/* Algorithms Comparison */}
        <h3 style={{ fontSize: '1.15rem', color: '#F8FAFC', marginBottom: '14px' }}>🤖 Supervised Machine Learning Algorithms</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginBottom: '20px' }}>
          <div className="glass-card" style={{ borderTop: '4px solid #14B8A6' }}>
            <h4 style={{ fontSize: '1.1rem', color: '#14B8A6', margin: '0 0 6px 0' }}>🌲 Decision Tree Classifier (DT)</h4>
            <p style={{ color: '#94A3B8', fontSize: '0.85rem', marginBottom: '10px' }}>
              A non-parametric model utilizing the CART (Classification and Regression Trees) formulation with Gini Impurity.
            </p>
            <ul style={{ color: '#CBD5E1', fontSize: '0.85rem', paddingLeft: '20px', lineHeight: 1.5 }}>
              <li><strong>Interpretability:</strong> Transparent if-then decision paths suitable for security auditing.</li>
              <li><strong>Architecture:</strong> Single tree with max depth of 8 and Gini split criteria.</li>
              <li><strong>Limitation:</strong> Susceptible to higher variance on complex lexical edge cases.</li>
            </ul>
          </div>

          <div className="glass-card" style={{ borderTop: '4px solid #0EA5E9' }}>
            <h4 style={{ fontSize: '1.1rem', color: '#0EA5E9', margin: '0 0 6px 0' }}>🌳 Random Forest Classifier (RF)</h4>
            <p style={{ color: '#94A3B8', fontSize: '0.85rem', marginBottom: '10px' }}>
              An ensemble of 150 decorrelated decision trees combining bootstrap aggregating (bagging) and random subspace projection.
            </p>
            <ul style={{ color: '#CBD5E1', fontSize: '0.85rem', paddingLeft: '20px', lineHeight: 1.5 }}>
              <li><strong>Variance Reduction:</strong> Averages multiple trees to prevent single-tree overfitting.</li>
              <li><strong>Architecture:</strong> 150 estimators with Gini split criterion and feature bagging.</li>
              <li><strong>Output:</strong> Calibrated class probabilities and Gini feature importances.</li>
            </ul>
          </div>
        </div>

        {/* Technology Stack Grid */}
        <h3 style={{ fontSize: '1.15rem', color: '#F8FAFC', marginBottom: '14px' }}>💻 Production Technology Stack</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '20px' }}>
          {[
            { name: "Render", role: "Backend Web Service", col: "#0EA5E9" },
            { name: "Vercel", role: "Frontend Web Application", col: "#FFFFFF" },
            { name: "FastAPI / Python 3.11", role: "REST API & ML Services", col: "#10B981" },
            { name: "Scikit-learn", role: "CART & Random Forest Models", col: "#F59E0B" },
            { name: "React 19 / Vite", role: "Reactive Dashboard", col: "#38BDF8" },
            { name: "FPDF2", role: "Audit PDF Report Generator", col: "#8B5CF6" }
          ].map((t, idx) => (
            <div key={idx} className="glass-card" style={{ textAlign: 'center', padding: '14px' }}>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', color: t.col }}>{t.name}</div>
              <div style={{ fontSize: '0.78rem', color: '#94A3B8', marginTop: '2px' }}>{t.role}</div>
            </div>
          ))}
        </div>

        {/* Scope Boundaries */}
        <div className="glass-card" style={{ borderLeft: '4px solid #EF4444' }}>
          <h4 style={{ fontSize: '1.05rem', color: '#EF4444', margin: '0 0 6px 0' }}>⚠️ Operational Scope & Academic Boundaries</h4>
          <p style={{ color: '#CBD5E1', fontSize: '0.88rem', lineHeight: 1.5, margin: 0 }}>
            “The application analyzes URL characteristics only. It does not inspect website content, verify ownership, or guarantee that a website is safe.”
          </p>
          <p style={{ color: '#94A3B8', fontSize: '0.82rem', lineHeight: 1.5, marginTop: '8px', margin: '8px 0 0 0' }}>
            PhishGuard AI evaluates structural indicators without visiting destination domains. All classifications represent probabilistic machine-learning estimates and do not replace antivirus, firewalls, or user vigilance.
          </p>
        </div>
      </div>
    );
  }
}
