import React, { useState, useEffect, useRef } from 'react';
import './App.css';

// TypeScript Interfaces
interface StatusData {
  signer_online: boolean;
  ready: boolean;
  sealed: boolean;
  node_id: string;
  reason?: string;
}

interface Quantiles {
  p50: number;
  p90: number;
  p99: number;
}

interface MetricsData {
  node_id: string;
  ts_utc: number;
  schema_version: number;
  metric_window_seconds: number;
  counters: Record<string, number>;
  gauges: Record<string, number>;
  quantiles: Record<string, Quantiles>;
}

interface Peer {
  address: string;
  node_id: string;
  last_seen_utc: number;
  rx_count: number;
  tx_count: number;
  is_bootstrap: boolean;
}

interface PeerListData {
  peers: Peer[];
  snapshot_utc: number;
}

interface AuditLine {
  ts_utc: number;
  record: string;
  json: string;
}

interface AuditTailData {
  lines: AuditLine[];
}

interface OllamaStatus {
  healthy: boolean;
  model_available: boolean;
  model_name: string;
}

interface ProjectionData {
  input_dim: number;
  omega_dim: number;
  pre: number;
  routing: string;
  similarity: number;
  similarities: Record<string, number>;
  vector_2d: [number, number];
  experts_2d: Record<string, [number, number]>;
}

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export default function App() {
  // Navigation & Config States
  const [activeTab, setActiveTab] = useState<'hud' | 'metrics' | 'peers' | 'audit'>('hud');
  const [pollInterval, setPollInterval] = useState<number>(2000);
  const [paused, setPaused] = useState<boolean>(false);
  const [systemPrompt, setSystemPrompt] = useState<string>(
    "Sei AETERNA, un'intelligenza artificiale cooperativa per l'analisi dei dati scientifici e crittografici."
  );

  // API Data States
  const [status, setStatus] = useState<StatusData | null>(null);
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [peersData, setPeersData] = useState<PeerListData | null>(null);
  const [auditData, setAuditData] = useState<AuditTailData | null>(null);
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus | null>(null);

  // Chat & Projection States
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [userInput, setUserInput] = useState<string>('');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [lastProjection, setLastProjection] = useState<ProjectionData | null>(null);

  // Canvas Reference
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  // Interpolated vector for smooth movement in Canvas
  const currentVectorRef = useRef<[number, number]>([0, 0]);
  const targetVectorRef = useRef<[number, number]>([0, 0]);

  // Fetch status, metrics, peers, audit logs
  const fetchData = async () => {
    try {
      // 1. Node Status
      const statusRes = await fetch('http://127.0.0.1:8000/api/status');
      if (statusRes.ok) {
        const data = await statusRes.json();
        setStatus(data);
      }

      // 2. Metrics
      const metricsRes = await fetch('http://127.0.0.1:8000/api/metrics');
      if (metricsRes.ok) {
        const data = await metricsRes.json();
        setMetrics(data);
      }

      // 3. Peers
      const peersRes = await fetch('http://127.0.0.1:8000/api/peers');
      if (peersRes.ok) {
        const data = await peersRes.json();
        setPeersData(data);
      }

      // 4. Audit Log
      const auditRes = await fetch('http://127.0.0.1:8000/api/audit?limit=30');
      if (auditRes.ok) {
        const data = await auditRes.json();
        setAuditData(data);
      }

      // 5. Ollama Status
      const ollamaRes = await fetch('http://127.0.0.1:8000/api/ollama/status');
      if (ollamaRes.ok) {
        const data = await ollamaRes.json();
        setOllamaStatus(data);
      }
    } catch (err) {
      console.error('Error fetching dashboard API data:', err);
    }
  };

  // Initial and Polling Effect
  useEffect(() => {
    fetchData(); // Immediate call
    if (paused) return;

    const intervalId = setInterval(fetchData, pollInterval);
    return () => clearInterval(intervalId);
  }, [pollInterval, paused]);

  // Handle Chat Submission
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim() || isGenerating) return;

    const prompt = userInput;
    setUserInput('');
    setIsGenerating(true);

    // Add user message locally
    const updatedMessages: ChatMessage[] = [...chatMessages, { role: 'user', content: prompt }];
    setChatMessages(updatedMessages);

    try {
      const res = await fetch('http://127.0.0.1:8000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, system: systemPrompt })
      });

      if (res.ok) {
        const data = await res.json();
        setChatMessages([...updatedMessages, { role: 'assistant', content: data.response }]);
        if (data.projection) {
          setLastProjection(data.projection);
          // Set target for smooth visual transition
          targetVectorRef.current = data.projection.vector_2d;
        }
      } else {
        const data = await res.json();
        setChatMessages([
          ...updatedMessages,
          { role: 'system', content: `[ERR] Generazione fallita: ${data.error || 'Server error'}` }
        ]);
      }
    } catch (err) {
      setChatMessages([
        ...updatedMessages,
        { role: 'system', content: `[ERR] Impossibile contattare il server API di AETERNA.` }
      ]);
    } finally {
      setIsGenerating(false);
    }
  };

  // Clear Chat History
  const handleClearHistory = () => {
    setChatMessages([]);
    setLastProjection(null);
    targetVectorRef.current = [0, 0];
    currentVectorRef.current = [0, 0];
  };

  // Format UNIX timestamp to UTC string
  const formatUtc = (ts: number) => {
    if (!ts) return '—';
    return new Date(ts * 1000).toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  };

  // Format duration in seconds
  const formatDurationS = (seconds: number) => {
    if (seconds <= 0) return '—';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  // Canvas HUD Projection Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let rotationAngle = 0;

    const render = (time: number) => {
      // Clear and size canvas to container
      const width = canvas.width = canvas.parentElement?.clientWidth || 500;
      const height = canvas.height = canvas.parentElement?.clientHeight || 400;
      
      ctx.fillStyle = '#030712';
      ctx.fillRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(width, height) * 0.42;

      // 1. Draw grid background & radial lines
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.06)';
      ctx.lineWidth = 1;

      // Concentric circles
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius * (i / 4), 0, Math.PI * 2);
        ctx.stroke();
      }

      // X-Y Axes
      ctx.beginPath();
      ctx.moveTo(centerX - radius, centerY);
      ctx.lineTo(centerX + radius, centerY);
      ctx.moveTo(centerX, centerY - radius);
      ctx.lineTo(centerX, centerY + radius);
      ctx.stroke();

      // Dashed ticks
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.2)';
      ctx.setLineDash([2, 5]);
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      // 2. Draw outer rotating HUD ring
      rotationAngle += 0.003;
      ctx.strokeStyle = 'rgba(168, 85, 247, 0.18)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.05, rotationAngle, rotationAngle + Math.PI * 0.4);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.05, rotationAngle + Math.PI, rotationAngle + Math.PI * 1.4);
      ctx.stroke();

      // Outer rings corner brackets
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.3)';
      ctx.lineWidth = 1;
      const bracketSize = 15;
      
      // Top-Left Corner
      ctx.beginPath();
      ctx.moveTo(10, 10 + bracketSize); ctx.lineTo(10, 10); ctx.lineTo(10 + bracketSize, 10);
      ctx.stroke();
      // Top-Right Corner
      ctx.beginPath();
      ctx.moveTo(width - 10, 10 + bracketSize); ctx.lineTo(width - 10, 10); ctx.lineTo(width - 10 - bracketSize, 10);
      ctx.stroke();
      // Bottom-Left Corner
      ctx.beginPath();
      ctx.moveTo(10, height - 10 - bracketSize); ctx.lineTo(10, height - 10); ctx.lineTo(10 + bracketSize, height - 10);
      ctx.stroke();
      // Bottom-Right Corner
      ctx.beginPath();
      ctx.moveTo(width - 10, height - 10 - bracketSize); ctx.lineTo(width - 10, height - 10); ctx.lineTo(width - 10 - bracketSize, height - 10);
      ctx.stroke();

      // 3. Define Expert Coordinates (matching backend 2D vectors)
      // Generale: [0.70, 0.50], Oncologia: [0.15, 0.85], HP-Folding: [0.80, -0.35]
      // In Cartesian, standard canvas y increases downwards, so we negate y scaling
      const experts: Record<string, { x: number; y: number; color: string; label: string }> = {
        'Generale': { x: 0.60, y: 0.40, color: '#10b981', label: 'Centr. Generale (Ω)' },
        'Oncologia': { x: -0.50, y: 0.70, color: '#ef4444', label: 'Centr. Oncologia' },
        'HP-Folding': { x: 0.70, y: -0.50, color: '#a855f7', label: 'Centr. HP-Folding' }
      };

      // Draw expert centroids
      Object.entries(experts).forEach(([name, exp]) => {
        const cx = centerX + exp.x * radius;
        const cy = centerY - exp.y * radius; // Negate Y

        // Outer glow circle
        ctx.fillStyle = exp.color + '0c'; // 5% opacity
        ctx.beginPath();
        ctx.arc(cx, cy, 18, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = exp.color + '33'; // 20% opacity
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(cx, cy, 10, 0, Math.PI * 2);
        ctx.stroke();

        // Inner solid dot
        ctx.fillStyle = exp.color;
        ctx.beginPath();
        ctx.arc(cx, cy, 4, 0, Math.PI * 2);
        ctx.fill();

        // Label
        ctx.fillStyle = 'rgba(243, 244, 246, 0.4)';
        ctx.font = '9px "Share Tech Mono"';
        ctx.fillText(exp.label, cx + 12, cy + 3);
      });

      // 4. Smooth Vector Interpolation
      const dx = targetVectorRef.current[0] - currentVectorRef.current[0];
      const dy = targetVectorRef.current[1] - currentVectorRef.current[1];
      currentVectorRef.current[0] += dx * 0.08;
      currentVectorRef.current[1] += dy * 0.08;

      const vx = centerX + currentVectorRef.current[0] * radius;
      const vy = centerY - currentVectorRef.current[1] * radius; // Negate Y

      const hasActiveProjection = lastProjection !== null;

      if (hasActiveProjection) {
        // Draw path line from center (0,0) to v_omega
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.4)';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(vx, vy);
        ctx.stroke();
        ctx.setLineDash([]);

        // Draw routing alignment line from v_omega to nearest expert centroid
        const route = lastProjection?.routing;
        if (route && experts[route]) {
          const exp = experts[route];
          const ecx = centerX + exp.x * radius;
          const ecy = centerY - exp.y * radius;
          
          ctx.strokeStyle = exp.color + '77';
          ctx.lineWidth = 1.5;
          ctx.setLineDash([2, 4]);
          ctx.beginPath();
          ctx.moveTo(vx, vy);
          ctx.lineTo(ecx, ecy);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // Draw pulsating projection vector
        const pulse = Math.sin(time * 0.007) * 4 + 10;
        const grad = ctx.createRadialGradient(vx, vy, 1, vx, vy, pulse);
        grad.addColorStop(0, 'rgba(6, 182, 212, 1)');
        grad.addColorStop(0.3, 'rgba(6, 182, 212, 0.5)');
        grad.addColorStop(1, 'rgba(6, 182, 212, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(vx, vy, pulse, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#06b6d4';
        ctx.beginPath();
        ctx.arc(vx, vy, 4, 0, Math.PI * 2);
        ctx.fill();

        // Vector labels
        ctx.fillStyle = '#f3f4f6';
        ctx.font = '10px "Share Tech Mono"';
        ctx.fillText(`Vector Omega (v_ω)`, vx + 12, vy - 12);
        ctx.fillStyle = 'rgba(6, 182, 212, 0.8)';
        ctx.fillText(`[X: ${currentVectorRef.current[0].toFixed(3)}, Y: ${currentVectorRef.current[1].toFixed(3)}]`, vx + 12, vy - 2);
      } else {
        // Draw hovering idle scanning vector
        const idleX = Math.sin(time * 0.001) * 0.3;
        const idleY = Math.cos(time * 0.0008) * 0.3;
        targetVectorRef.current = [idleX, idleY];

        const pulse = Math.sin(time * 0.005) * 2 + 6;
        ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
        ctx.beginPath();
        ctx.arc(vx, vy, pulse, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = 'rgba(6, 182, 212, 0.4)';
        ctx.beginPath();
        ctx.arc(vx, vy, 2.5, 0, Math.PI * 2);
        ctx.fill();

        // Center coordinate label
        ctx.fillStyle = 'rgba(6, 182, 212, 0.3)';
        ctx.font = '9px "Share Tech Mono"';
        ctx.fillText("Allineatore Rosetta Attivo (Scan)", vx + 8, vy - 4);
      }

      // 5. Draw live digital matrix overlays (top-left metadata / bottom-right coordinates)
      ctx.fillStyle = 'rgba(6, 182, 212, 0.4)';
      ctx.font = '8px "Share Tech Mono"';
      ctx.fillText(`SHD_DIM: 64D | ALIGN_TOL: 0.005`, 18, 26);
      ctx.fillText(`SYS_SEED: 0x${(lastProjection?.similarity || 0.4242).toString(16).substring(2, 8).toUpperCase()}`, 18, 38);
      
      const statusText = status?.ready ? "SYS_OK // ALIGNED" : (status?.sealed ? "SYS_SEALED" : "SYS_WAIT_INIT");
      ctx.fillStyle = status?.ready ? 'rgba(16, 185, 129, 0.6)' : 'rgba(239, 68, 68, 0.6)';
      ctx.fillText(`STATUS: ${statusText}`, 18, 50);

      animationFrameRef.current = requestAnimationFrame(render);
    };

    animationFrameRef.current = requestAnimationFrame(render);
    return () => {
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
    };
  }, [lastProjection, status]);

  // Handle status indicators
  const isOnline = status?.signer_online;
  const isReady = status?.ready;
  const isSealed = status?.sealed;

  return (
    <div className="app-container">
      {/* Sidebar Control Panel */}
      <aside className="sidebar">
        <div className="logo-container">
          <h1 className="logo-text glow-cyan">Aeterna</h1>
          <span className="logo-subtext">operator deck</span>
        </div>

        {/* Node Health Section */}
        <div className="sidebar-section">
          <label>Stato Nodo</label>
          <div className="hud-panel" style={{ padding: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
              <span className={`expert-bar-inner`} style={{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: isOnline ? '#10b981' : '#ef4444',
                boxShadow: isOnline ? '0 0 8px #10b981' : '0 0 8px #ef4444'
              }}></span>
              <span className="digital-font" style={{ fontSize: '0.8rem' }}>
                Signer: {isOnline ? 'CONNESSO' : 'SCOLLEGATO'}
              </span>
            </div>
            
            {isOnline && (
              <>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Node: <strong className="digital-font" style={{ color: 'var(--cyan)' }}>{status?.node_id}</strong>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Vault: <strong style={{ color: isSealed ? '#ef4444' : '#10b981' }}>{isSealed ? 'SIGILLATO' : 'SBLOCCATO'}</strong>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Stato: <strong style={{ color: isReady ? '#10b981' : '#ef4444' }}>{isReady ? 'PRONTO' : 'NON PRONTO'}</strong>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Ollama Health Section */}
        <div className="sidebar-section">
          <label>Modello Locale (Ollama)</label>
          <div className="hud-panel" style={{ padding: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
              <span style={{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: ollamaStatus?.healthy ? '#10b981' : '#ef4444',
                boxShadow: ollamaStatus?.healthy ? '0 0 8px #10b981' : '0 0 8px #ef4444'
              }}></span>
              <span className="digital-font" style={{ fontSize: '0.8rem' }}>
                Daemon: {ollamaStatus?.healthy ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
            {ollamaStatus?.healthy && (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Modello: <strong className="digital-font" style={{ color: 'var(--purple)' }}>{ollamaStatus?.model_name}</strong>
              </div>
            )}
          </div>
        </div>

        {/* Configuration Section */}
        <div className="sidebar-section">
          <label>Frequenza Refresh (ms)</label>
          <select 
            className="sidebar-select digital-font"
            value={pollInterval} 
            onChange={(e) => setPollInterval(Number(e.target.value))}
          >
            <option value={500}>500 ms (Rapid)</option>
            <option value={1000}>1000 ms (Fast)</option>
            <option value={2000}>2000 ms (Normal)</option>
            <option value={5000}>5000 ms (Slow)</option>
            <option value={10000}>10000 ms (Diagnostic)</option>
          </select>
        </div>

        <div className="sidebar-section" style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
          <label htmlFor="pause-toggle" style={{ cursor: 'pointer' }}>Pausa Polling</label>
          <input 
            id="pause-toggle"
            type="checkbox" 
            style={{ width: '18px', height: '18px', cursor: 'pointer' }}
            checked={paused}
            onChange={(e) => setPaused(e.target.checked)}
          />
        </div>

        <button 
          className="hud-btn hud-btn-purple"
          onClick={handleClearHistory}
        >
          Reset Sessione
        </button>

        <div style={{ marginTop: 'auto', fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          AETERNA v0.3.0 'Oculus'<br />
          Loopback API Interface (Port 8000)
        </div>
      </aside>

      {/* Main Panel Viewports */}
      <main className="main-content">
        <nav className="header-tabs">
          <button 
            className={`tab-button ${activeTab === 'hud' ? 'active' : ''}`}
            onClick={() => setActiveTab('hud')}
          >
            HUD Proiezioni
          </button>
          <button 
            className={`tab-button ${activeTab === 'metrics' ? 'active' : ''}`}
            onClick={() => setActiveTab('metrics')}
          >
            Metriche
          </button>
          <button 
            className={`tab-button ${activeTab === 'peers' ? 'active' : ''}`}
            onClick={() => setActiveTab('peers')}
          >
            Rete Gossip
          </button>
          <button 
            className={`tab-button ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            Audit Logs
          </button>
        </nav>

        {/* View Contents */}
        <div className="panel-container">
          
          {/* TAB 1: HUD Projection Chat */}
          {activeTab === 'hud' && (
            <div className="chat-hud-grid">
              
              {/* Chat Interface Column */}
              <div className="chat-column">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                  <h2 style={{ margin: 0 }} className="glow-cyan digital-font">AETERNA Cog-Deck</h2>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    Allineamento semantico nello spazio Omega condiviso in tempo reale.
                  </p>
                </div>

                <div className="sidebar-section">
                  <label>System Instructions</label>
                  <input 
                    type="text" 
                    className="sidebar-input"
                    value={systemPrompt}
                    onChange={(e) => setSystemPrompt(e.target.value)}
                  />
                </div>

                <div className="chat-history">
                  {chatMessages.length === 0 ? (
                    <div style={{ margin: 'auto', textAlign: 'center', color: 'var(--text-muted)', maxWidth: '80%' }}>
                      <p style={{ fontSize: '1.2rem', marginBottom: '0.5rem' }} className="digital-font glow-cyan">IN ATTESA DI INPUT</p>
                      <p style={{ fontSize: '0.85rem' }}>
                        Invia una query crittografica o scientifica ad AETERNA. L'allineatore Pietra di Rosetta mapperà il vettore semantico nello spazio Omega proiettandolo sul radar HUD.
                      </p>
                    </div>
                  ) : (
                    chatMessages.map((msg, idx) => (
                      <div key={idx} className={`message-bubble ${msg.role}`}>
                        {parseMarkdown(msg.content)}
                      </div>
                    ))
                  )}
                  {isGenerating && (
                    <div className="message-bubble assistant digital-font" style={{ animation: 'text-blink 1.5s infinite' }}>
                      [ELABORAZIONE VETTORI SEMANTICI...]
                    </div>
                  )}
                </div>

                <form className="chat-input-bar" onSubmit={handleSendMessage}>
                  <input 
                    type="text" 
                    className="chat-text-input"
                    placeholder={ollamaStatus?.healthy ? "Invia messaggio ad AETERNA..." : "Ollama offline. Avvia Ollama per chattare..."}
                    value={userInput}
                    disabled={!ollamaStatus?.healthy || isGenerating}
                    onChange={(e) => setUserInput(e.target.value)}
                  />
                  <button 
                    type="submit" 
                    className={`hud-btn ${(!ollamaStatus?.healthy || isGenerating) ? 'hud-btn-disabled' : ''}`}
                    disabled={!ollamaStatus?.healthy || isGenerating}
                  >
                    Invia
                  </button>
                </form>
              </div>

              {/* Holographic HUD Column */}
              <div className="hud-column">
                <div className="latent-viz-box">
                  <canvas ref={canvasRef} className="latent-canvas" />
                </div>

                {/* Metrics Readouts */}
                <div className="hud-metrics-grid">
                  <div className="hud-metric-card">
                    <span className="hud-metric-label">Dimensione Locale</span>
                    <span className="hud-metric-value glow-cyan">{lastProjection ? `${lastProjection.input_dim}D` : '—'}</span>
                  </div>
                  <div className="hud-metric-card">
                    <span className="hud-metric-label">Dimensione Condivisa (Ω)</span>
                    <span className="hud-metric-value glow-purple">{lastProjection ? `${lastProjection.omega_dim}D` : '—'}</span>
                  </div>
                  <div className="hud-metric-card">
                    <span className="hud-metric-label">Errore Ricostruzione (PRE)</span>
                    <span className={`hud-metric-value ${lastProjection && lastProjection.pre > 0.01 ? 'glow-red' : 'glow-green'}`}>
                      {lastProjection ? lastProjection.pre.toFixed(4) : '—'}
                    </span>
                  </div>
                  <div className="hud-metric-card">
                    <span className="hud-metric-label">Best Coherence Coeff</span>
                    <span className="hud-metric-value glow-cyan">
                      {lastProjection ? `${(lastProjection.similarity * 100).toFixed(2)}%` : '—'}
                    </span>
                  </div>
                </div>

                {/* Expert Centroids Map */}
                <div className="hud-panel">
                  <h3 className="digital-font glow-cyan" style={{ margin: '0 0 1rem 0', fontSize: '0.9rem', textTransform: 'uppercase' }}>
                    Coerenza Centroidi Esperti
                  </h3>
                  
                  <div className="expert-bars-container">
                    {/* Centroid: Generale */}
                    <div className="expert-row">
                      <div className="expert-header">
                        <span>Generale (Ω_0)</span>
                        <span className="digital-font" style={{ color: 'var(--green)' }}>
                          {lastProjection ? `${(lastProjection.similarities.Generale * 100).toFixed(2)}%` : '—'}
                        </span>
                      </div>
                      <div className="expert-bar-outer">
                        <div 
                          className="expert-bar-inner Generale" 
                          style={{ width: lastProjection ? `${Math.max(0, lastProjection.similarities.Generale * 100)}%` : '0%' }}
                        />
                      </div>
                    </div>

                    {/* Centroid: Oncologia */}
                    <div className="expert-row">
                      <div className="expert-header">
                        <span>Oncologia (Ω_1)</span>
                        <span className="digital-font" style={{ color: 'var(--red)' }}>
                          {lastProjection ? `${(lastProjection.similarities.Oncologia * 100).toFixed(2)}%` : '—'}
                        </span>
                      </div>
                      <div className="expert-bar-outer">
                        <div 
                          className="expert-bar-inner Oncologia" 
                          style={{ width: lastProjection ? `${Math.max(0, lastProjection.similarities.Oncologia * 100)}%` : '0%' }}
                        />
                      </div>
                    </div>

                    {/* Centroid: HP-Folding */}
                    <div className="expert-row">
                      <div className="expert-header">
                        <span>HP-Folding (Ω_2)</span>
                        <span className="digital-font" style={{ color: 'var(--purple)' }}>
                          {lastProjection ? `${(lastProjection.similarities["HP-Folding"] * 100).toFixed(2)}%` : '—'}
                        </span>
                      </div>
                      <div className="expert-bar-outer">
                        <div 
                          className="expert-bar-inner HP-Folding" 
                          style={{ width: lastProjection ? `${Math.max(0, lastProjection.similarities["HP-Folding"] * 100)}%` : '0%' }}
                        />
                      </div>
                    </div>
                  </div>

                  {lastProjection && (
                    <div style={{ marginTop: '1.2rem', padding: '0.6rem', background: 'rgba(255,255,255,0.03)', borderRadius: '4px', border: '1px solid rgba(6,182,212,0.1)' }}>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Instradamento Semantico: 
                        <strong className="digital-font" style={{ color: 'var(--cyan)', marginLeft: '0.5rem' }}>
                          {lastProjection.routing.toUpperCase()}
                        </strong>
                      </span>
                    </div>
                  )}
                </div>
              </div>

            </div>
          )}

          {/* TAB 2: Metrics Table */}
          {activeTab === 'metrics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                <h2 className="glow-cyan digital-font" style={{ margin: 0 }}>Gauges & Counters di Sistema</h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
                  Gauges e Counters registrati sulla superficie di amministrazione gRPC del nodo.
                </p>
              </div>

              {metrics ? (
                <>
                  <div className="metrics-summary-cards">
                    <div className="hud-metric-card">
                      <span className="hud-metric-label">Node Identifier</span>
                      <span className="hud-metric-value glow-cyan" style={{ fontSize: '1.2rem' }}>{metrics.node_id}</span>
                    </div>
                    <div className="hud-metric-card">
                      <span className="hud-metric-label">Versione Schema</span>
                      <span className="hud-metric-value glow-purple">{metrics.schema_version}</span>
                    </div>
                    <div className="hud-metric-card">
                      <span className="hud-metric-label">Finestra Metriche</span>
                      <span className="hud-metric-value glow-green">{metrics.metric_window_seconds}s</span>
                    </div>
                    <div className="hud-metric-card">
                      <span className="hud-metric-label">Snapshot UTC</span>
                      <span className="hud-metric-value" style={{ fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>{formatUtc(metrics.ts_utc)}</span>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                    <div className="table-container">
                      <table className="hud-table">
                        <thead>
                          <tr>
                            <th>Signer Gauges (Santuario Rust)</th>
                            <th style={{ width: '120px' }}>Valore</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(metrics.gauges)
                            .filter(([k]) => k.startsWith('santuario_'))
                            .map(([k, v]) => (
                              <tr key={k}>
                                <td className="digital-font" style={{ fontSize: '0.8rem' }}>{k}</td>
                                <td className="digital-font" style={{ color: 'var(--cyan)' }}>{v.toFixed(2)}</td>
                              </tr>
                            ))}
                          {Object.entries(metrics.gauges).filter(([k]) => k.startsWith('santuario_')).length === 0 && (
                            <tr><td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Nessun gauge di firma attivo</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>

                    <div className="table-container">
                      <table className="hud-table">
                        <thead>
                          <tr>
                            <th>Signer Counters (Santuario Rust)</th>
                            <th style={{ width: '120px' }}>Valore</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(metrics.counters)
                            .filter(([k]) => k.startsWith('santuario_'))
                            .map(([k, v]) => (
                              <tr key={k}>
                                <td className="digital-font" style={{ fontSize: '0.8rem' }}>{k}</td>
                                <td className="digital-font" style={{ color: 'var(--green)' }}>{v}</td>
                              </tr>
                            ))}
                          {Object.entries(metrics.counters).filter(([k]) => k.startsWith('santuario_')).length === 0 && (
                            <tr><td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Nessun contatore di firma attivo</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginTop: '1.5rem' }}>
                    <div className="table-container">
                      <table className="hud-table">
                        <thead>
                          <tr>
                            <th>Sentinel Gauges (Aeterna Python)</th>
                            <th style={{ width: '120px' }}>Valore</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(metrics.gauges)
                            .filter(([k]) => k.startsWith('aeterna_'))
                            .map(([k, v]) => (
                              <tr key={k}>
                                <td className="digital-font" style={{ fontSize: '0.8rem' }}>{k}</td>
                                <td className="digital-font" style={{ color: 'var(--purple)' }}>{v.toFixed(2)}</td>
                              </tr>
                            ))}
                          {Object.entries(metrics.gauges).filter(([k]) => k.startsWith('aeterna_')).length === 0 && (
                            <tr><td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Nessun gauge orchestratore attivo</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>

                    <div className="table-container">
                      <table className="hud-table">
                        <thead>
                          <tr>
                            <th>Sentinel Counters (Aeterna Python)</th>
                            <th style={{ width: '120px' }}>Valore</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(metrics.counters)
                            .filter(([k]) => k.startsWith('aeterna_'))
                            .map(([k, v]) => (
                              <tr key={k}>
                                <td className="digital-font" style={{ fontSize: '0.8rem' }}>{k}</td>
                                <td className="digital-font" style={{ color: 'var(--cyan)' }}>{v}</td>
                              </tr>
                            ))}
                          {Object.entries(metrics.counters).filter(([k]) => k.startsWith('aeterna_')).length === 0 && (
                            <tr><td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Nessun contatore orchestratore attivo</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              ) : (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Caricamento metriche di amministrazione...
                </div>
              )}
            </div>
          )}

          {/* TAB 3: Gossip Network Peers */}
          {activeTab === 'peers' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                <h2 className="glow-cyan digital-font" style={{ margin: 0 }}>Gossip Network Topology</h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
                  Nodi peer attivi e scoperti nella rete P2P decentralizzata di AETERNA.
                </p>
              </div>

              {peersData ? (
                <div className="table-container">
                  <table className="hud-table">
                    <thead>
                      <tr>
                        <th>Node IP / Socket</th>
                        <th>Node ID</th>
                        <th style={{ width: '100px' }}>Bootstrap</th>
                        <th style={{ width: '120px' }}>Ultimo Contatto</th>
                        <th style={{ width: '100px' }}>Rx Msg</th>
                        <th style={{ width: '100px' }}>Tx Msg</th>
                      </tr>
                    </thead>
                    <tbody>
                      {peersData.peers.map((peer, idx) => {
                        const now = Math.floor(Date.now() / 1000);
                        const age = peer.last_seen_utc > 0 ? (now - peer.last_seen_utc) : -1;
                        return (
                          <tr key={idx}>
                            <td className="digital-font" style={{ color: 'var(--cyan)' }}>{peer.address}</td>
                            <td className="digital-font" style={{ fontSize: '0.8rem' }}>{peer.node_id || '—'}</td>
                            <td className="digital-font" style={{ color: peer.is_bootstrap ? 'var(--green)' : 'var(--text-muted)' }}>
                              {peer.is_bootstrap ? '✓ SI' : 'NO'}
                            </td>
                            <td>{age >= 0 ? formatDurationS(age) : 'never'}</td>
                            <td className="digital-font">{peer.rx_count}</td>
                            <td className="digital-font">{peer.tx_count}</td>
                          </tr>
                        );
                      })}
                      {peersData.peers.length === 0 && (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                            Nessun nodo peer collegato (modalità di rete standalone).
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  In attesa della topologia di rete...
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Audit Logs Console */}
          {activeTab === 'audit' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                <h2 className="glow-green digital-font" style={{ margin: 0 }}>Terminal Console & Audit Trail</h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
                  Visualizzazione in tempo reale degli eventi di sicurezza, alert ed eccezioni registrati dal nodo.
                </p>
              </div>

              <div className="terminal-console">
                {auditData && auditData.lines.length > 0 ? (
                  auditData.lines.map((line, idx) => {
                    let recordObj = {};
                    try {
                      recordObj = JSON.parse(line.json);
                    } catch (e) {}

                    return (
                      <div key={idx} className="terminal-line">
                        <span className="terminal-timestamp">[{formatUtc(line.ts_utc)}]</span>
                        <span style={{ color: '#fff', fontWeight: 'bold' }}>{line.record.toUpperCase()}</span>
                        <span style={{ color: 'rgba(16, 185, 129, 0.85)', marginLeft: '0.8rem' }}>
                          {JSON.stringify(recordObj)}
                        </span>
                      </div>
                    );
                  })
                ) : (
                  <div style={{ textAlign: 'center', color: 'rgba(16, 185, 129, 0.4)', padding: '2rem' }}>
                    [NESSUN RECORD PRESENTE SULLA TRACCIA DI AUDIT]
                  </div>
                )}
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}

// Markdown Parser Helpers
function parseMarkdown(text: string): React.ReactNode[] {
  const parts = text.split(/(```[\s\S]*?```)/g);
  return parts.map((part, index) => {
    if (part.startsWith('```') && part.endsWith('```')) {
      const lines = part.slice(3, -3).trim().split('\n');
      let lang = 'text';
      let code = part.slice(3, -3);
      if (lines.length > 0 && /^[a-zA-Z0-9_-]+$/.test(lines[0])) {
        lang = lines[0];
        code = lines.slice(1).join('\n');
      }
      return (
        <pre key={index} className="markdown-code-block">
          <div className="code-block-header">{lang}</div>
          <code>{code}</code>
        </pre>
      );
    }

    const lines = part.split('\n');
    return (
      <div key={index}>
        {lines.map((line, lineIdx) => {
          if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
            const content = line.trim().substring(2);
            return (
              <li key={lineIdx} style={{ marginLeft: '1rem', marginBottom: '0.2rem' }}>
                {renderInlineMarkdown(content)}
              </li>
            );
          }
          if (line.trim().startsWith('### ')) {
            return (
              <h3 key={lineIdx} className="glow-cyan" style={{ margin: '0.8rem 0 0.4rem 0', fontSize: '1rem' }}>
                {renderInlineMarkdown(line.substring(4))}
              </h3>
            );
          }
          if (line.trim().startsWith('## ')) {
            return (
              <h2 key={lineIdx} className="glow-cyan" style={{ margin: '1rem 0 0.5rem 0', fontSize: '1.2rem' }}>
                {renderInlineMarkdown(line.substring(3))}
              </h2>
            );
          }
          return (
            <p key={lineIdx} style={{ margin: '0 0 0.4rem 0' }}>
              {renderInlineMarkdown(line)}
            </p>
          );
        })}
      </div>
    );
  });
}

function renderInlineMarkdown(text: string): React.ReactNode {
  let parts: (string | React.ReactElement)[] = [text];

  parts = parts.flatMap((part) => {
    if (typeof part !== 'string') return part;
    const subparts = part.split(/(\`[^\`]+\`)/g);
    return subparts.map((sub) => {
      if (sub.startsWith('`') && sub.endsWith('`')) {
        return <code key={sub} className="markdown-inline-code">{sub.slice(1, -1)}</code>;
      }
      return sub;
    });
  });

  parts = parts.flatMap((part) => {
    if (typeof part !== 'string') return part;
    const subparts = part.split(/(\*\*[^*]+\*\*)/g);
    return subparts.map((sub) => {
      if (sub.startsWith('**') && sub.endsWith('**')) {
        return <strong key={sub}>{sub.slice(2, -2)}</strong>;
      }
      return sub;
    });
  });

  parts = parts.flatMap((part) => {
    if (typeof part !== 'string') return part;
    const subparts = part.split(/(\*[^*]+\*)/g);
    return subparts.map((sub) => {
      if (sub.startsWith('*') && sub.endsWith('*')) {
        return <em key={sub}>{sub.slice(1, -1)}</em>;
      }
      return sub;
    });
  });

  return <>{parts}</>;
}
