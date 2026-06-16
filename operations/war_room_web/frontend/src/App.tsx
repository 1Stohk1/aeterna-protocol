import React, { useState, useEffect, useRef, useMemo } from 'react';
import './App.css';

// TypeScript Interfaces
interface StatusData {
  signer_online: boolean;
  ready: boolean;
  sealed: boolean;
  seccomp_active?: boolean;
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

interface AnchorCheckpoint {
  btc_tx_hash: string;
  block_hash: string;
  block_height: number;
  creator: string;
  event_name: string;
  timestamp: number;
}

interface AnchorResponse {
  latest_anchor: AnchorCheckpoint | null;
  connected: boolean;
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
  vector_3d?: [number, number, number];
  experts_3d?: Record<string, [number, number, number]>;
}

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

const baseExperts: Record<string, { x: number; y: number; z: number; color: string; label: string }> = {
  'Generale': { x: 0.60, y: 0.40, z: 0.20, color: '#10b981', label: 'Centr. Generale (Ω)' },
  'Oncologia': { x: -0.50, y: 0.70, z: -0.40, color: '#ef4444', label: 'Centr. Oncologia' },
  'HP-Folding': { x: 0.70, y: -0.50, z: 0.50, color: '#a855f7', label: 'Centr. HP-Folding' }
};

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
  const [chainStatus, setChainStatus] = useState<{ height: number; validator_count: number; latest_block_time: string; guardians_count: number } | null>(null);
  const [shipperStatus, setShipperStatus] = useState<{ enabled: boolean; endpoint_url: string; endpoint_pin_sha256: string; total_segments: number; pending_segments: number; last_push_time: string } | null>(null);

  // Chat & Projection States
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [userInput, setUserInput] = useState<string>('');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [lastProjection, setLastProjection] = useState<ProjectionData | null>(null);
  const [sanctuaryStatus, setSanctuaryStatus] = useState<{ seq: number; status: string; error?: string } | null>(null);
  const sanctuaryStatusRef = useRef<{ seq: number; status: string; error?: string } | null>(null);
  useEffect(() => {
    sanctuaryStatusRef.current = sanctuaryStatus;
  }, [sanctuaryStatus]);

  const [anchorData, setAnchorData] = useState<AnchorResponse | null>(null);
  const anchorDataRef = useRef<AnchorResponse | null>(null);
  useEffect(() => {
    anchorDataRef.current = anchorData;
  }, [anchorData]);

  // Derive running workloads from audit logs
  const runningWorkloads = useMemo(() => {
    if (!auditData?.lines) return [];
    const active = new Map<number, { pid: number; policy: string; startedAt: number }>();
    const sortedLines = [...auditData.lines].reverse();
    for (const line of sortedLines) {
      let recordObj: any = {};
      try {
        recordObj = JSON.parse(line.json);
      } catch (e) {
        continue;
      }
      if (line.record === 'workload_start') {
        active.set(recordObj.pid, {
          pid: recordObj.pid,
          policy: recordObj.policy,
          startedAt: line.ts_utc
        });
      } else if (line.record === 'workload_stop') {
        active.delete(recordObj.pid);
      }
    }
    return Array.from(active.values());
  }, [auditData]);

  // Derive a history of recent workloads (e.g. last 5)
  const recentWorkloads = useMemo(() => {
    if (!auditData?.lines) return [];
    const workloads: { pid: number; policy: string; ts: number; status: 'running' | 'success' | 'failed'; error?: string }[] = [];
    const starts = auditData.lines.filter(l => l.record === 'workload_start');
    const stops = auditData.lines.filter(l => l.record === 'workload_stop');
    
    for (const startLine of starts) {
      let startObj: any = {};
      try { startObj = JSON.parse(startLine.json); } catch (e) { continue; }
      
      const matchingStop = stops.find(s => {
        try {
          const stopObj = JSON.parse(s.json);
          return stopObj.pid === startObj.pid;
        } catch (e) {
          return false;
        }
      });
      
      let status: 'running' | 'success' | 'failed' = 'running';
      let error = '';
      if (matchingStop) {
        try {
          const stopObj = JSON.parse(matchingStop.json);
          if (stopObj.status === 'success' || stopObj.status === 'killed') {
            status = 'success';
          } else {
            status = 'failed';
            error = stopObj.status;
          }
        } catch (e) {}
      }
      
      workloads.push({
        pid: startObj.pid,
        policy: startObj.policy,
        ts: startLine.ts_utc,
        status,
        error
      });
    }
    
    workloads.sort((a, b) => b.ts - a.ts);
    return workloads.slice(0, 5);
  }, [auditData]);

  // Canvas Reference
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  // Interpolated vector for smooth movement in Canvas
  const currentVectorRef = useRef<[number, number, number]>([0, 0, 0]);
  const targetVectorRef = useRef<[number, number, number]>([0, 0, 0]);
  const lockProgressRef = useRef<number>(0);

  // 3D Orbit Interaction Refs
  const yawRef = useRef<number>(0);
  const pitchRef = useRef<number>(0.45);
  const zoomRef = useRef<number>(1.0);
  const isDraggingRef = useRef<boolean>(false);
  const lastMousePosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // Volumetric Particle Cloud Interface
  interface ExpertParticle {
    expert: string;
    ox: number;
    oy: number;
    oz: number;
    size: number;
    color: string;
  }
  const particlesRef = useRef<ExpertParticle[]>([]);

  // Dynamic Sprouted Experts State
  const [sproutedExperts, setSproutedExperts] = useState<{ id: string; label: string; color: string; x: number; y: number; z: number }[]>([]);
  const sproutingActiveRef = useRef<boolean>(false);
  const sproutingProgressRef = useRef<number>(0);
  const sproutingFilamentTargetRef = useRef<[number, number, number]>([0, 0, 0]);

  // Firewall Threat Animation States
  const firewallThreatActiveRef = useRef<boolean>(false);
  const firewallThreatProgressRef = useRef<number>(0);
  const firewallThreatPosRef = useRef<[number, number, number]>([0, 0, 0]);
  const firewallFlashRef = useRef<number>(0); // Flashes red/cyan on event

  // Anti-Entropy digest sweep
  const antiEntropyPulseRef = useRef<number>(0);
  const lastAntiEntropyTimeRef = useRef<number>(0);

  // Semantic Memory Consolidation Animation States
  const consolidationActiveRef = useRef<boolean>(false);
  const consolidationProgressRef = useRef<number>(0);
  const consolidationSourceRef = useRef<[number, number, number]>([0, 0, 0]);
  const consolidationTargetRef = useRef<[number, number, number]>([0, 0, 0]);
  const consolidationParticlesRef = useRef<{ x: number; y: number; z: number; progress: number; speed: number; delay: number }[]>([]);

  // Workload Sandboxing Container Nodes Ref
  const runningWorkloadsRef = useRef<any[]>([]);
  useEffect(() => {
    runningWorkloadsRef.current = runningWorkloads;
  }, [runningWorkloads]);

  interface ContainerNode {
    pid: number;
    policy: string;
    x: number;
    y: number;
    z: number;
    birthTime: number;
    deathTime: number | null;
    spawnFlash: number;
    deathFlash: number;
    isGvisor: boolean;
    particles: { x: number; y: number; z: number; vx: number; vy: number; vz: number; life: number; color: string }[];
  }
  const containerNodesRef = useRef<Record<number, ContainerNode>>({});



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

      // 6. Chain Status
      const chainRes = await fetch('http://127.0.0.1:8000/api/chain');
      if (chainRes.ok) {
        const data = await chainRes.json();
        setChainStatus(data);
      }

      // 7. Shipper Status
      const shipperRes = await fetch('http://127.0.0.1:8000/api/shipper');
      if (shipperRes.ok) {
        const data = await shipperRes.json();
        setShipperStatus(data);
      }

      // 8. Bitcoin L1 Anchor Status
      const anchorRes = await fetch('http://127.0.0.1:8000/api/anchor/latest');
      if (anchorRes.ok) {
        const data = await anchorRes.json();
        setAnchorData(data);
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

  // Poll Sanctuary Transaction Status
  useEffect(() => {
    if (!sanctuaryStatus || sanctuaryStatus.status === 'committed' || sanctuaryStatus.status === 'failed') {
      return;
    }

    let active = true;
    const pollStatus = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/sanctuary/status?seq=${sanctuaryStatus.seq}`);
        if (!active) return;
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'committed' || data.status === 'failed') {
            setSanctuaryStatus({
              seq: data.seq,
              status: data.status,
              error: data.error
            });
            // Auto-clear success status after 4 seconds
            if (data.status === 'committed') {
              setTimeout(() => {
                setSanctuaryStatus(current => {
                  if (current && current.seq === data.seq && current.status === 'committed') {
                    return null;
                  }
                  return current;
                });
              }, 4000);
            }
          }
        }
      } catch (err) {
        console.error("Error polling sanctuary status:", err);
      }
    };

    const intervalId = setInterval(pollStatus, 800);
    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [sanctuaryStatus]);

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
          const proj = data.projection;
          const x = proj.vector_3d?.[0] ?? proj.vector_2d?.[0] ?? 0;
          const y = proj.vector_3d?.[1] ?? proj.vector_2d?.[1] ?? 0;
          const z = proj.vector_3d?.[2] ?? (Math.sin(x * 3 + y * 2) * 0.4);
          targetVectorRef.current = [x, y, z];
        }
        if (data.sanctuary_seq) {
          setSanctuaryStatus({ seq: data.sanctuary_seq, status: 'pending' });
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
    targetVectorRef.current = [0, 0, 0];
    currentVectorRef.current = [0, 0, 0];
  };

  // Mouse and Touch Interaction Handlers for 3D Orbit
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    isDraggingRef.current = true;
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDraggingRef.current) return;
    const dx = e.clientX - lastMousePosRef.current.x;
    const dy = e.clientY - lastMousePosRef.current.y;
    
    // Update camera angles (yaw and pitch)
    yawRef.current += dx * 0.007;
    // Clamp pitch between -85 and 85 degrees to prevent gimbal lock
    pitchRef.current = Math.max(-1.48, Math.min(1.48, pitchRef.current + dy * 0.007));
    
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseUpOrLeave = () => {
    isDraggingRef.current = false;
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    // Zoom control
    zoomRef.current = Math.max(0.4, Math.min(2.5, zoomRef.current + e.deltaY * 0.001));
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

  // Trigger simulated threat (quarantine firewall animation)
  const triggerSimulatedThreat = () => {
    firewallThreatActiveRef.current = true;
    firewallThreatProgressRef.current = 0;
    // Set starting position at random outside boundary
    firewallThreatPosRef.current = [1.3, 0.7, -0.6];
    firewallFlashRef.current = 0;
    
    // Add warning audit line locally
    if (auditData) {
      setAuditData({
        lines: [
          { ts_utc: Date.now() / 1000, record: "[WARN] IMMUNOLOGY_FIREWALL: Rilevato vettore sospetto ad alto errore di ricostruzione (PRE > 0.05).", json: "{}" },
          ...auditData.lines
        ]
      });
    }
  };

  // Trigger simulated sprouting (OOD expert creation)
  const triggerSimulatedSprouting = () => {
    if (sproutingActiveRef.current) return;
    
    const count = sproutedExperts.length + 1;
    const targetX = 0.5 + Math.random() * 0.4;
    const targetY = -0.4 - Math.random() * 0.3;
    const targetZ = -0.3 - Math.random() * 0.4;
    
    sproutingActiveRef.current = true;
    sproutingProgressRef.current = 0;
    sproutingFilamentTargetRef.current = [targetX, targetY, targetZ];
    
    // Add sprout logs
    if (auditData) {
      setAuditData({
        lines: [
          { ts_utc: Date.now() / 1000, record: `[INFO] COGNITIVE_ROUTER: Rilevato concetto OOD. Inizializzazione sprouting per nuovo modulo Esperto_${count}...`, json: "{}" },
          ...auditData.lines
        ]
      });
    }
  };

  // Trigger memory consolidation animation
  const triggerSimulatedConsolidation = () => {
    if (consolidationActiveRef.current) return;
    
    // Select target: random active expert
    const expertKeys = ['Generale', 'Oncologia', 'HP-Folding'];
    const targetKey = expertKeys[Math.floor(Math.random() * expertKeys.length)];
    const targetExp = baseExperts[targetKey];
    
    // Starting position: a random spot on the episodic ring
    const angle = Math.random() * Math.PI * 2;
    const srcX = 0.9 * Math.cos(angle);
    const srcY = 0.0;
    const srcZ = 0.9 * Math.sin(angle);
    
    consolidationActiveRef.current = true;
    consolidationProgressRef.current = 0;
    consolidationSourceRef.current = [srcX, srcY, srcZ];
    consolidationTargetRef.current = [targetExp.x, targetExp.y, targetExp.z];
    consolidationParticlesRef.current = []; // will be generated in loop
    
    if (auditData) {
      setAuditData({
        lines: [
          { ts_utc: Date.now() / 1000, record: `[INFO] MEMORY_CONSOLIDATOR: Avvio consolidamento memoria episodica a breve termine nel cluster ${targetKey} (lungo termine).`, json: "{}" },
          ...auditData.lines
        ]
      });
    }
  };

  // Reset 3D camera orientation
  const resetCamera = () => {
    yawRef.current = 0;
    pitchRef.current = 0.45;
    zoomRef.current = 1.0;
  };

  // Trigger benchmark (real if online, simulated if offline)
  const triggerSimulatedBenchmark = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/benchmark');
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'triggered') {
          if (auditData) {
            setAuditData({
              lines: [
                { ts_utc: Date.now() / 1000, record: `[INFO] BENCHMARK: Avvio asincrono task di calcolo (Gompertz) in sandbox. ID: ${data.id_task}`, json: "{}" },
                ...auditData.lines
              ]
            });
          }
          return;
        }
      }
    } catch (e) {}

    // Offline / fallback simulator
    const simPid = Math.floor(1000 + Math.random() * 9000);
    const policy = "julia";
    const startLog: AuditLine = {
      ts_utc: Date.now() / 1000,
      record: "workload_start",
      json: JSON.stringify({ record: "workload_start", ts_utc: Date.now() / 1000, pid: simPid, policy })
    };
    
    // Inject start
    setAuditData(current => {
      if (!current) return { lines: [startLog] };
      return { lines: [startLog, ...current.lines] };
    });

    // Inject stop after 4 seconds
    setTimeout(() => {
      const stopLog: AuditLine = {
        ts_utc: Date.now() / 1000,
        record: "workload_stop",
        json: JSON.stringify({ record: "workload_stop", ts_utc: Date.now() / 1000, pid: simPid, status: "success" })
      };
      setAuditData(current => {
        if (!current) return { lines: [stopLog] };
        return { lines: [stopLog, ...current.lines] };
      });
    }, 4000);
  };

  // Canvas HUD Projection Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const render = (time: number) => {
      // Clear and size canvas to container
      const width = canvas.width = canvas.parentElement?.clientWidth || 500;
      const height = canvas.height = canvas.parentElement?.clientHeight || 400;
      
      ctx.fillStyle = '#030712';
      ctx.fillRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(width, height) * 0.40;

      // 3D Projection Math with Interactive Drag & Zoom camera orientation
      const project3D = (x: number, y: number, z: number) => {
        // Horizontal rotation over time (vertical axis) + manual drag
        const rotY = yawRef.current + time * 0.0001;
        const x1 = x * Math.cos(rotY) - z * Math.sin(rotY);
        const z1 = x * Math.sin(rotY) + z * Math.cos(rotY);

        // Vertical tilt + manual drag
        const tiltX = pitchRef.current + Math.sin(time * 0.0001) * 0.03;
        const y2 = y * Math.cos(tiltX) + z1 * Math.sin(tiltX);
        const z2 = -y * Math.sin(tiltX) + z1 * Math.cos(tiltX);

        // Perspective scaling (camera distance)
        const cameraDistance = 2.5;
        const scale = cameraDistance / (cameraDistance + z2);
        
        const sx = centerX + x1 * scale * radius * zoomRef.current;
        const sy = centerY - y2 * scale * radius * zoomRef.current;
        
        return { x: sx, y: sy, z: z2, scale: scale * zoomRef.current };
      };

      // Volumetric Particle Cloud Jitter (Brownian Motion)
      if (particlesRef.current.length === 0) {
        const list: ExpertParticle[] = [];
        const colors: Record<string, string> = { Generale: '#10b981', Oncologia: '#ef4444', 'HP-Folding': '#a855f7' };
        Object.entries(colors).forEach(([expName, color]) => {
          for (let i = 0; i < 35; i++) {
            const ox = (Math.random() + Math.random() + Math.random() - 1.5) * 0.12;
            const oy = (Math.random() + Math.random() + Math.random() - 1.5) * 0.12;
            const oz = (Math.random() + Math.random() + Math.random() - 1.5) * 0.12;
            list.push({
              expert: expName,
              ox, oy, oz,
              size: Math.random() * 1.5 + 0.6,
              color
            });
          }
        });
        particlesRef.current = list;
      }

      // Add jitter to expert particles
      particlesRef.current.forEach(p => {
        p.ox += (Math.random() - 0.5) * 0.002;
        p.oy += (Math.random() - 0.5) * 0.002;
        p.oz += (Math.random() - 0.5) * 0.002;
        const dist = Math.sqrt(p.ox*p.ox + p.oy*p.oy + p.oz*p.oz);
        if (dist > 0.22) {
          p.ox *= 0.9;
          p.oy *= 0.9;
          p.oz *= 0.9;
        }
      });

      // 1. Draw 3D Grid floor (concentric rings in X-Z plane)
      const ringColor = 'rgba(6, 182, 212, 0.05)';
      const ringColorDashed = 'rgba(6, 182, 212, 0.12)';
      
      const drawXZRing = (r: number, color: string, isDashed = false) => {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        if (isDashed) ctx.setLineDash([2, 5]);
        ctx.beginPath();
        const segments = 64;
        for (let j = 0; j <= segments; j++) {
          const theta = (j / segments) * Math.PI * 2;
          const px = r * Math.cos(theta);
          const pz = r * Math.sin(theta);
          const pt = project3D(px, 0, pz);
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();
        if (isDashed) ctx.setLineDash([]);
      };

      // Floor rings
      for (let i = 1; i <= 4; i++) {
        drawXZRing(i / 4, i === 4 ? ringColorDashed : ringColor, i === 4);
      }

      // 2. Draw outer wireframe sphere hoops (X-Y and Y-Z hoops at radius 0.6)
      const drawSphereWireframe = () => {
        // Y-Z hoop
        ctx.strokeStyle = 'rgba(168, 85, 247, 0.03)';
        ctx.beginPath();
        for (let j = 0; j <= 64; j++) {
          const theta = (j / 64) * Math.PI * 2;
          const pt = project3D(0, 0.6 * Math.cos(theta), 0.6 * Math.sin(theta));
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();

        // X-Y hoop
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.03)';
        ctx.beginPath();
        for (let j = 0; j <= 64; j++) {
          const theta = (j / 64) * Math.PI * 2;
          const pt = project3D(0.6 * Math.cos(theta), 0.6 * Math.sin(theta), 0);
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();
      };
      drawSphereWireframe();

      // 3. Draw Anchor Concepts (Constellation of Gold Star axioms inside Rosetta core)
      const anchors = [
        { x: 0.15, y: 0.25, z: -0.20, label: 'Axiom-Ω' },
        { x: -0.30, y: -0.15, z: 0.25, label: 'Planck-h' },
        { x: 0.20, y: -0.25, z: -0.10, label: 'Newton-G' },
        { x: -0.10, y: 0.35, z: 0.15, label: 'Dirac-e' },
        { x: 0.35, y: 0.10, z: 0.30, label: 'Boltzmann-kB' },
        { x: -0.25, y: 0.20, z: -0.35, label: 'Maxwell-c' },
        { x: 0.30, y: -0.30, z: 0.20, label: 'Rosetta-π' },
        { x: -0.35, y: -0.25, z: -0.15, label: 'Euler-φ' }
      ];

      // Draw constellation lines first
      ctx.strokeStyle = 'rgba(254, 240, 138, 0.05)';
      ctx.lineWidth = 1;
      const connections = [[0, 1], [1, 5], [2, 6], [3, 7], [0, 4], [4, 7], [2, 3]];
      connections.forEach(([i, j]) => {
        const ptA = project3D(anchors[i].x, anchors[i].y, anchors[i].z);
        const ptB = project3D(anchors[j].x, anchors[j].y, anchors[j].z);
        if (isFinite(ptA.x) && isFinite(ptA.y) && isFinite(ptB.x) && isFinite(ptB.y)) {
          ctx.beginPath();
          ctx.moveTo(ptA.x, ptA.y);
          ctx.lineTo(ptB.x, ptB.y);
          ctx.stroke();
        }
      });

      // Draw anchor dots
      anchors.forEach(a => {
        const pt = project3D(a.x, a.y, a.z);
        const depthOpacity = Math.max(0.15, Math.min(0.8, 1 - (pt.z + 1.2) / 2.4));
        ctx.fillStyle = `rgba(254, 240, 138, ${depthOpacity})`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 2 * pt.scale, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = `rgba(254, 240, 138, ${depthOpacity * 0.4})`;
        ctx.font = `${Math.max(5, Math.floor(6.5 * pt.scale))}px "Share Tech Mono"`;
        ctx.fillText(a.label, pt.x + 5 * pt.scale, pt.y + 2);
      });

      // 4. Concentric Orbiting Dials on the X-Z plane floor (gyroscope style)
      const rotAngle = time * 0.0008;
      
      const drawXZDial = (r: number, rotSpeed: number, color: string, dashes: number[]) => {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        if (dashes.length > 0) ctx.setLineDash(dashes);
        ctx.beginPath();
        const segments = 64;
        const currentAngle = rotAngle * rotSpeed;
        for (let j = 0; j <= segments; j++) {
          const theta = (j / segments) * Math.PI * 2 + currentAngle;
          const px = r * Math.cos(theta);
          const pz = r * Math.sin(theta);
          const pt = project3D(px, 0, pz);
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();
        if (dashes.length > 0) ctx.setLineDash([]);
      };

      drawXZDial(1.05, 0.25, 'rgba(168, 85, 247, 0.12)', [20, 40]);
      drawXZDial(0.8, -0.5, 'rgba(6, 182, 212, 0.10)', [4, 15]);
      drawXZDial(0.4, 0.7, 'rgba(168, 85, 247, 0.10)', [2, 8]);

      // 5. Draw 3D coordinate axes
      const axes = [
        { start: [-1.1, 0, 0], end: [1.1, 0, 0], label: 'X', color: 'rgba(6, 182, 212, 0.15)' },
        { start: [0, -1.1, 0], end: [0, 1.1, 0], label: 'Y', color: 'rgba(168, 85, 247, 0.15)' },
        { start: [0, 0, -1.1], end: [0, 0, 1.1], label: 'Z', color: 'rgba(16, 185, 129, 0.15)' }
      ];
      axes.forEach(axis => {
        const ptS = project3D(axis.start[0], axis.start[1], axis.start[2]);
        const ptE = project3D(axis.end[0], axis.end[1], axis.end[2]);
        ctx.strokeStyle = axis.color;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(ptS.x, ptS.y);
        ctx.lineTo(ptE.x, ptE.y);
        ctx.stroke();
        
        ctx.fillStyle = 'rgba(243, 244, 246, 0.25)';
        ctx.font = '8px "Share Tech Mono"';
        ctx.fillText(axis.label, ptE.x + 4, ptE.y + 3);
      });

      // 6. Define active experts (base + sprouted)
      const experts3d: Record<string, { x: number; y: number; z: number; color: string; label: string }> = { ...baseExperts };
      sproutedExperts.forEach(exp => {
        experts3d[exp.id] = { x: exp.x, y: exp.y, z: exp.z, color: exp.color, label: exp.label };
      });

      // Draw volumetric particle clouds (Expert density clouds)
      particlesRef.current.forEach(p => {
        const exp = experts3d[p.expert];
        if (!exp) return;
        const px = exp.x + p.ox;
        const py = exp.y + p.oy;
        const pz = exp.z + p.oz;
        const pt = project3D(px, py, pz);
        if (!isFinite(pt.x) || !isFinite(pt.y)) return;

        const depthOpacity = Math.max(0.1, Math.min(0.7, 1 - (pt.z + 1.2) / 2.4));
        ctx.fillStyle = `${p.color}${Math.floor(depthOpacity * 80).toString(16).padStart(2, '0')}`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, p.size * pt.scale, 0, Math.PI * 2);
        ctx.fill();
      });

      // Draw dynamic sprouted expert particles if active
      sproutedExperts.forEach(exp => {
        for (let i = 0; i < 20; i++) {
          const jitterAngle = (i / 20) * Math.PI * 2 + time * 0.001;
          const r = 0.04 + Math.sin(time * 0.005 + i) * 0.015;
          const px = exp.x + r * Math.cos(jitterAngle);
          const py = exp.y + Math.sin(time * 0.002 + i) * 0.03;
          const pz = exp.z + r * Math.sin(jitterAngle);
          const pt = project3D(px, py, pz);
          if (!isFinite(pt.x) || !isFinite(pt.y)) continue;
          
          const depthOpacity = Math.max(0.1, Math.min(0.6, 1 - (pt.z + 1.2) / 2.4));
          ctx.fillStyle = `${exp.color}${Math.floor(depthOpacity * 70).toString(16).padStart(2, '0')}`;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, pt.scale, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // Draw expert centroids in 3D (sorted by depth Z for layering)
      const projectedExperts = Object.entries(experts3d).map(([name, exp]) => {
        const pt = project3D(exp.x, exp.y, exp.z);
        return { name, exp, pt };
      });
      
      projectedExperts.sort((a, b) => b.pt.z - a.pt.z);

      projectedExperts.forEach(({ exp, pt }) => {
        const depthOpacity = Math.max(0.2, Math.min(1.0, 1 - (pt.z + 1.2) / 2.4));
        
        ctx.fillStyle = `${exp.color}${Math.floor(depthOpacity * 12).toString(16).padStart(2, '0')}`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 14 * pt.scale, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = `${exp.color}${Math.floor(depthOpacity * 50).toString(16).padStart(2, '0')}`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 8 * pt.scale, 0, Math.PI * 2);
        ctx.stroke();

        ctx.fillStyle = exp.color;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 3.5 * pt.scale, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = `rgba(243, 244, 246, ${0.25 + depthOpacity * 0.4})`;
        ctx.font = `${Math.max(6, Math.floor(9 * pt.scale))}px "Share Tech Mono"`;
        ctx.fillText(exp.label, pt.x + 10 * pt.scale, pt.y + 3);
      });

      // 7. Vector Interpolation & Render
      const tx = targetVectorRef.current[0] ?? 0;
      const ty = targetVectorRef.current[1] ?? 0;
      const tz = targetVectorRef.current[2] ?? 0;

      const cx = currentVectorRef.current[0] ?? 0;
      const cy = currentVectorRef.current[1] ?? 0;
      const cz = currentVectorRef.current[2] ?? 0;

      const dx = tx - cx;
      const dy = ty - cy;
      const dz = tz - cz;

      currentVectorRef.current[0] = cx + dx * 0.08;
      currentVectorRef.current[1] = cy + dy * 0.08;
      currentVectorRef.current[2] = cz + dz * 0.08;

      const cvx = currentVectorRef.current[0];
      const cvy = currentVectorRef.current[1];
      const cvz = currentVectorRef.current[2];
      const vpt = project3D(cvx, cvy, cvz);

      const hasActiveProjection = lastProjection !== null;

      if (hasActiveProjection && !firewallThreatActiveRef.current) {
        const opt = project3D(0, 0, 0);
        if (isFinite(opt.x) && isFinite(opt.y) && isFinite(vpt.x) && isFinite(vpt.y)) {
          ctx.strokeStyle = 'rgba(6, 182, 212, 0.4)';
          ctx.lineWidth = 1.5;
          ctx.setLineDash([3, 3]);
          ctx.beginPath();
          ctx.moveTo(opt.x, opt.y);
          ctx.lineTo(vpt.x, vpt.y);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        const floorPt = project3D(cvx, 0, cvz);
        if (isFinite(vpt.x) && isFinite(vpt.y) && isFinite(floorPt.x) && isFinite(floorPt.y)) {
          ctx.strokeStyle = 'rgba(6, 182, 212, 0.2)';
          ctx.lineWidth = 1;
          ctx.setLineDash([1, 4]);
          ctx.beginPath();
          ctx.moveTo(vpt.x, vpt.y);
          ctx.lineTo(floorPt.x, floorPt.y);
          ctx.stroke();
          ctx.setLineDash([]);
          
          ctx.fillStyle = 'rgba(6, 182, 212, 0.25)';
          ctx.beginPath();
          ctx.arc(floorPt.x, floorPt.y, 2, 0, Math.PI * 2);
          ctx.fill();
        }

        const route = lastProjection?.routing;
        if (route && experts3d[route]) {
          const exp = experts3d[route];
          const ept = project3D(exp.x, exp.y, exp.z);
          
          if (isFinite(vpt.x) && isFinite(vpt.y) && isFinite(ept.x) && isFinite(ept.y)) {
            ctx.strokeStyle = exp.color + '66';
            ctx.lineWidth = 1.5;
            ctx.setLineDash([2, 4]);
            ctx.beginPath();
            ctx.moveTo(vpt.x, vpt.y);
            ctx.lineTo(ept.x, ept.y);
            ctx.stroke();
            ctx.setLineDash([]);
          }
        }

        const pulse = (Math.sin(time * 0.007) * 4 + 10) * vpt.scale;
        if (isFinite(vpt.x) && isFinite(vpt.y) && isFinite(pulse) && pulse > 0) {
          const grad = ctx.createRadialGradient(vpt.x, vpt.y, 1, vpt.x, vpt.y, pulse);
          grad.addColorStop(0, 'rgba(6, 182, 212, 1)');
          grad.addColorStop(0.3, 'rgba(6, 182, 212, 0.5)');
          grad.addColorStop(1, 'rgba(6, 182, 212, 0)');
          ctx.fillStyle = grad;
          ctx.beginPath();
          ctx.arc(vpt.x, vpt.y, pulse, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = '#06b6d4';
          ctx.beginPath();
          ctx.arc(vpt.x, vpt.y, Math.max(1, 4 * vpt.scale), 0, Math.PI * 2);
          ctx.fill();
        }

        const bracketOffset = (1 - lockProgressRef.current) * 25 + 10;
        const bSize = 6;
        ctx.strokeStyle = `rgba(6, 182, 212, ${0.4 + lockProgressRef.current * 0.5})`;
        ctx.lineWidth = 1.5;
        
        ctx.beginPath();
        ctx.moveTo(vpt.x - bracketOffset, vpt.y - bracketOffset + bSize);
        ctx.lineTo(vpt.x - bracketOffset, vpt.y - bracketOffset);
        ctx.lineTo(vpt.x - bracketOffset + bSize, vpt.y - bracketOffset);
        
        ctx.moveTo(vpt.x + bracketOffset, vpt.y - bracketOffset + bSize);
        ctx.lineTo(vpt.x + bracketOffset, vpt.y - bracketOffset);
        ctx.lineTo(vpt.x + bracketOffset - bSize, vpt.y - bracketOffset);
        
        ctx.moveTo(vpt.x - bracketOffset, vpt.y + bracketOffset - bSize);
        ctx.lineTo(vpt.x - bracketOffset, vpt.y + bracketOffset);
        ctx.lineTo(vpt.x - bracketOffset + bSize, vpt.y + bracketOffset);
        
        ctx.moveTo(vpt.x + bracketOffset, vpt.y + bracketOffset - bSize);
        ctx.lineTo(vpt.x + bracketOffset, vpt.y + bracketOffset);
        ctx.lineTo(vpt.x + bracketOffset - bSize, vpt.y + bracketOffset);
        ctx.stroke();

        ctx.fillStyle = '#f3f4f6';
        ctx.font = '10px "Share Tech Mono"';
        ctx.fillText(`Vector Omega (v_ω)`, vpt.x + 12, vpt.y - 12);
        ctx.fillStyle = 'rgba(6, 182, 212, 0.8)';
        ctx.fillText(`[X: ${cvx.toFixed(3)}, Y: ${cvy.toFixed(3)}, Z: ${cvz.toFixed(3)}]`, vpt.x + 12, vpt.y - 2);
      } else if (!firewallThreatActiveRef.current) {
        const idleX = Math.sin(time * 0.001) * 0.3;
        const idleY = Math.cos(time * 0.0008) * 0.3;
        const idleZ = Math.sin(time * 0.0012) * 0.2;
        targetVectorRef.current = [idleX, idleY, idleZ];

        const pulse = (Math.sin(time * 0.005) * 2 + 6) * vpt.scale;
        ctx.fillStyle = 'rgba(6, 182, 212, 0.12)';
        ctx.beginPath();
        ctx.arc(vpt.x, vpt.y, pulse, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = 'rgba(6, 182, 212, 0.4)';
        ctx.beginPath();
        ctx.arc(vpt.x, vpt.y, 2.5 * vpt.scale, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = 'rgba(6, 182, 212, 0.3)';
        ctx.font = '9px "Share Tech Mono"';
        ctx.fillText("Allineatore Rosetta Attivo (Scan)", vpt.x + 8, vpt.y - 4);
      }

      // 8. Dynamic Sprouting Animation (Germogliazione)
      if (sproutingActiveRef.current) {
        sproutingProgressRef.current = Math.min(1.0, sproutingProgressRef.current + 0.008);
        
        const startPt = project3D(0, 0, 0);
        const [tx, ty, tz] = sproutingFilamentTargetRef.current;
        const fx = tx * sproutingProgressRef.current;
        const fy = ty * sproutingProgressRef.current;
        const fz = tz * sproutingProgressRef.current;
        const filamentPt = project3D(fx, fy, fz);

        // Micro-camera shift/vibration
        yawRef.current += Math.sin(sproutingProgressRef.current * Math.PI * 8) * 0.002;

        if (isFinite(startPt.x) && isFinite(startPt.y) && isFinite(filamentPt.x) && isFinite(filamentPt.y)) {
          ctx.strokeStyle = 'rgba(245, 158, 11, 0.8)'; // Amber sprout filament
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.moveTo(startPt.x, startPt.y);
          ctx.lineTo(filamentPt.x, filamentPt.y);
          ctx.stroke();

          ctx.fillStyle = '#f59e0b';
          ctx.beginPath();
          ctx.arc(filamentPt.x, filamentPt.y, 4 * filamentPt.scale, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = '#f3f4f6';
          ctx.font = '9px "Share Tech Mono"';
          ctx.fillText(`GERMOGLIAZIONE: Esperto_${sproutedExperts.length + 1} (${Math.floor(sproutingProgressRef.current*100)}%)`, filamentPt.x + 10, filamentPt.y - 4);
        }

        if (sproutingProgressRef.current >= 1.0) {
          sproutingActiveRef.current = false;
          const nextCount = sproutedExperts.length + 1;
          const newExpName = `Esperto_${nextCount}`;
          const newExp = {
            id: newExpName,
            label: `Centr. ${newExpName} (OOD)`,
            color: '#f59e0b',
            x: tx, y: ty, z: tz
          };
          setSproutedExperts([...sproutedExperts, newExp]);
        }
      }

      // 9. Semantic Immunology Firewall & Threat Quarantine
      if (firewallThreatActiveRef.current) {
        firewallThreatProgressRef.current = Math.min(1.0, firewallThreatProgressRef.current + 0.015);
        const progress = firewallThreatProgressRef.current;

        // Path of threat vector: starts at [1.3, 0.7, -0.6] and enters system
        let tx = 1.3 * (1 - progress);
        let ty = 0.7 * (1 - progress);
        let tz = -0.6 * (1 - progress);
        
        const cagePos: [number, number, number] = [1.2, -0.8, 0.4];

        if (progress > 0.65) {
          // Hits shield and gets quarantined (redirected to quarantine cage)
          const redirectProgress = (progress - 0.65) / 0.35;
          tx = 0 * (1 - redirectProgress) + cagePos[0] * redirectProgress;
          ty = 0.35 * (1 - redirectProgress) + cagePos[1] * redirectProgress;
          tz = 0 * (1 - redirectProgress) + cagePos[2] * redirectProgress;
          firewallFlashRef.current = Math.max(0, 1 - (progress - 0.65) * 3); // Flash decay
        }

        const threatPt = project3D(tx, ty, tz);
        
        // Draw the concentric protection shield
        const shieldColor = firewallFlashRef.current > 0 
          ? `rgba(239, 68, 68, ${0.15 + firewallFlashRef.current * 0.4})` 
          : 'rgba(6, 182, 212, 0.07)';
        ctx.strokeStyle = shieldColor;
        ctx.lineWidth = 2;
        drawXZRing(1.15, shieldColor, false);

        if (isFinite(threatPt.x) && isFinite(threatPt.y)) {
          // Render threat point
          ctx.fillStyle = '#ef4444';
          ctx.beginPath();
          ctx.arc(threatPt.x, threatPt.y, 5 * threatPt.scale, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = '#ef4444';
          ctx.font = '8px "Share Tech Mono"';
          ctx.fillText(`ALERT: PAYLOAD_SPAM // PRE: 0.1843`, threatPt.x + 10, threatPt.y - 4);

          // Draw laser blast when hitting shield
          if (progress >= 0.65 && progress < 0.8) {
            const shieldPt = project3D(1.15 * Math.cos(time * 0.005), 0, 1.15 * Math.sin(time * 0.005));
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.9)';
            ctx.lineWidth = 3;
            ctx.beginPath();
            ctx.moveTo(shieldPt.x, shieldPt.y);
            ctx.lineTo(threatPt.x, threatPt.y);
            ctx.stroke();
          }

          // Draw Quarantine Cage at [1.2, -0.8, 0.4]
          const cageCenter = project3D(cagePos[0], cagePos[1], cagePos[2]);
          if (isFinite(cageCenter.x) && isFinite(cageCenter.y)) {
            const cSize = 25 * cageCenter.scale;
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.5)';
            ctx.lineWidth = 1;
            ctx.strokeRect(cageCenter.x - cSize/2, cageCenter.y - cSize/2, cSize, cSize);
            ctx.fillStyle = 'rgba(239, 68, 68, 0.1)';
            ctx.fillRect(cageCenter.x - cSize/2, cageCenter.y - cSize/2, cSize, cSize);
            ctx.fillStyle = '#ef4444';
            ctx.font = '7px "Share Tech Mono"';
            ctx.fillText("QUARANTENA", cageCenter.x - cSize/2, cageCenter.y - cSize/2 - 2);
          }
        }

        if (progress >= 1.0) {
          firewallThreatActiveRef.current = false;
        }
      }

      // 10. Double Memory Store (Episodic Memory Ring turns & Consolidation)
      const episodicTurns = chatMessages.slice(-5);
      const turnsCount = episodicTurns.length;
      if (turnsCount > 0) {
        episodicTurns.forEach((turn, idx) => {
          const angle = (idx * 2 * Math.PI / turnsCount) + time * 0.00015;
          const rx = 0.95 * Math.cos(angle);
          const ry = 0.1 * Math.sin(time * 0.0015 + idx);
          const rz = 0.95 * Math.sin(angle);
          const pt = project3D(rx, ry, rz);

          if (isFinite(pt.x) && isFinite(pt.y)) {
            // Draw capsule
            const cColor = turn.role === 'user' ? 'rgba(168, 85, 247, 0.3)' : 'rgba(6, 182, 212, 0.3)';
            const cBg = turn.role === 'user' ? 'rgba(168, 85, 247, 0.08)' : 'rgba(6, 182, 212, 0.08)';
            ctx.strokeStyle = cColor;
            ctx.fillStyle = cBg;
            ctx.lineWidth = 1;
            
            const w = 40 * pt.scale;
            const h = 14 * pt.scale;
            ctx.beginPath();
            ctx.roundRect(pt.x - w/2, pt.y - h/2, w, h, 4);
            ctx.fill();
            ctx.stroke();

            // Label
            ctx.fillStyle = '#f3f4f6';
            ctx.font = `${Math.max(5, Math.floor(7 * pt.scale))}px "Share Tech Mono"`;
            const labelText = turn.role === 'user' ? `USER` : `AI`;
            ctx.fillText(labelText, pt.x - 10 * pt.scale, pt.y + 2.5 * pt.scale);
          }
        });
      }

      // Semantic Consolidation Particles Stream
      if (consolidationActiveRef.current) {
        consolidationProgressRef.current = Math.min(1.0, consolidationProgressRef.current + 0.015);
        const progress = consolidationProgressRef.current;

        // Initialize particles if empty
        if (consolidationParticlesRef.current.length === 0) {
          const parts = [];
          for (let i = 0; i < 20; i++) {
            parts.push({
              x: consolidationSourceRef.current[0],
              y: consolidationSourceRef.current[1],
              z: consolidationSourceRef.current[2],
              progress: 0,
              speed: 0.015 + Math.random() * 0.02,
              delay: Math.random() * 0.3
            });
          }
          consolidationParticlesRef.current = parts;
        }

        // Draw and update each consolidation particle
        const [tx, ty, tz] = consolidationTargetRef.current;
        consolidationParticlesRef.current.forEach(p => {
          if (progress > p.delay) {
            p.progress = Math.min(1.0, p.progress + p.speed);
          }
          const px = p.x * (1 - p.progress) + tx * p.progress + (Math.random() - 0.5) * 0.04;
          const py = p.y * (1 - p.progress) + ty * p.progress + (Math.random() - 0.5) * 0.04;
          const pz = p.z * (1 - p.progress) + tz * p.progress + (Math.random() - 0.5) * 0.04;
          const pt = project3D(px, py, pz);

          if (isFinite(pt.x) && isFinite(pt.y) && p.progress < 1.0) {
            ctx.fillStyle = 'rgba(6, 182, 212, 0.8)';
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 1.5 * pt.scale, 0, Math.PI * 2);
            ctx.fill();
          }
        });

        if (progress >= 1.0) {
          consolidationActiveRef.current = false;
          consolidationParticlesRef.current = [];
        }
      }

      // 11. Gossip UDP Links & Anti-Entropy Pulses
      const gossipPeers = [
        { name: 'Guardiano-C', x: -1.3, y: -0.2, z: 0.4, color: '#06b6d4' },
        { name: 'Guardiano-D', x: 1.2, y: 0.3, z: -0.5, color: '#a855f7' }
      ];

      gossipPeers.forEach(peer => {
        const pt = project3D(peer.x, peer.y, peer.z);
        const opt = project3D(0, 0, 0);

        if (isFinite(pt.x) && isFinite(pt.y) && isFinite(opt.x) && isFinite(opt.y)) {
          // Draw peer link
          ctx.strokeStyle = 'rgba(6, 182, 212, 0.07)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(opt.x, opt.y);
          ctx.lineTo(pt.x, pt.y);
          ctx.stroke();

          // Draw peer server node
          ctx.strokeStyle = peer.color + '44';
          ctx.fillStyle = 'rgba(17, 24, 39, 0.6)';
          ctx.lineWidth = 1;
          const size = 12 * pt.scale;
          ctx.strokeRect(pt.x - size/2, pt.y - size/2, size, size);
          ctx.fillRect(pt.x - size/2, pt.y - size/2, size, size);

          ctx.fillStyle = 'rgba(243, 244, 246, 0.4)';
          ctx.font = '7px "Share Tech Mono"';
          ctx.fillText(peer.name, pt.x - 18, pt.y - size/2 - 2);

          // Draw envelope packet traveling
          const gossipProgress = (time * 0.0004) % 1.0;
          const epx = peer.x * (1 - gossipProgress);
          const epy = peer.y * (1 - gossipProgress);
          const epz = peer.z * (1 - gossipProgress);
          const envelopePt = project3D(epx, epy, epz);
          if (isFinite(envelopePt.x) && isFinite(envelopePt.y)) {
            ctx.fillStyle = '#06b6d4';
            ctx.beginPath();
            ctx.arc(envelopePt.x, envelopePt.y, 2 * envelopePt.scale, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      });

      // Anti-Entropy digest sweep (every 10 seconds)
      const elapsed = time - lastAntiEntropyTimeRef.current;
      if (elapsed > 10000) {
        lastAntiEntropyTimeRef.current = time;
        antiEntropyPulseRef.current = 0;
      }
      
      antiEntropyPulseRef.current = Math.min(1.0, antiEntropyPulseRef.current + 0.012);
      const sweepRad = antiEntropyPulseRef.current * 1.5;
      if (sweepRad > 0 && sweepRad < 1.5) {
        ctx.strokeStyle = `rgba(16, 185, 129, ${0.3 * (1 - antiEntropyPulseRef.current)})`;
        ctx.lineWidth = 1.5;
        drawXZRing(sweepRad, ctx.strokeStyle, false);
      }

      // 11.5 Sanctuary Spooler Visualisation
      if (sanctuaryStatusRef.current) {
        const sStatus = sanctuaryStatusRef.current;
        const sx = 0;
        const sy = -0.9;
        const sz = 0;
        const pt = project3D(sx, sy, sz);
        const opt = project3D(0, 0, 0);

        if (isFinite(pt.x) && isFinite(pt.y) && isFinite(opt.x) && isFinite(opt.y)) {
          // Draw sanctuary link
          let linkColor = 'rgba(245, 158, 11, 0.1)';
          let nodeColor = '#f59e0b';
          if (sStatus.status === 'committed') {
            linkColor = 'rgba(6, 182, 212, 0.25)';
            nodeColor = '#06b6d4';
          } else if (sStatus.status === 'failed') {
            linkColor = 'rgba(239, 68, 68, 0.25)';
            nodeColor = '#ef4444';
          }
          
          ctx.strokeStyle = linkColor;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(opt.x, opt.y);
          ctx.lineTo(pt.x, pt.y);
          ctx.stroke();

          // Draw sanctuary node (cold storage safe)
          ctx.strokeStyle = nodeColor + '66';
          ctx.fillStyle = 'rgba(17, 24, 39, 0.85)';
          ctx.lineWidth = 2;
          const size = 16 * pt.scale;
          
          // Draw diamond shape
          ctx.beginPath();
          ctx.moveTo(pt.x, pt.y - size/2);
          ctx.lineTo(pt.x + size/2, pt.y);
          ctx.lineTo(pt.x, pt.y + size/2);
          ctx.lineTo(pt.x - size/2, pt.y);
          ctx.closePath();
          ctx.stroke();
          ctx.fill();

          // Text label
          ctx.fillStyle = 'rgba(243, 244, 246, 0.7)';
          ctx.font = '7px "Share Tech Mono"';
          ctx.fillText(`SANCTUARY (TX #${sStatus.seq})`, pt.x - 30 * pt.scale, pt.y + size/2 + 8 * pt.scale);

          // If pending, animate an envelope packet moving along the link
          if (sStatus.status === 'pending') {
            const packetProgress = (time * 0.001) % 1.0;
            const px = sx * packetProgress;
            const py = sy * packetProgress;
            const pz = sz * packetProgress;
            const pPt = project3D(px, py, pz);
            if (isFinite(pPt.x) && isFinite(pPt.y)) {
              ctx.fillStyle = '#f59e0b';
              ctx.beginPath();
              ctx.arc(pPt.x, pPt.y, 3 * pPt.scale, 0, Math.PI * 2);
              ctx.fill();
            }
          }
        }
      }

      // 11.6 Bitcoin L1 Anchor Visualisation
      if (anchorDataRef.current && anchorDataRef.current.latest_anchor) {
        const latest = anchorDataRef.current.latest_anchor;
        const btc_tx = latest.btc_tx_hash;
        if (btc_tx) {
          const bx = -0.7;
          const by = -0.4;
          const bz = -0.7;
          const pt = project3D(bx, by, bz);
          
          // General Centroid coordinate
          const gx = 0.60;
          const gy = 0.40;
          const gz = 0.20;
          const gpt = project3D(gx, gy, gz);
          
          if (isFinite(pt.x) && isFinite(pt.y) && isFinite(gpt.x) && isFinite(gpt.y)) {
            // Draw golden filament (glowing yellow/amber line connecting Generale to Bitcoin Anchor)
            ctx.strokeStyle = 'rgba(245, 158, 11, 0.4)'; // bright amber/gold
            ctx.lineWidth = 2.0;
            ctx.beginPath();
            ctx.moveTo(gpt.x, gpt.y);
            ctx.lineTo(pt.x, pt.y);
            ctx.stroke();
            
            // Draw vertical dashed line to floor
            const floorPt = project3D(bx, 0, bz);
            if (isFinite(floorPt.x) && isFinite(floorPt.y)) {
              ctx.strokeStyle = 'rgba(245, 158, 11, 0.15)';
              ctx.lineWidth = 1;
              ctx.setLineDash([2, 3]);
              ctx.beginPath();
              ctx.moveTo(pt.x, pt.y);
              ctx.lineTo(floorPt.x, floorPt.y);
              ctx.stroke();
              ctx.setLineDash([]);
            }
            
            // Draw golden node (diamond shape representing Bitcoin L1 anchor)
            ctx.strokeStyle = 'rgba(245, 158, 11, 0.8)';
            ctx.fillStyle = 'rgba(17, 24, 39, 0.9)';
            ctx.lineWidth = 2;
            const size = 12 * pt.scale;
            ctx.beginPath();
            ctx.moveTo(pt.x, pt.y - size);
            ctx.lineTo(pt.x + size, pt.y);
            ctx.lineTo(pt.x, pt.y + size);
            ctx.lineTo(pt.x - size, pt.y);
            ctx.closePath();
            ctx.stroke();
            ctx.fill();
            
            // Inner core
            ctx.fillStyle = '#f59e0b';
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 3 * pt.scale, 0, Math.PI * 2);
            ctx.fill();
            
            // Label
            ctx.fillStyle = 'rgba(245, 158, 11, 0.9)';
            ctx.font = '7.5px "Share Tech Mono"';
            ctx.fillText('₿ Bitcoin L1 Anchor', pt.x - 32 * pt.scale, pt.y + size + 9 * pt.scale);
            
            ctx.fillStyle = 'rgba(243, 244, 246, 0.6)';
            ctx.font = '6.5px "Share Tech Mono"';
            ctx.fillText(`BTC TX: ${btc_tx.substring(0, 10)}...`, pt.x - 32 * pt.scale, pt.y + size + 16 * pt.scale);
            
            // Glowing pulse moving from General Centroid to Bitcoin Anchor
            const pulseProgress = (time * 0.00025) % 1.0;
            const px = gx + (bx - gx) * pulseProgress;
            const py = gy + (by - gy) * pulseProgress;
            const pz = gz + (bz - gz) * pulseProgress;
            const pulsePt = project3D(px, py, pz);
            
            if (isFinite(pulsePt.x) && isFinite(pulsePt.y)) {
              const grad = ctx.createRadialGradient(pulsePt.x, pulsePt.y, 1, pulsePt.x, pulsePt.y, 8 * pulsePt.scale);
              grad.addColorStop(0, 'rgba(245, 158, 11, 1)');
              grad.addColorStop(0.5, 'rgba(245, 158, 11, 0.4)');
              grad.addColorStop(1, 'rgba(245, 158, 11, 0)');
              ctx.fillStyle = grad;
              ctx.beginPath();
              ctx.arc(pulsePt.x, pulsePt.y, 8 * pulsePt.scale, 0, Math.PI * 2);
              ctx.fill();
            }
          }
        }
      }

      // 11.75 Workload Sandboxing Container Nodes Synchronization & Rendering
      const currentRunning = runningWorkloadsRef.current || [];
      const currentRunningPids = new Set(currentRunning.map(w => w.pid));

      // Synchronize births
      for (const w of currentRunning) {
        if (!containerNodesRef.current[w.pid]) {
          const angle = (w.pid * 1.37) % (Math.PI * 2);
          const wx = 0.85 * Math.cos(angle);
          const wy = 0.3 + 0.15 * Math.sin(w.pid * 0.9);
          const wz = 0.85 * Math.sin(angle);
          const isGvisor = status?.seccomp_active ?? false;
          
          containerNodesRef.current[w.pid] = {
            pid: w.pid,
            policy: w.policy,
            x: wx,
            y: wy,
            z: wz,
            birthTime: time,
            deathTime: null,
            spawnFlash: 1.0,
            deathFlash: 0.0,
            isGvisor,
            particles: []
          };
        }
      }

      // Synchronize deaths
      for (const pidStr in containerNodesRef.current) {
        const pid = parseInt(pidStr);
        const node = containerNodesRef.current[pid];
        if (!currentRunningPids.has(pid) && node.deathTime === null) {
          node.deathTime = time;
          node.deathFlash = 1.0;
          
          // Spawn destruction particles
          const color = node.isGvisor ? '#10b981' : '#3b82f6';
          for (let i = 0; i < 15; i++) {
            node.particles.push({
              x: node.x,
              y: node.y,
              z: node.z,
              vx: (Math.random() - 0.5) * 0.02,
              vy: (Math.random() - 0.5) * 0.02,
              vz: (Math.random() - 0.5) * 0.02,
              life: 1.0,
              color
            });
          }
        }
      }

      // Update and render nodes
      for (const pidStr in containerNodesRef.current) {
        const pid = parseInt(pidStr);
        const node = containerNodesRef.current[pid];
        
        // Expiration check
        if (node.deathTime !== null && (time - node.deathTime > 1000)) {
          delete containerNodesRef.current[pid];
          continue;
        }

        // Decay flashes
        node.spawnFlash = Math.max(0.0, 1.0 - (time - node.birthTime) / 800);
        if (node.deathTime !== null) {
          node.deathFlash = Math.max(0.0, 1.0 - (time - node.deathTime) / 1000);
        }

        // Update particles
        node.particles.forEach(p => {
          p.x += p.vx;
          p.y += p.vy;
          p.z += p.vz;
          p.life -= 0.02;
        });
        node.particles = node.particles.filter(p => p.life > 0);

        // Project node to 2D
        const pt = project3D(node.x, node.y, node.z);
        if (isFinite(pt.x) && isFinite(pt.y)) {
          const depthOpacity = Math.max(0.2, Math.min(1.0, 1 - (pt.z + 1.2) / 2.4));
          
          // Draw particles
          node.particles.forEach(p => {
            const ppt = project3D(p.x, p.y, p.z);
            if (isFinite(ppt.x) && isFinite(ppt.y)) {
              ctx.fillStyle = p.color + Math.floor(p.life * depthOpacity * 255).toString(16).padStart(2, '0');
              ctx.beginPath();
              ctx.arc(ppt.x, ppt.y, 1.5 * ppt.scale, 0, Math.PI * 2);
              ctx.fill();
            }
          });

          const baseColor = node.isGvisor ? '#10b981' : '#3b82f6';
          let opacity = depthOpacity;
          if (node.deathTime !== null) {
            opacity *= node.deathFlash;
          }

          // Draw spawn flash glow
          if (node.spawnFlash > 0 && node.deathTime === null) {
            const pulseRadius = (20 + node.spawnFlash * 30) * pt.scale;
            const grad = ctx.createRadialGradient(pt.x, pt.y, 1, pt.x, pt.y, pulseRadius);
            grad.addColorStop(0, `rgba(16, 185, 129, ${node.spawnFlash * opacity * 0.8})`);
            grad.addColorStop(0.5, `rgba(16, 185, 129, ${node.spawnFlash * opacity * 0.2})`);
            grad.addColorStop(1, 'rgba(16, 185, 129, 0)');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, pulseRadius, 0, Math.PI * 2);
            ctx.fill();
          }

          // Draw death flash glow
          if (node.deathTime !== null && node.deathFlash > 0) {
            const pulseRadius = (12 + (1 - node.deathFlash) * 40) * pt.scale;
            const grad = ctx.createRadialGradient(pt.x, pt.y, 1, pt.x, pt.y, pulseRadius);
            grad.addColorStop(0, `rgba(239, 68, 68, ${node.deathFlash * opacity * 0.8})`);
            grad.addColorStop(0.5, `rgba(245, 158, 11, ${node.deathFlash * opacity * 0.3})`);
            grad.addColorStop(1, 'rgba(239, 68, 68, 0)');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, pulseRadius, 0, Math.PI * 2);
            ctx.fill();
          }

          // Vertical line from floor
          const floorPt = project3D(node.x, 0, node.z);
          if (isFinite(floorPt.x) && isFinite(floorPt.y)) {
            ctx.strokeStyle = node.isGvisor ? `rgba(16, 185, 129, ${opacity * 0.15})` : `rgba(59, 130, 246, ${opacity * 0.15})`;
            ctx.lineWidth = 1;
            ctx.setLineDash([2, 3]);
            ctx.beginPath();
            ctx.moveTo(pt.x, pt.y);
            ctx.lineTo(floorPt.x, floorPt.y);
            ctx.stroke();
            ctx.setLineDash([]);
          }

          // Draw shape
          const size = 9 * pt.scale;
          ctx.strokeStyle = baseColor + Math.floor(opacity * 255).toString(16).padStart(2, '0');
          ctx.lineWidth = 1.5;

          if (node.isGvisor) {
            ctx.strokeRect(pt.x - size/2, pt.y - size/2, size, size);
            ctx.fillStyle = `rgba(16, 185, 129, ${opacity * 0.15})`;
            ctx.fillRect(pt.x - size/2, pt.y - size/2, size, size);
            ctx.strokeStyle = `rgba(255, 255, 255, ${opacity * 0.25})`;
            ctx.strokeRect(pt.x - size/2 - 2, pt.y - size/2 - 2, size + 4, size + 4);
          } else {
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, size * 0.6, 0, Math.PI * 2);
            ctx.stroke();
            ctx.strokeStyle = `rgba(59, 130, 246, ${opacity * 0.4})`;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, size, 0, Math.PI * 2);
            ctx.stroke();
            ctx.fillStyle = `rgba(59, 130, 246, ${opacity * 0.1})`;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, size * 0.6, 0, Math.PI * 2);
            ctx.fill();
          }

          // Label
          ctx.fillStyle = `rgba(243, 244, 246, ${opacity})`;
          ctx.font = '7.5px "Share Tech Mono"';
          const label = node.isGvisor ? `gVisor (PID ${node.pid})` : `Host Proc (PID ${node.pid})`;
          ctx.fillText(label, pt.x + size/2 + 6, pt.y + 2);
          
          ctx.fillStyle = node.isGvisor ? `rgba(16, 185, 129, ${opacity * 0.8})` : `rgba(59, 130, 246, ${opacity * 0.8})`;
          ctx.font = '6.5px "Share Tech Mono"';
          ctx.fillText(`POLICY: ${node.policy.toUpperCase()}`, pt.x + size/2 + 6, pt.y + 9);
        }
      }

      // 12. Draw live digital matrix overlays (top-left metadata)
      ctx.fillStyle = 'rgba(6, 182, 212, 0.4)';
      ctx.font = '8px "Share Tech Mono"';
      ctx.fillText(`SHD_DIM: 64D | ALIGN_TOL: 0.005`, 18, 26);
      ctx.fillText(`SYS_SEED: 0x${(lastProjection?.similarity || 0.4242).toString(16).substring(2, 8).toUpperCase()}`, 18, 38);
      
      const statusText = status?.ready ? "SYS_OK // ALIGNED" : (status?.sealed ? "SYS_SEALED" : "SYS_WAIT_INIT");
      ctx.fillStyle = status?.ready ? 'rgba(16, 185, 129, 0.6)' : 'rgba(239, 68, 68, 0.6)';
      ctx.fillText(`STATUS: ${statusText}`, 18, 50);

      // Draw hex stream code rain on the right side of the Canvas
      ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
      ctx.font = '8px "Share Tech Mono"';
      for (let i = 0; i < 8; i++) {
        const streamY = ((time * 0.05 + i * 50) % (height - 40)) + 20;
        const randomHex = Math.floor(Math.sin(Math.floor(time / 150) + i) * 65535).toString(16).toUpperCase();
        ctx.fillText(`0x${randomHex.padStart(4, '0')}`, width - 60, streamY);
      }

      animationFrameRef.current = requestAnimationFrame(render);
    };

    animationFrameRef.current = requestAnimationFrame(render);
    return () => {
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
    };
  }, [lastProjection, status, sproutedExperts, chatMessages, anchorData]);

  // Handle status indicators
  const isOnline = status?.signer_online;
  const isReady = status?.ready;
  const isSealed = status?.sealed;

  return (
    <div className="app-container">
      <style>{`
        @keyframes flashPulse {
          0% { background-color: rgba(16, 185, 129, 0.03); }
          50% { background-color: rgba(16, 185, 129, 0.15); }
          100% { background-color: rgba(16, 185, 129, 0.03); }
        }
        .workload-item.running {
          animation: flashPulse 1.5s infinite ease-in-out;
        }
      `}</style>
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

        {/* Chain Widget Section */}
        <div className="sidebar-section">
          <label>Consenso AppChain</label>
          <div className="hud-panel" style={{ padding: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
              <span style={{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: (chainStatus && chainStatus.height > 0) ? '#10b981' : '#ef4444',
                boxShadow: (chainStatus && chainStatus.height > 0) ? '0 0 8px #10b981' : '0 0 8px #ef4444'
              }}></span>
              <span className="digital-font" style={{ fontSize: '0.8rem' }}>
                Catena: {(chainStatus && chainStatus.height > 0) ? 'CONNESSA' : 'DISCONNESSA'}
              </span>
            </div>
            {chainStatus && chainStatus.height > 0 && (
              <>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Altezza Blocco: <strong className="digital-font" style={{ color: 'var(--cyan)' }}>{chainStatus.height}</strong>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Validatori: <strong className="digital-font" style={{ color: 'var(--green)' }}>{chainStatus.validator_count} attivi</strong>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Ultimo Blocco: <strong className="digital-font" style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>{chainStatus.latest_block_time.split('T')[1]?.split('.')[0] || chainStatus.latest_block_time}</strong>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Shipper Widget Section */}
        <div className="sidebar-section">
          <label>Santuario Shipper</label>
          <div className="hud-panel" style={{ padding: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
              <span style={{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: shipperStatus?.enabled ? '#10b981' : '#6b7280',
                boxShadow: shipperStatus?.enabled ? '0 0 8px #10b981' : 'none'
              }}></span>
              <span className="digital-font" style={{ fontSize: '0.8rem' }}>
                Shipper: {shipperStatus?.enabled ? 'ATTIVO' : 'INATTIVO'}
              </span>
            </div>
            {shipperStatus?.enabled && (
              <>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Segmenti Totali: <strong className="digital-font" style={{ color: 'var(--cyan)' }}>{shipperStatus.total_segments}</strong>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Pendenti Push: <strong className="digital-font" style={{ color: shipperStatus.pending_segments > 0 ? '#ffd60a' : '#10b981' }}>{shipperStatus.pending_segments}</strong>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Ultimo Invio: <strong className="digital-font" style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>{shipperStatus.last_push_time.split('T')[1]?.split('.')[0] || shipperStatus.last_push_time}</strong>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Workload Monitor Widget Section */}
        <div className="sidebar-section">
          <label>Stato Workload Sandbox</label>
          <div className="hud-panel" style={{ padding: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span className="digital-font" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Attivi: <strong style={{ color: runningWorkloads.length > 0 ? '#10b981' : 'var(--text-secondary)' }}>{runningWorkloads.length}</strong>
              </span>
              {runningWorkloads.length > 0 && (
                <span className="pulse" style={{
                  display: 'inline-block',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: '#10b981',
                  boxShadow: '0 0 8px #10b981'
                }}></span>
              )}
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '150px', overflowY: 'auto' }}>
              {recentWorkloads.length === 0 ? (
                <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.3)', textAlign: 'center', padding: '0.5rem 0' }}>
                  Nessun workload recente
                </div>
              ) : (
                recentWorkloads.map((wl, i) => (
                  <div key={i} className={`workload-item ${wl.status}`} style={{
                    display: 'flex',
                    flexDirection: 'column',
                    padding: '0.4rem',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(255,255,255,0.03)',
                    borderLeft: `3px solid ${wl.status === 'running' ? '#10b981' : (wl.status === 'success' ? '#3b82f6' : '#ef4444')}`
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem' }}>
                      <span className="digital-font" style={{ fontWeight: 'bold', color: 'var(--text-primary)' }}>
                        PID {wl.pid} ({wl.policy})
                      </span>
                      <span className="digital-font" style={{
                        fontSize: '0.65rem',
                        padding: '1px 4px',
                        borderRadius: '2px',
                        backgroundColor: wl.status === 'running' ? 'rgba(16, 185, 129, 0.2)' : (wl.status === 'success' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(239, 68, 68, 0.2)'),
                        color: wl.status === 'running' ? '#10b981' : (wl.status === 'success' ? '#60a5fa' : '#ef4444')
                      }}>
                        {wl.status.toUpperCase()}
                      </span>
                    </div>
                    {wl.error && (
                      <div style={{ fontSize: '0.65rem', color: '#ef4444', marginTop: '2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {wl.error}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
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

                {sanctuaryStatus && (
                  <div className="sanctuary-status-bar digital-font" style={{
                    fontSize: '0.75rem',
                    color: sanctuaryStatus.status === 'committed' ? '#00e5ff' : sanctuaryStatus.status === 'failed' ? '#ff3b30' : '#ffd60a',
                    backgroundColor: 'rgba(0, 0, 0, 0.4)',
                    padding: '6px 10px',
                    borderRadius: '4px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    border: '1px solid ' + (sanctuaryStatus.status === 'committed' ? '#00e5ff33' : sanctuaryStatus.status === 'failed' ? '#ff3b3033' : '#ffd60a33')
                  }}>
                    <span>🔒 DATA SANCTUARY SPOOL (TX #{sanctuaryStatus.seq})</span>
                    <span>STATUS: {sanctuaryStatus.status.toUpperCase()}</span>
                  </div>
                )}

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
                  <canvas 
                    ref={canvasRef} 
                    className="latent-canvas" 
                    onMouseDown={handleMouseDown}
                    onMouseMove={handleMouseMove}
                    onMouseUp={handleMouseUpOrLeave}
                    onMouseLeave={handleMouseUpOrLeave}
                    onWheel={handleWheel}
                  />
                  
                  {/* Floating Simulation Toolbar */}
                  <div className="hud-sim-toolbar">
                    <span className="hud-sim-title digital-font">SIMULATORE:</span>
                    <button className="hud-sim-btn sprout" style={{ border: '1px solid #10b981', color: '#10b981' }} onClick={triggerSimulatedBenchmark} title="Avvia benchmark reale (se online) o simula container effimero">
                      <span>🚀</span> BENCHMARK
                    </button>
                    <button className="hud-sim-btn sprout" onClick={triggerSimulatedSprouting} title="Simula sprouting di un nuovo esperto per concetto OOD">
                      <span>🌱</span> SPROUT
                    </button>
                    <button className="hud-sim-btn threat" onClick={triggerSimulatedThreat} title="Simula anomalia semantica ad alto PRE messa in quarantena">
                      <span>🛡️</span> MINACCIA
                    </button>
                    <button className="hud-sim-btn consolidate" onClick={triggerSimulatedConsolidation} title="Simula consolidamento da memoria a breve a lungo termine">
                      <span>⚡</span> CONSOLIDA
                    </button>
                    <button className="hud-sim-btn reset" onClick={resetCamera} title="Resetta zoom e angolazione della telecamera 3D">
                      <span>🔄</span> RESET CAM
                    </button>
                  </div>
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

                {/* Bitcoin L1 Anchor Status Widget */}
                <div className="hud-panel" style={{ marginTop: '1rem' }}>
                  <h3 className="digital-font glow-amber" style={{ margin: '0 0 1rem 0', fontSize: '0.9rem', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>₿</span> Bitcoin L1 Anchor Status
                  </h3>
                  
                  {anchorData && anchorData.latest_anchor ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                        <span className="pulse" style={{
                          display: 'inline-block',
                          width: '8px',
                          height: '8px',
                          borderRadius: '50%',
                          backgroundColor: '#f59e0b',
                          boxShadow: '0 0 8px #f59e0b'
                        }}></span>
                        <span className="digital-font glow-amber" style={{ fontSize: '0.8rem', fontWeight: 'bold' }}>
                          STATO: ANCORATO
                        </span>
                      </div>
                      
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '0.4rem 0.2rem', fontSize: '0.8rem' }}>
                        <div style={{ color: 'var(--text-secondary)' }}>Altezza Cosmos:</div>
                        <div className="digital-font" style={{ color: 'var(--cyan)', fontWeight: 'bold' }}>
                          {anchorData.latest_anchor.block_height}
                        </div>
                        
                        <div style={{ color: 'var(--text-secondary)' }}>Hash Cosmos:</div>
                        <div className="digital-font" style={{ color: 'var(--text-primary)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={anchorData.latest_anchor.block_hash}>
                          {anchorData.latest_anchor.block_hash.substring(0, 10)}...{anchorData.latest_anchor.block_hash.substring(anchorData.latest_anchor.block_hash.length - 6)}
                        </div>

                        <div style={{ color: 'var(--text-secondary)' }}>BTC TX (OP_RETURN):</div>
                        <div className="digital-font" style={{ color: '#f59e0b', fontWeight: 'bold', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={anchorData.latest_anchor.btc_tx_hash}>
                          <a 
                            href={`https://mempool.space/tx/${anchorData.latest_anchor.btc_tx_hash}`} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            style={{ color: '#f59e0b', textDecoration: 'none' }}
                            className="glow-amber-hover"
                          >
                            {anchorData.latest_anchor.btc_tx_hash.substring(0, 10)}...{anchorData.latest_anchor.btc_tx_hash.substring(anchorData.latest_anchor.btc_tx_hash.length - 6)}
                          </a>
                        </div>

                        <div style={{ color: 'var(--text-secondary)' }}>Creatore/Signer:</div>
                        <div className="digital-font" style={{ color: 'var(--text-primary)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={anchorData.latest_anchor.creator}>
                          {anchorData.latest_anchor.creator.substring(0, 10)}...{anchorData.latest_anchor.creator.substring(anchorData.latest_anchor.creator.length - 6)}
                        </div>

                        <div style={{ color: 'var(--text-secondary)' }}>Evento:</div>
                        <div className="digital-font" style={{ color: 'var(--purple)', textTransform: 'uppercase' }}>
                          {anchorData.latest_anchor.event_name}
                        </div>

                        <div style={{ color: 'var(--text-secondary)' }}>Timestamp:</div>
                        <div className="digital-font" style={{ color: 'var(--text-primary)' }}>
                          {new Date(anchorData.latest_anchor.timestamp * 1000).toLocaleString('it-IT')}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                        <span style={{
                          display: 'inline-block',
                          width: '8px',
                          height: '8px',
                          borderRadius: '50%',
                          backgroundColor: '#6b7280'
                        }}></span>
                        <span className="digital-font" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          STATO: NON ANCORATO
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.3)', textAlign: 'center', padding: '0.5rem 0' }}>
                        In attesa della prima transazione OP_RETURN...
                      </div>
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
                    let recordObj: any = {};
                    try {
                      recordObj = JSON.parse(line.json);
                    } catch (e) {}

                    return (
                      <div key={idx} className="terminal-line">
                        <span className="terminal-timestamp">[{formatUtc(line.ts_utc)}]</span>
                        <span style={{ color: '#fff', fontWeight: 'bold' }}>
                          {(() => {
                            const record = line.record;
                            if (record.includes("| IPFS:")) {
                              const parts = record.split("| IPFS:");
                              const textPart = parts[0].toUpperCase();
                              const cidPart = parts[1].trim();
                              const gatewayUrl = `http://localhost:8080/ipfs/${cidPart}`;
                              return (
                                <span>
                                  {textPart} | <span style={{ color: '#f59e0b', fontWeight: 'bold' }}>IPFS: </span>
                                  <a 
                                    href={gatewayUrl} 
                                    target="_blank" 
                                    rel="noopener noreferrer" 
                                    style={{ 
                                      color: '#60a5fa', 
                                      textDecoration: 'underline', 
                                      cursor: 'pointer',
                                      fontFamily: 'monospace'
                                    }}
                                    title="Apri nel gateway IPFS"
                                  >
                                    {cidPart}
                                  </a>
                                </span>
                              );
                            }
                            if (record === "workload_start") {
                              return (
                                <span style={{ color: '#10b981' }}>
                                  ⚡ [WORKLOAD IGNITION] PID {recordObj.pid} launched under policy "{recordObj.policy}"
                                </span>
                              );
                            }
                            if (record === "workload_stop") {
                              const isSuccess = recordObj.status === "success" || recordObj.status === "killed";
                              return (
                                <span style={{ color: isSuccess ? '#60a5fa' : '#ef4444' }}>
                                  ⏹️ [WORKLOAD DESTRUCTION] PID {recordObj.pid} stopped with status "{recordObj.status}"
                                </span>
                              );
                            }
                            return <span>{record.toUpperCase()}</span>;
                          })()}
                        </span>
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
