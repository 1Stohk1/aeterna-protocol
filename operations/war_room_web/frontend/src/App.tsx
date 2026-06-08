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
  vector_3d?: [number, number, number];
  experts_3d?: Record<string, [number, number, number]>;
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
  const currentVectorRef = useRef<[number, number, number]>([0, 0, 0]);
  const targetVectorRef = useRef<[number, number, number]>([0, 0, 0]);
  const lockProgressRef = useRef<number>(0);


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
          const proj = data.projection;
          const x = proj.vector_3d?.[0] ?? proj.vector_2d?.[0] ?? 0;
          const y = proj.vector_3d?.[1] ?? proj.vector_2d?.[1] ?? 0;
          const z = proj.vector_3d?.[2] ?? (Math.sin(x * 3 + y * 2) * 0.4);
          targetVectorRef.current = [x, y, z];
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

    const render = (time: number) => {
      // Clear and size canvas to container
      const width = canvas.width = canvas.parentElement?.clientWidth || 500;
      const height = canvas.height = canvas.parentElement?.clientHeight || 400;
      
      ctx.fillStyle = '#030712';
      ctx.fillRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(width, height) * 0.40;

      // 3D Projection Math
      const project3D = (x: number, y: number, z: number) => {
        // Horizontal rotation over time (vertical axis)
        const rotY = time * 0.0004;
        const x1 = x * Math.cos(rotY) - z * Math.sin(rotY);
        const z1 = x * Math.sin(rotY) + z * Math.cos(rotY);

        // Vertical tilt (slowly oscillating slightly for organic motion)
        const tiltX = 0.45 + Math.sin(time * 0.00015) * 0.08;
        const y2 = y * Math.cos(tiltX) + z1 * Math.sin(tiltX);
        const z2 = -y * Math.sin(tiltX) + z1 * Math.cos(tiltX);


        // Perspective scaling (camera distance)
        const cameraDistance = 2.5;
        const scale = cameraDistance / (cameraDistance + z2);
        
        const sx = centerX + x1 * scale * radius;
        const sy = centerY - y2 * scale * radius;
        
        return { x: sx, y: sy, z: z2, scale };
      };

      // 1. Draw 3D Grid floor (concentric rings in X-Z plane)
      const ringColor = 'rgba(6, 182, 212, 0.06)';
      const ringColorDashed = 'rgba(6, 182, 212, 0.15)';
      
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

      // Vertical longitudinal/latitudinal outer rings (wireframe sphere envelope)
      const drawSphereWireframe = () => {
        // Y-Z hoop
        ctx.strokeStyle = 'rgba(168, 85, 247, 0.04)';
        ctx.beginPath();
        for (let j = 0; j <= 64; j++) {
          const theta = (j / 64) * Math.PI * 2;
          const pt = project3D(0, Math.cos(theta), Math.sin(theta));
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();

        // X-Y hoop
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.04)';
        ctx.beginPath();
        for (let j = 0; j <= 64; j++) {
          const theta = (j / 64) * Math.PI * 2;
          const pt = project3D(Math.cos(theta), Math.sin(theta), 0);
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();
      };
      drawSphereWireframe();

      // Concentric Orbiting Dials on the X-Z plane rotating in opposite directions in 3D
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

      // Outer purple ring (gyroscope style)
      drawXZDial(1.05, 0.3, 'rgba(168, 85, 247, 0.15)', [20, 40]);
      // Outer Counter-clockwise dial
      drawXZDial(0.8, -0.6, 'rgba(6, 182, 212, 0.12)', [4, 15]);
      // Inner Clockwise dial
      drawXZDial(0.4, 0.9, 'rgba(168, 85, 247, 0.12)', [2, 8]);

      // 2. Draw 3D coordinate axes
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

      // Outer rings corner brackets (flat HUD overlay)
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.3)';
      ctx.lineWidth = 1;
      const bracketSize = 15;
      ctx.beginPath();
      ctx.moveTo(10, 10 + bracketSize); ctx.lineTo(10, 10); ctx.lineTo(10 + bracketSize, 10);
      ctx.moveTo(width - 10, 10 + bracketSize); ctx.lineTo(width - 10, 10); ctx.lineTo(width - 10 - bracketSize, 10);
      ctx.moveTo(10, height - 10 - bracketSize); ctx.lineTo(10, height - 10); ctx.lineTo(10 + bracketSize, height - 10);
      ctx.moveTo(width - 10, height - 10 - bracketSize); ctx.lineTo(width - 10, height - 10); ctx.lineTo(width - 10 - bracketSize, height - 10);
      ctx.stroke();

      // 3. Define Expert Coordinates (matching backend 3D vectors or fallback)
      const experts3d: Record<string, { x: number; y: number; z: number; color: string; label: string }> = {
        'Generale': { 
          x: lastProjection?.experts_3d?.Generale?.[0] ?? 0.60, 
          y: lastProjection?.experts_3d?.Generale?.[1] ?? 0.40, 
          z: lastProjection?.experts_3d?.Generale?.[2] ?? 0.20, 
          color: '#10b981', 
          label: 'Centr. Generale (Ω)' 
        },
        'Oncologia': { 
          x: lastProjection?.experts_3d?.Oncologia?.[0] ?? -0.50, 
          y: lastProjection?.experts_3d?.Oncologia?.[1] ?? 0.70, 
          z: lastProjection?.experts_3d?.Oncologia?.[2] ?? -0.40, 
          color: '#ef4444', 
          label: 'Centr. Oncologia' 
        },
        'HP-Folding': { 
          x: lastProjection?.experts_3d?.['HP-Folding']?.[0] ?? 0.70, 
          y: lastProjection?.experts_3d?.['HP-Folding']?.[1] ?? -0.50, 
          z: lastProjection?.experts_3d?.['HP-Folding']?.[2] ?? 0.50, 
          color: '#a855f7', 
          label: 'Centr. HP-Folding' 
        }
      };

      // Draw expert centroids in 3D (sorted by depth Z for correct layering)
      const projectedExperts = Object.entries(experts3d).map(([name, exp]) => {
        const pt = project3D(exp.x, exp.y, exp.z);
        return { name, exp, pt };
      });
      
      // Sort so deeper ones (larger Z) are drawn first
      projectedExperts.sort((a, b) => b.pt.z - a.pt.z);

      projectedExperts.forEach(({ name, exp, pt }) => {
        // Opacity and size based on depth (from near to far)
        const depthOpacity = Math.max(0.2, Math.min(1.0, 1 - (pt.z + 1.2) / 2.4));
        
        // Outer glow circle
        ctx.fillStyle = `${exp.color}${Math.floor(depthOpacity * 12).toString(16).padStart(2, '0')}`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 14 * pt.scale, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = `${exp.color}${Math.floor(depthOpacity * 50).toString(16).padStart(2, '0')}`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 8 * pt.scale, 0, Math.PI * 2);
        ctx.stroke();

        // Inner solid dot
        ctx.fillStyle = exp.color;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 3.5 * pt.scale, 0, Math.PI * 2);
        ctx.fill();

        // Label facing the screen
        ctx.fillStyle = `rgba(243, 244, 246, ${0.25 + depthOpacity * 0.4})`;
        ctx.font = `${Math.max(6, Math.floor(9 * pt.scale))}px "Share Tech Mono"`;
        ctx.fillText(exp.label, pt.x + 10 * pt.scale, pt.y + 3);
      });

      // 4. Smooth Vector Interpolation
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

      // Increment/decrement target lock progress
      if (hasActiveProjection) {
        if (lockProgressRef.current < 1) {
          lockProgressRef.current = Math.min(1, lockProgressRef.current + 0.04);
        }
      } else {
        lockProgressRef.current = 0;
      }

      if (hasActiveProjection) {
        const opt = project3D(0, 0, 0);
        // Draw path line from center (0,0,0) to current v_omega in 3D
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

        // Draw coordinate floor projection line (X-Z plane drop line)
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
          
          // Floor point marker
          ctx.fillStyle = 'rgba(6, 182, 212, 0.25)';
          ctx.beginPath();
          ctx.arc(floorPt.x, floorPt.y, 2, 0, Math.PI * 2);
          ctx.fill();
        }

        // Draw routing alignment line from v_omega to nearest expert centroid in 3D
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

        // Draw pulsating projection vector
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


        // Target Clamping Lock Brackets (Iron Man Style sweep in and lock)
        const bracketOffset = (1 - lockProgressRef.current) * 25 + 10;
        const bSize = 6;
        ctx.strokeStyle = `rgba(6, 182, 212, ${0.4 + lockProgressRef.current * 0.5})`;
        ctx.lineWidth = 1.5;
        
        // Top-Left
        ctx.beginPath();
        ctx.moveTo(vpt.x - bracketOffset, vpt.y - bracketOffset + bSize);
        ctx.lineTo(vpt.x - bracketOffset, vpt.y - bracketOffset);
        ctx.lineTo(vpt.x - bracketOffset + bSize, vpt.y - bracketOffset);
        ctx.stroke();

        // Top-Right
        ctx.beginPath();
        ctx.moveTo(vpt.x + bracketOffset, vpt.y - bracketOffset + bSize);
        ctx.lineTo(vpt.x + bracketOffset, vpt.y - bracketOffset);
        ctx.lineTo(vpt.x + bracketOffset - bSize, vpt.y - bracketOffset);
        ctx.stroke();

        // Bottom-Left
        ctx.beginPath();
        ctx.moveTo(vpt.x - bracketOffset, vpt.y + bracketOffset - bSize);
        ctx.lineTo(vpt.x - bracketOffset, vpt.y + bracketOffset);
        ctx.lineTo(vpt.x - bracketOffset + bSize, vpt.y + bracketOffset);
        ctx.stroke();

        // Bottom-Right
        ctx.beginPath();
        ctx.moveTo(vpt.x + bracketOffset, vpt.y + bracketOffset - bSize);
        ctx.lineTo(vpt.x + bracketOffset, vpt.y + bracketOffset);
        ctx.lineTo(vpt.x + bracketOffset - bSize, vpt.y + bracketOffset);
        ctx.stroke();

        // Vector labels
        ctx.fillStyle = '#f3f4f6';
        ctx.font = '10px "Share Tech Mono"';
        ctx.fillText(`Vector Omega (v_ω)`, vpt.x + 12, vpt.y - 12);
        ctx.fillStyle = 'rgba(6, 182, 212, 0.8)';
        ctx.fillText(`[X: ${cvx.toFixed(3)}, Y: ${cvy.toFixed(3)}, Z: ${cvz.toFixed(3)}]`, vpt.x + 12, vpt.y - 2);
      } else {
        // Draw hovering idle scanning vector in 3D
        const idleX = Math.sin(time * 0.001) * 0.3;
        const idleY = Math.cos(time * 0.0008) * 0.3;
        const idleZ = Math.sin(time * 0.0012) * 0.2;
        targetVectorRef.current = [idleX, idleY, idleZ];

        const pulse = (Math.sin(time * 0.005) * 2 + 6) * vpt.scale;
        ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
        ctx.beginPath();
        ctx.arc(vpt.x, vpt.y, pulse, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = 'rgba(6, 182, 212, 0.4)';
        ctx.beginPath();
        ctx.arc(vpt.x, vpt.y, 2.5 * vpt.scale, 0, Math.PI * 2);
        ctx.fill();

        // Center coordinate label
        ctx.fillStyle = 'rgba(6, 182, 212, 0.3)';
        ctx.font = '9px "Share Tech Mono"';
        ctx.fillText("Allineatore Rosetta Attivo (Scan)", vpt.x + 8, vpt.y - 4);
      }

      // 5. Draw live digital matrix overlays (top-left metadata)
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
