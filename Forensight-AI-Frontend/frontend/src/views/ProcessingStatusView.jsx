import React, { useState } from "react";
import {
  Cpu,
  Layers,
  CheckCircle2,
  Clock,
  Sparkles,
  ArrowRight,
  Database,
  ShieldCheck,
  FileCode,
  Terminal,
  Activity,
  RotateCw
} from "lucide-react";
import { runCorrelation } from "../services/api";

export default function ProcessingStatusView({ activeCase, _stats, onRefresh, onNavigate }) {
  const [runningJob, setRunningJob] = useState(false);

  const pipelineStages = [
    { id: 1, title: "Evidence Validation", tool: "Cryptographic Engine", desc: "SHA-256 bit-stream integrity & chain of custody check", status: "COMPLETED", progress: 100, targetTab: "evidence" },
    { id: 2, title: "Artifact Extraction", tool: "TSK, Volatility, RegRipper, Zeek", desc: "Carving NTFS $MFT, memory process trees, registry hives, PCAP streams", status: "COMPLETED", progress: 100, targetTab: "artifacts" },
    { id: 3, title: "Event Normalization", tool: "Common Event Model (CEM)", desc: "Standardizing disparate logs, timestamps (UTC), and execution telemetry", status: "COMPLETED", progress: 100, targetTab: "normalization" },
    { id: 4, title: "Forensic Correlation", tool: "Correlation Engine", desc: "Multi-source temporal sequencing & cross-system host clustering", status: "COMPLETED", progress: 100, targetTab: "correlation_graph" },
    { id: 5, title: "AI Anomaly Analysis", tool: "Behavioral Heuristics & ML", desc: "Scoring obfuscated PowerShell, LSASS access, and C2 beacons", status: "COMPLETED", progress: 100, targetTab: "anomaly_detection" },
    { id: 6, title: "Examiner Validation", tool: "Human-in-the-Loop Gate", desc: "Lead investigator confirms or rejects candidate AI findings", status: "ACTIVE", progress: 85, targetTab: "validation" },
    { id: 7, title: "Cryptographic Vault", tool: "Two-Key AES-256-GCM Engine", desc: "Dossier compilation, REK wrapping, and legal attestation seal", status: "READY", progress: 100, targetTab: "reports" }
  ];

  const forensicTools = [
    {
      name: "The Sleuth Kit (TSK) / Autopsy",
      category: "File System & Disk Forensic",
      coverage: "NTFS $MFT, USN Journal, Master File Table, Deleted Record Recovery",
      status: "ONLINE",
      version: "v4.19.3",
      artifactsProcessed: "1,420 Records"
    },
    {
      name: "Volatility 3 Engine",
      category: "Volatile RAM Analysis",
      coverage: "Process Tree (windows.pstree), Malfind Code Injection, Hidden DLLs",
      status: "ONLINE",
      version: "v2.5.0",
      artifactsProcessed: "18 Injected PIDs Scanned"
    },
    {
      name: "Plaso (log2timeline)",
      category: "Super-Timeline Engine",
      coverage: "System events, Prefetch, Shellbags, USB insertion timestamps",
      status: "ONLINE",
      version: "v20231124",
      artifactsProcessed: "Unified Time Stream"
    },
    {
      name: "YARA Engine",
      category: "Heuristic Signature Matching",
      coverage: "Weaponized Office macros, encoded PowerShell stagers, Mimikatz rules",
      status: "ONLINE",
      version: "v4.3.2",
      artifactsProcessed: "4 Rule Sets Matched"
    },
    {
      name: "Zeek (Bro) Network Parser",
      category: "Protocol & Stream Reconstruction",
      coverage: "PCAP protocol dissection, C2 session reassembly, 84.5 MB exfiltration",
      status: "ONLINE",
      version: "v5.2.0",
      artifactsProcessed: "830 Flows Analyzed"
    },
    {
      name: "RegRipper 3.0",
      category: "Windows Hive Extraction",
      coverage: "Run/RunOnce persistence keys, UserAssist execution counts, SAM accounts",
      status: "ONLINE",
      version: "v3.0",
      artifactsProcessed: "6 Hives Parsed"
    }
  ];

  const handleRunPipeline = async () => {
    if (!activeCase) return;
    setRunningJob(true);
    try {
      const res = await runCorrelation(activeCase.case_id);
      alert(`Pipeline execution complete! Scanned ${res.events_scanned} events, updated ${res.anomalous_events_flagged} behavioral anomalies.`);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Pipeline run failed: " + err.message);
    } finally {
      setRunningJob(false);
    }
  };

  return (
    <div style={{ padding: "24px 28px", maxWidth: "1400px", margin: "0 auto", width: "100%" }}>
      {/* Header */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "20px",
        flexWrap: "wrap",
        gap: "12px"
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <Activity size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Forensic Processing Status & Tool Orchestration
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            End-to-end investigation pipeline status, forensic parsing engines, and correlation telemetry.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          <button
            className="btn btn-primary"
            onClick={handleRunPipeline}
            disabled={runningJob}
          >
            <RotateCw size={14} className={runningJob ? "spin" : ""} />
            {runningJob ? "Executing Correlation Engine..." : "Run Pipeline Correlation"}
          </button>
        </div>
      </div>

      {/* 7-Stage Pipeline Progression Bar */}
      <div className="forensic-card" style={{ marginBottom: "24px" }}>
        <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", marginBottom: "16px" }}>
          7-Stage Investigation Pipeline Execution
        </h3>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {pipelineStages.map((stage) => {
            const isCompleted = stage.status === "COMPLETED";
            const isActive = stage.status === "ACTIVE";

            return (
              <div
                key={stage.id}
                onClick={() => onNavigate && stage.targetTab && onNavigate(stage.targetTab)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "12px 16px",
                  borderRadius: "var(--radius-sm)",
                  backgroundColor: "var(--bg-card-subtle)",
                  border: `1px solid ${isActive ? "var(--primary-border)" : "var(--border)"}`,
                  borderLeft: `4px solid ${isCompleted ? "var(--emerald)" : isActive ? "var(--primary)" : "var(--border-strong)"}`,
                  flexWrap: "wrap",
                  gap: "10px",
                  cursor: "pointer",
                  transition: "all 0.15s ease"
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <div style={{
                    width: "28px",
                    height: "28px",
                    borderRadius: "50%",
                    backgroundColor: isCompleted ? "var(--emerald-subtle)" : isActive ? "var(--primary-subtle)" : "var(--bg-card)",
                    color: isCompleted ? "var(--emerald-text)" : isActive ? "var(--primary-text)" : "var(--text-muted)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: "700",
                    fontSize: "12px",
                    fontFamily: "var(--font-mono)"
                  }}>
                    {stage.id}
                  </div>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "13.5px", fontWeight: "700", color: "var(--text-main)" }}>
                        {stage.title}
                      </span>
                      <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        [{stage.tool}]
                      </span>
                    </div>
                    <div style={{ fontSize: "11.5px", color: "var(--text-dim)", marginTop: "2px" }}>
                      {stage.desc}
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <span className={`badge-tag ${isCompleted ? "badge-emerald" : isActive ? "badge-cyan" : "badge-amber"}`} style={{ fontSize: "10.5px" }}>
                    {stage.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Forensic Tool Orchestration Grid */}
      <div className="forensic-card">
        <h3 style={{
          fontSize: "15px",
          fontWeight: "700",
          color: "var(--text-main)",
          marginBottom: "14px",
          display: "flex",
          alignItems: "center",
          gap: "8px"
        }}>
          <Cpu size={17} color="var(--primary)" />
          Orchestrated Forensic Extraction Tools
        </h3>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "12px" }}>
          {forensicTools.map((tool) => (
            <div
              key={tool.name}
              style={{
                backgroundColor: "var(--bg-card-subtle)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "14px",
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between"
              }}
            >
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                  <div>
                    <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)" }}>
                      {tool.name}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                      {tool.category} • {tool.version}
                    </div>
                  </div>
                  <span className="badge-tag badge-emerald" style={{ fontSize: "10px" }}>
                    {tool.status}
                  </span>
                </div>

                <p style={{ fontSize: "12px", color: "var(--text-dim)", lineHeight: "1.45", margin: "6px 0" }}>
                  {tool.coverage}
                </p>
              </div>

              <div style={{
                borderTop: "1px solid var(--border-subtle)",
                paddingTop: "8px",
                marginTop: "6px",
                display: "flex",
                justifyContent: "space-between",
                fontSize: "11px",
                color: "var(--text-muted)"
              }}>
                <span>Telemetry Yield:</span>
                <span className="mono" style={{ color: "var(--primary-text)", fontWeight: "600" }}>{tool.artifactsProcessed}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
