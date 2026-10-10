import {
  FolderCheck,
  HardDrive,
  Clock,
  AlertTriangle,
  ShieldCheck,
  FileLock2,
  Activity,
  Bot,
  Plus,
  ArrowRight,
  ShieldAlert,
  GitFork,
  Layers,
  FileCode
} from "lucide-react";

export default function DashboardView({ stats, activeCase, attackPathData, _cases, setCurrentTab }) {
  const killChainStages = attackPathData?.stages && attackPathData.stages.length > 0
    ? attackPathData.stages.map(st => ({
        name: st.stage_name,
        technique: st.mitre_technique,
        order: st.stage_order,
        validated: st.finding?.validation_status === "Accepted"
      }))
    : [
        { order: 1, name: "Initial Access", technique: "T1566: Spearphishing Attachment", validated: true },
        { order: 2, name: "Execution", technique: "T1059: PowerShell Subprocess", validated: true },
        { order: 3, name: "Persistence", technique: "T1547: Registry Run Key", validated: true },
        { order: 4, name: "Privilege Escalation", technique: "T1003: LSASS Memory Injection", validated: true },
        { order: 5, name: "Lateral Movement", technique: "T1021: SMB Admin$ Access", validated: true },
        { order: 6, name: "Exfiltration", technique: "T1048: Encrypted Outbound C2", validated: true },
      ];

  return (
    <div style={{ padding: "24px 28px", maxWidth: "1400px", margin: "0 auto", width: "100%" }}>
      {/* Welcome & Case Banner */}
      <div className="forensic-card" style={{
        marginBottom: "20px",
        padding: "22px 24px",
        display: "flex",
        flexWrap: "wrap",
        justifyContent: "space-between",
        alignItems: "flex-start",
        gap: "16px"
      }}>
        <div style={{ flex: "1 1 500px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
            <span className="badge-tag badge-cyan">
              Active Case: {activeCase?.case_number || "FS-2026-001"}
            </span>
            <span className="badge-tag badge-rose">
              <ShieldAlert size={12} />
              {activeCase?.status || "Under Investigation"}
            </span>
          </div>

          <h1 style={{
            fontSize: "21px",
            fontWeight: "700",
            color: "var(--text-main)",
            marginBottom: "6px"
          }}>
            {activeCase?.case_name || "Operation Blackout: APT Spearphishing"}
          </h1>

          <p style={{
            color: "var(--text-dim)",
            fontSize: "13px",
            lineHeight: "1.5",
            maxWidth: "850px"
          }}>
            {activeCase?.description || "Investigating targeted intrusion, payload execution, privilege escalation, and lateral movement artifacts."}
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <button className="btn btn-primary" onClick={() => setCurrentTab("evidence_upload")}>
            <Plus size={14} />
            Acquire Evidence
          </button>
          <button className="btn btn-secondary" onClick={() => setCurrentTab("cases")}>
            <FolderCheck size={14} />
            Manage Cases
          </button>
          <button className="btn btn-secondary" onClick={() => setCurrentTab("ai_assistant")}>
            <Bot size={14} color="var(--primary)" />
            AI Assistant
          </button>
        </div>
      </div>

      {/* 5 Primary Telemetry Widgets */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
        gap: "14px",
        marginBottom: "20px"
      }}>
        <div className="stat-widget" onClick={() => setCurrentTab("evidence")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Evidence Containers</div>
            <div className="stat-value" style={{ color: "var(--primary-text)" }}>
              {stats ? stats.evidence_count : "—"}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
              E01, RAW, EVTX, PCAP
            </div>
          </div>
          <HardDrive size={26} color="var(--primary)" />
        </div>

        <div className="stat-widget" onClick={() => setCurrentTab("timeline")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Normalized Events</div>
            <div className="stat-value" style={{ color: "var(--cyan-text)" }}>
              {stats ? stats.event_count : "—"}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
              Common Event Model
            </div>
          </div>
          <Clock size={26} color="var(--cyan)" />
        </div>

        <div className="stat-widget" onClick={() => setCurrentTab("anomaly_detection")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Flagged Anomalies</div>
            <div className="stat-value" style={{ color: "var(--rose-text)" }}>
              {stats ? stats.anomalous_events_count : "—"}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
              Score &ge; 0.70 Threshold
            </div>
          </div>
          <AlertTriangle size={26} color="var(--rose)" />
        </div>

        <div className="stat-widget" onClick={() => setCurrentTab("validation")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Validated Findings</div>
            <div className="stat-value" style={{ color: "var(--emerald-text)" }}>
              {stats ? `${stats.validated_findings} / ${stats.total_findings}` : "—"}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
              Examiner Confirmed
            </div>
          </div>
          <ShieldCheck size={26} color="var(--emerald)" />
        </div>

        <div className="stat-widget" onClick={() => setCurrentTab("reports")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Vault Dossiers</div>
            <div className="stat-value" style={{ color: "var(--purple-text)" }}>
              {stats ? stats.finalized_reports : "—"}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
              AES-256-GCM Vault
            </div>
          </div>
          <FileLock2 size={26} color="var(--purple)" />
        </div>
      </div>

      {/* MITRE ATT&CK Intrusion Progression Summary */}
      <div className="forensic-card" style={{ marginBottom: "20px" }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "14px",
          flexWrap: "wrap",
          gap: "8px"
        }}>
          <div>
            <h3 style={{ fontSize: "15.5px", fontWeight: "700", color: "var(--text-main)" }}>
              MITRE ATT&CK Reconstructed Attack Path
            </h3>
            <p style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>
              Sequential kill-chain progression grounded directly in validated host and network evidence
            </p>
          </div>
          <button className="btn btn-secondary" style={{ fontSize: "12px" }} onClick={() => setCurrentTab("attack_path")}>
            Interactive Graph <ArrowRight size={13} />
          </button>
        </div>

        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "10px"
        }}>
          {killChainStages.map((stage) => (
            <div
              key={stage.order}
              onClick={() => setCurrentTab("attack_path")}
              style={{
                backgroundColor: "var(--bg-card-subtle)",
                border: "1px solid var(--border)",
                borderTop: "3px solid var(--primary)",
                borderRadius: "var(--radius-sm)",
                padding: "12px",
                cursor: "pointer"
              }}
            >
              <div style={{ fontSize: "10.5px", color: "var(--text-muted)", fontWeight: "600", textTransform: "uppercase" }}>
                Stage {stage.order}
              </div>
              <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", margin: "3px 0" }}>
                {stage.name}
              </div>
              <div style={{ fontSize: "11px", color: "var(--primary-text)", fontFamily: "var(--font-mono)" }}>
                {stage.technique}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Two Column Layout: Processing Status & Quick Workflows */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "18px" }}>
        {/* Processing Jobs & Pipeline Status */}
        <div className="forensic-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
            <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", display: "flex", alignItems: "center", gap: "7px" }}>
              <Activity size={16} color="var(--primary)" />
              Forensic Processing Engines Status
            </h3>
            <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "3px 8px" }} onClick={() => setCurrentTab("processing")}>
              View Details <ArrowRight size={12} />
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {[
              { tool: "Autopsy / TSK", task: "NTFS $MFT & Deleted Carving", status: "COMPLETED", color: "var(--emerald-text)" },
              { tool: "Volatility 3", task: "RAM Process Trees & Injected Malfind", status: "COMPLETED", color: "var(--emerald-text)" },
              { tool: "Zeek Network Parser", task: "PCAP Stream Reassembly & Exfiltration", status: "COMPLETED", color: "var(--emerald-text)" },
              { tool: "RegRipper 3.0", task: "Registry Autoruns & UserAssist Hives", status: "COMPLETED", color: "var(--emerald-text)" },
              { tool: "Heuristic Anomaly Engine", task: "CEM Normalization & Anomaly Scoring", status: "ACTIVE", color: "var(--primary-text)" }
            ].map((p, idx) => (
              <div
                key={idx}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "8px 12px",
                  backgroundColor: "var(--bg-card-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)"
                }}
              >
                <div>
                  <div style={{ fontSize: "12.5px", fontWeight: "600", color: "var(--text-main)" }}>
                    {p.tool}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                    {p.task}
                  </div>
                </div>
                <span className="badge-tag badge-emerald" style={{ fontSize: "10px" }}>
                  {p.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Investigative Navigation */}
        <div className="forensic-card">
          <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
            Investigative Lifecycle Shortcuts
          </h3>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
            <button
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "12px", padding: "10px" }}
              onClick={() => setCurrentTab("evidence_upload")}
            >
              <HardDrive size={15} color="var(--primary)" /> Evidence Ingest
            </button>
            <button
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "12px", padding: "10px" }}
              onClick={() => setCurrentTab("artifacts")}
            >
              <FileCode size={15} color="var(--cyan)" /> Artifact Explorer
            </button>
            <button
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "12px", padding: "10px" }}
              onClick={() => setCurrentTab("normalization")}
            >
              <Layers size={15} color="var(--purple)" /> Event Normalization
            </button>
            <button
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "12px", padding: "10px" }}
              onClick={() => setCurrentTab("correlation_graph")}
            >
              <GitFork size={15} color="var(--indigo)" /> Correlation Graph
            </button>
            <button
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "12px", padding: "10px" }}
              onClick={() => setCurrentTab("anomaly_detection")}
            >
              <AlertTriangle size={15} color="var(--rose)" /> Anomaly Scoring
            </button>
            <button
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "12px", padding: "10px" }}
              onClick={() => setCurrentTab("validation")}
            >
              <ShieldCheck size={15} color="var(--emerald)" /> Validation Gate
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
