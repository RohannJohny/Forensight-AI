import React, { useState } from "react";
import {
  GitBranch,
  ShieldCheck,
  ArrowRight,
  ExternalLink
} from "lucide-react";

export default function AttackPathView({ attackPathData, _activeCase, setCurrentTab }) {
  const [selectedStage, setSelectedStage] = useState(0);

  const stages = attackPathData?.stages || [];
  const currentStage = stages[selectedStage] || stages[0];

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
            <GitBranch size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Attack Path Reconstruction (MITRE ATT&CK)
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Sequential kill-chain progression bound directly to verified forensic evidence artifacts.
          </p>
        </div>

        <button className="btn btn-emerald" onClick={() => setCurrentTab("validation")}>
          <ShieldCheck size={14} />
          Examiner Validation Gate
        </button>
      </div>

      {/* Visual Kill-Chain Stepper Bar */}
      <div className="forensic-card" style={{ marginBottom: "20px", padding: "18px 20px" }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "8px"
        }}>
          {stages.length === 0 ? (
            <div style={{ textAlign: "center", padding: "30px 10px", color: "var(--text-muted)", width: "100%" }}>
              <GitBranch size={32} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
              <div style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-main)" }}>No MITRE Attack Stages Reconstructed</div>
              <p style={{ fontSize: "12.5px", marginTop: "4px" }}>
                Run AI correlation on active evidence to map chronological findings into the ATT&CK kill chain.
              </p>
            </div>
          ) : (
            stages.map((st, idx) => {
            const isSelected = selectedStage === idx;
            const isValidated = st.finding?.validation_status === "Accepted";

            return (
              <React.Fragment key={st.node_id || idx}>
                <div
                  onClick={() => setSelectedStage(idx)}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    cursor: "pointer",
                    flex: "1 1 120px",
                    maxWidth: "180px",
                    textAlign: "center",
                    padding: "8px 6px",
                    borderRadius: "var(--radius-sm)",
                    backgroundColor: isSelected ? "var(--primary-subtle)" : "transparent",
                    border: isSelected ? "1px solid var(--primary-border)" : "1px solid transparent",
                    transition: "all 0.15s ease"
                  }}
                >
                  <div style={{
                    width: "32px",
                    height: "32px",
                    borderRadius: "50%",
                    backgroundColor: isSelected ? "var(--primary)" : "var(--bg-card-subtle)",
                    border: `2px solid ${isSelected ? "var(--primary)" : "var(--border)"}`,
                    color: isSelected ? "#ffffff" : "var(--text-muted)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: "700",
                    fontSize: "13px",
                    fontFamily: "var(--font-mono)",
                    marginBottom: "6px"
                  }}>
                    {st.stage_order}
                  </div>

                  <div style={{
                    fontSize: "12.5px",
                    fontWeight: "600",
                    color: isSelected ? "var(--primary-text)" : "var(--text-main)"
                  }}>
                    {st.stage_name}
                  </div>

                  <div style={{
                    fontSize: "11px",
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                    marginTop: "2px"
                  }}>
                    {st.mitre_technique ? st.mitre_technique.split(":")[0] : ""}
                  </div>

                  <div style={{ marginTop: "4px" }}>
                    <span className={`badge-tag ${isValidated ? "badge-emerald" : "badge-amber"}`} style={{ fontSize: "9.5px", padding: "1px 5px" }}>
                      {isValidated ? "Validated" : "Pending"}
                    </span>
                  </div>
                </div>

                {idx < stages.length - 1 && (
                  <div style={{ color: "var(--border-strong)", display: "flex", alignItems: "center" }}>
                    <ArrowRight size={14} />
                  </div>
                )}
              </React.Fragment>
            );
          }))}
        </div>
      </div>

      {/* Deep Stage Inspector */}
      {currentStage && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "20px" }}>
          {/* Left: MITRE Technique & Finding Info */}
          <div className="forensic-card">
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
              <span className="badge-tag badge-cyan">
                Stage {currentStage.stage_order} of {stages.length}
              </span>
              <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)" }}>
                {currentStage.stage_name}
              </h3>
            </div>

            <div style={{
              backgroundColor: "var(--bg-card-subtle)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: "14px",
              marginBottom: "16px"
            }}>
              <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>
                MITRE ATT&CK Technique
              </div>
              <div style={{ fontSize: "13.5px", fontWeight: "700", color: "var(--primary-text)", fontFamily: "var(--font-mono)", marginTop: "3px" }}>
                {currentStage.mitre_technique}
              </div>
              <p style={{ fontSize: "13px", color: "var(--text-dim)", marginTop: "6px", lineHeight: "1.5" }}>
                {currentStage.description}
              </p>
            </div>

            {/* Correlated Finding Details */}
            {currentStage.finding && (
              <div>
                <div style={{ fontSize: "11.5px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600", marginBottom: "6px" }}>
                  Correlated Finding
                </div>
                <div style={{
                  backgroundColor: "var(--bg-card-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "14px"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <div style={{ fontSize: "13.5px", fontWeight: "700", color: "var(--text-main)" }}>
                      {currentStage.finding.title}
                    </div>
                    <span className={`badge-tag ${currentStage.finding.validation_status === "Accepted" ? "badge-emerald" : "badge-amber"}`}>
                      {currentStage.finding.validation_status}
                    </span>
                  </div>
                  <p style={{ fontSize: "12.5px", color: "var(--text-dim)", lineHeight: "1.5", marginBottom: "8px" }}>
                    {currentStage.finding.description}
                  </p>
                  <div style={{ fontSize: "11.5px", color: "var(--text-muted)", borderTop: "1px solid var(--border)", paddingTop: "6px" }}>
                    <strong>Examiner Notes:</strong> {currentStage.finding.notes || "None"}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right: Direct Evidence Citation Link */}
          <div className="forensic-card">
            <h4 style={{
              fontSize: "14.5px",
              fontWeight: "700",
              color: "var(--text-main)",
              marginBottom: "12px",
              display: "flex",
              alignItems: "center",
              gap: "8px"
            }}>
              <ExternalLink size={15} color="var(--primary)" />
              Supporting Digital Forensic Evidence Link
            </h4>

            {currentStage.evidence_link ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div style={{
                  backgroundColor: "var(--bg-card-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "12px 14px"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "5px" }}>
                    <span style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>NORMALIZED EVENT ID</span>
                    <span className="mono" style={{ fontSize: "11.5px", color: "var(--primary-text)" }}>
                      {currentStage.evidence_link.event_id}
                    </span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "5px" }}>
                    <span style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>TIMESTAMP (UTC)</span>
                    <span className="mono" style={{ fontSize: "11.5px", color: "var(--emerald-text)" }}>
                      {currentStage.evidence_link.timestamp}
                    </span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>SOURCE ARTIFACT</span>
                    <span style={{ fontSize: "11.5px", color: "var(--text-main)", fontWeight: "500" }}>
                      {currentStage.evidence_link.source}
                    </span>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", marginBottom: "5px" }}>
                    RAW EXECUTED ATTRIBUTES / COMMAND
                  </div>
                  <pre style={{
                    backgroundColor: "var(--bg-code)",
                    border: "1px solid var(--border)",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    fontSize: "11.5px",
                    color: "var(--text-main)",
                    fontFamily: "var(--font-mono)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    maxHeight: "180px",
                    overflowY: "auto"
                  }}>
                    {JSON.stringify(currentStage.evidence_link.details, null, 2)}
                  </pre>
                </div>

                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  fontSize: "11.5px",
                  color: "var(--text-muted)"
                }}>
                  <span>User: <strong style={{ color: "var(--text-dim)" }}>{currentStage.evidence_link.user}</strong></span>
                  <span>Host IP: <strong style={{ color: "var(--text-dim)" }}>{currentStage.evidence_link.host}</strong></span>
                </div>
              </div>
            ) : (
              <div style={{ color: "var(--text-muted)", fontSize: "13px", padding: "16px 0" }}>
                No direct single event bound to this stage.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
