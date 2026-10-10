import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  CheckCircle2,
  Clock,
  ArrowRight,
  Activity,
  RotateCw,
  AlertTriangle,
  Play,
  HardDrive,
  Server,
  Terminal
} from "lucide-react";
import {
  processEvidence,
  getEvidenceStatus,
  getForensicTools,
  runCorrelation
} from "../services/api";

export default function ProcessingStatusView({
  activeCase,
  evidenceList = [],
  onRefresh,
  onNavigate
}) {
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(() => {
    if (evidenceList && evidenceList.length > 0) {
      // Prioritize pending/in-progress evidence, or first
      const pending = evidenceList.find((e) => e.processing_status !== "COMPLETED");
      return pending ? pending.evidence_id : evidenceList[0].evidence_id;
    }
    return null;
  });

  const [currentStatus, setCurrentStatus] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [pollError, setPollError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  // M1 Tool Status State
  const [tools, setTools] = useState([]);
  const [loadingTools, setLoadingTools] = useState(true);

  // Correlation job state
  const [runningCorrelation, setRunningCorrelation] = useState(false);

  const pollIntervalRef = useRef(null);

  // Keep selectedEvidenceId valid when evidenceList updates
  useEffect(() => {
    if (!selectedEvidenceId && evidenceList && evidenceList.length > 0) {
      setSelectedEvidenceId(evidenceList[0].evidence_id);
    }
  }, [evidenceList, selectedEvidenceId]);

  const activeEvidence = evidenceList.find((e) => e.evidence_id === selectedEvidenceId) || null;

  // Stop polling helper
  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    setIsPolling(false);
  }, []);

  // Poll evidence status from backend (Task 3)
  const pollStatus = useCallback(async (evidenceId) => {
    if (!evidenceId) return;
    try {
      const statusData = await getEvidenceStatus(evidenceId);
      setCurrentStatus(statusData);
      setLastUpdated(new Date().toLocaleTimeString());
      setPollError(null);

      const st = statusData.processing_status?.toUpperCase();
      if (st === "COMPLETED" || st === "FAILED") {
        stopPolling();
        setIsProcessing(false);
        if (onRefresh) onRefresh();
      }
    } catch (err) {
      console.warn("Status polling error:", err);
      setPollError(err.message);
    }
  }, [onRefresh, stopPolling]);

  // Start polling mechanism
  const startPolling = useCallback((evidenceId) => {
    stopPolling();
    setIsPolling(true);
    pollStatus(evidenceId);
    pollIntervalRef.current = setInterval(() => {
      pollStatus(evidenceId);
    }, 2500);
  }, [pollStatus, stopPolling]);

  // Clean up polling timer on unmount
  useEffect(() => {
    return () => {
      stopPolling();
    };
  }, [stopPolling]);

  // Sync initial status when selected evidence changes
  useEffect(() => {
    if (activeEvidence) {
      setCurrentStatus({
        evidence_id: activeEvidence.evidence_id,
        case_id: activeEvidence.case_id,
        source_name: activeEvidence.source_name,
        processing_status: activeEvidence.processing_status || "PENDING",
        processing_error: activeEvidence.processing_error || null,
        ingested_at: activeEvidence.ingested_at
      });

      const st = (activeEvidence.processing_status || "").toUpperCase();
      if (["EXTRACTING", "NORMALIZING", "INGESTING", "ANALYZING"].includes(st)) {
        setIsProcessing(true);
        startPolling(activeEvidence.evidence_id);
      } else {
        stopPolling();
        setIsProcessing(false);
      }
    } else {
      setCurrentStatus(null);
      stopPolling();
    }
  }, [activeEvidence, startPolling, stopPolling]);

  // Fetch genuine forensic tool statuses from M1 (Task 5)
  useEffect(() => {
    async function loadTools() {
      setLoadingTools(true);
      try {
        const toolList = await getForensicTools();
        setTools(Array.isArray(toolList) ? toolList : []);
      } catch (err) {
        console.warn("Failed to load live tool status:", err);
      } finally {
        setLoadingTools(false);
      }
    }
    loadTools();
  }, []);

  // Trigger real evidence processing endpoint (Task 2)
  const handleProcessEvidence = async () => {
    if (!selectedEvidenceId) return;
    setIsProcessing(true);
    setPollError(null);

    // Update local status to immediate starting state
    setCurrentStatus((prev) => ({
      ...(prev || {}),
      evidence_id: selectedEvidenceId,
      source_name: activeEvidence?.source_name || "Evidence Container",
      processing_status: "EXTRACTING",
      processing_error: null
    }));

    startPolling(selectedEvidenceId);

    try {
      const res = await processEvidence(selectedEvidenceId, {
        kind: "auto",
        timeline: true,
        run_analysis: true
      });

      setCurrentStatus({
        evidence_id: selectedEvidenceId,
        case_id: activeCase?.case_id,
        source_name: activeEvidence?.source_name || "Evidence Container",
        processing_status: res.status || "COMPLETED",
        processing_error: null
      });

      stopPolling();
      setIsProcessing(false);
      if (onRefresh) onRefresh();
    } catch (err) {
      stopPolling();
      setIsProcessing(false);
      setCurrentStatus((prev) => ({
        ...(prev || {}),
        processing_status: "FAILED",
        processing_error: err.message || "Forensic extraction failed"
      }));
    }
  };

  // Run M2 AI correlation on case
  const handleRunCorrelation = async () => {
    if (!activeCase) return;
    setRunningCorrelation(true);
    try {
      const res = await runCorrelation(activeCase.case_id);
      alert(`AI Correlation Complete! Scanned ${res.events_scanned} events, updated ${res.anomalous_events_flagged} anomalies.`);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Correlation run failed: " + err.message);
    } finally {
      setRunningCorrelation(false);
    }
  };

  const getStatusBadge = (status) => {
    const s = (status || "PENDING").toUpperCase();
    switch (s) {
      case "COMPLETED":
        return <span className="badge-tag badge-emerald"><CheckCircle2 size={12} /> COMPLETED</span>;
      case "FAILED":
        return <span className="badge-tag badge-rose"><AlertTriangle size={12} /> FAILED</span>;
      case "EXTRACTING":
        return <span className="badge-tag badge-cyan"><RotateCw size={12} className="spin" /> EXTRACTING (M1)</span>;
      case "NORMALIZING":
        return <span className="badge-tag badge-cyan"><RotateCw size={12} className="spin" /> NORMALIZING</span>;
      case "INGESTING":
        return <span className="badge-tag badge-cyan"><RotateCw size={12} className="spin" /> INGESTING (M3 SQLite)</span>;
      case "ANALYZING":
        return <span className="badge-tag badge-purple"><RotateCw size={12} className="spin" /> ANALYZING (M2)</span>;
      default:
        return <span className="badge-tag badge-amber"><Clock size={12} /> PENDING</span>;
    }
  };

  const currentProcessingStatus = (currentStatus?.processing_status || activeEvidence?.processing_status || "PENDING").toUpperCase();

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
              Forensic Processing Pipeline & Engine Status
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Live orchestration: M1 container extraction, Plaso timeline normalization, M3 SQLite ingestion, and M2 behavioral analysis.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          {isPolling && (
            <span style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "11.5px",
              color: "var(--cyan-text)",
              fontFamily: "var(--font-mono)"
            }}>
              <RotateCw size={12} className="spin" /> Live polling active
            </span>
          )}

          <button
            className="btn btn-secondary"
            onClick={() => pollStatus(selectedEvidenceId)}
            disabled={!selectedEvidenceId || isProcessing}
          >
            <RotateCw size={13} /> Refresh Status
          </button>

          <button
            className="btn btn-primary"
            onClick={handleRunCorrelation}
            disabled={runningCorrelation || !activeCase}
          >
            <RotateCw size={13} className={runningCorrelation ? "spin" : ""} />
            {runningCorrelation ? "Correlating..." : "Run AI Correlation"}
          </button>
        </div>
      </div>

      {/* Main Grid: Active Processing Card + Evidence Switcher */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
        gap: "20px",
        marginBottom: "24px"
      }}>
        {/* Active Evidence Processing Monitor */}
        <div className="forensic-card" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: "10px" }}>
            <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", display: "flex", alignItems: "center", gap: "8px" }}>
              <Terminal size={16} color="var(--primary)" />
              Evidence Processing Monitor
            </h3>
            {getStatusBadge(currentProcessingStatus)}
          </div>

          {activeEvidence ? (
            <>
              {/* Evidence Container Meta */}
              <div style={{
                backgroundColor: "var(--bg-card-subtle)",
                padding: "12px 14px",
                borderRadius: "var(--radius-sm)",
                border: "1px solid var(--border)",
                display: "flex",
                flexDirection: "column",
                gap: "8px"
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ fontWeight: "700", fontSize: "14px", color: "var(--text-main)" }}>
                    {activeEvidence.source_name}
                  </div>
                  <span className="badge-tag badge-cyan" style={{ fontSize: "10px" }}>
                    {activeEvidence.evidence_type}
                  </span>
                </div>

                <div className="mono" style={{ fontSize: "11px", color: "var(--text-muted)", wordBreak: "break-all" }}>
                  <strong>ID:</strong> {activeEvidence.evidence_id}
                </div>

                <div className="mono" style={{ fontSize: "11px", color: "var(--text-muted)", wordBreak: "break-all" }}>
                  <strong>SHA-256:</strong> {activeEvidence.hash_sha256}
                </div>

                {lastUpdated && (
                  <div style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>
                    Status refreshed: {lastUpdated}
                  </div>
                )}
              </div>

              {/* Status Specific Render */}
              {currentProcessingStatus === "FAILED" && (
                <div style={{
                  backgroundColor: "var(--rose-subtle)",
                  border: "1px solid var(--rose-border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "14px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--rose-text)", fontWeight: "700", fontSize: "13px" }}>
                    <AlertTriangle size={16} /> Forensic Processing Failed
                  </div>
                  <div className="mono" style={{ fontSize: "12px", color: "var(--rose-text)", lineHeight: "1.4" }}>
                    {currentStatus?.processing_error || activeEvidence.processing_error || "Unknown execution failure occurred during extraction."}
                  </div>
                  <button
                    className="btn btn-rose"
                    style={{ alignSelf: "flex-start", fontSize: "12px" }}
                    onClick={handleProcessEvidence}
                    disabled={isProcessing}
                  >
                    <RotateCw size={13} /> Retry Evidence Processing
                  </button>
                </div>
              )}

              {["EXTRACTING", "NORMALIZING", "INGESTING", "ANALYZING"].includes(currentProcessingStatus) && (
                <div style={{
                  backgroundColor: "var(--cyan-subtle)",
                  border: "1px solid var(--cyan-border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "16px",
                  textAlign: "center"
                }}>
                  <RotateCw size={28} color="var(--cyan)" className="spin" style={{ margin: "0 auto 10px" }} />
                  <div style={{ fontWeight: "700", fontSize: "14px", color: "var(--cyan-text)" }}>
                    Forensic Pipeline In Progress ({currentProcessingStatus})
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>
                    Orchestrating M1 forensic tools, Plaso super-timeline extraction, and M2 behavioral heuristics...
                  </div>
                </div>
              )}

              {currentProcessingStatus === "COMPLETED" && (
                <div style={{
                  backgroundColor: "var(--emerald-subtle)",
                  border: "1px solid var(--emerald-border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "16px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--emerald-text)", fontWeight: "700", fontSize: "13.5px" }}>
                    <CheckCircle2 size={18} /> Evidence Container Successfully Processed
                  </div>
                  <p style={{ fontSize: "12.5px", color: "var(--text-dim)", margin: "0" }}>
                    Artifacts carved, events normalized to CEM schema, and initial anomalies analyzed. Data is ready for investigator review.
                  </p>
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "4px" }}>
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: "11.5px" }}
                      onClick={() => onNavigate && onNavigate("timeline")}
                    >
                      View Forensic Timeline <ArrowRight size={12} />
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: "11.5px" }}
                      onClick={() => onNavigate && onNavigate("findings")}
                    >
                      View Proposed Findings <ArrowRight size={12} />
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: "11.5px" }}
                      onClick={() => onNavigate && onNavigate("attack_path")}
                    >
                      View MITRE Attack Path <ArrowRight size={12} />
                    </button>
                  </div>
                </div>
              )}

              {/* Action Button for Pending / Reprocess */}
              {currentProcessingStatus !== "EXTRACTING" &&
               currentProcessingStatus !== "NORMALIZING" &&
               currentProcessingStatus !== "INGESTING" &&
               currentProcessingStatus !== "ANALYZING" &&
               currentProcessingStatus !== "FAILED" && (
                <div style={{ display: "flex", gap: "10px", marginTop: "auto" }}>
                  <button
                    className="btn btn-primary"
                    style={{ flex: 1, padding: "10px", fontSize: "13px" }}
                    onClick={handleProcessEvidence}
                    disabled={isProcessing}
                  >
                    <Play size={14} />
                    {currentProcessingStatus === "COMPLETED" ? "Re-Process Evidence" : "Process Evidence Container"}
                  </button>
                </div>
              )}
            </>
          ) : (
            <div style={{ textAlign: "center", padding: "40px 16px", color: "var(--text-muted)" }}>
              <HardDrive size={32} style={{ margin: "0 auto 10px", opacity: 0.5 }} />
              <div style={{ fontWeight: "600", fontSize: "14px", color: "var(--text-main)" }}>
                No Evidence Ingested for Active Case
              </div>
              <p style={{ fontSize: "12.5px", marginTop: "4px", marginBottom: "14px" }}>
                Acquire an E01 disk image, memory dump, or log file to begin analysis.
              </p>
              <button
                className="btn btn-primary"
                style={{ fontSize: "12px" }}
                onClick={() => onNavigate && onNavigate("evidence_upload")}
              >
                Go to Evidence Acquisition
              </button>
            </div>
          )}

          {pollError && (
            <div style={{ fontSize: "11px", color: "var(--rose-text)", marginTop: "4px" }}>
              Warning: Polling issue ({pollError})
            </div>
          )}
        </div>

        {/* Evidence Containers in Active Case */}
        <div className="forensic-card" style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", display: "flex", alignItems: "center", gap: "8px" }}>
              <HardDrive size={16} color="var(--primary)" />
              Case Evidence Items ({evidenceList.length})
            </h3>
            <button
              className="btn btn-secondary"
              style={{ fontSize: "11px", padding: "3px 8px" }}
              onClick={() => onNavigate && onNavigate("evidence_upload")}
            >
              + Ingest New
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px", overflowY: "auto", maxHeight: "380px" }}>
            {evidenceList.length === 0 ? (
              <div style={{ textAlign: "center", padding: "30px 10px", color: "var(--text-muted)", fontSize: "12.5px" }}>
                No evidence items associated with this case yet.
              </div>
            ) : (
              evidenceList.map((ev) => {
                const isSelected = ev.evidence_id === selectedEvidenceId;
                return (
                  <div
                    key={ev.evidence_id}
                    onClick={() => setSelectedEvidenceId(ev.evidence_id)}
                    style={{
                      padding: "10px 12px",
                      borderRadius: "var(--radius-sm)",
                      border: `1px solid ${isSelected ? "var(--primary-border)" : "var(--border)"}`,
                      backgroundColor: isSelected ? "var(--primary-subtle)" : "var(--bg-card-subtle)",
                      cursor: "pointer",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      transition: "all 0.15s ease"
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "13px", fontWeight: "600", color: isSelected ? "var(--primary-text)" : "var(--text-main)" }}>
                        {ev.source_name}
                      </div>
                      <div className="mono" style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>
                        {ev.evidence_type} • {ev.evidence_id.substring(0, 8)}...
                      </div>
                    </div>
                    {getStatusBadge(ev.processing_status)}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Forensic Tool Orchestration Section (Task 5: Real M1 Tool Status) */}
      <div className="forensic-card">
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "14px",
          borderBottom: "1px solid var(--border)",
          paddingBottom: "10px"
        }}>
          <div>
            <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", display: "flex", alignItems: "center", gap: "8px" }}>
              <Server size={16} color="var(--primary)" />
              Detected Forensic Tool Engines (Live M1 Status)
            </h3>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>
              Reported by M1 module engine (http://localhost:8001/tools)
            </div>
          </div>

          <span className="badge-tag badge-emerald" style={{ fontSize: "10.5px" }}>
            <CheckCircle2 size={12} /> Verified Pipeline
          </span>
        </div>

        {loadingTools ? (
          <div style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)", fontSize: "13px" }}>
            Detecting installed forensic tool binaries...
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
            {tools.map((t, idx) => {
              const isAvail = Boolean(t.available);
              return (
                <div
                  key={t.name || idx}
                  style={{
                    backgroundColor: "var(--bg-card-subtle)",
                    border: `1px solid ${isAvail ? "var(--border)" : "var(--border-subtle)"}`,
                    borderRadius: "var(--radius-sm)",
                    padding: "14px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ fontWeight: "700", fontSize: "13.5px", color: "var(--text-main)" }}>
                      {t.name}
                    </div>
                    <span className={`badge-tag ${isAvail ? "badge-emerald" : "badge-rose"}`} style={{ fontSize: "10px" }}>
                      {isAvail ? "ONLINE" : "NOT DETECTED"}
                    </span>
                  </div>

                  <div style={{ fontSize: "11.5px", color: "var(--text-dim)" }}>
                    {t.note || (t.name === "Autopsy" ? "File system extraction engine" : t.name === "Plaso" ? "Super-timeline generation engine" : "Volatile memory analysis framework")}
                  </div>

                  <div className="mono" style={{ fontSize: "10.5px", color: "var(--text-muted)", marginTop: "4px", wordBreak: "break-all" }}>
                    <strong>Binary:</strong> {t.executable || "Available after configuration"}
                  </div>

                  {t.version && (
                    <div className="mono" style={{ fontSize: "10.5px", color: "var(--primary-text)" }}>
                      <strong>Version:</strong> {t.version}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
