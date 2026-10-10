import React, { useState } from "react";
import {
  HardDrive,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Copy,
  Layers,
  Play,
  RotateCw,
  Plus,
  AlertTriangle
} from "lucide-react";
import { verifyEvidenceIntegrity, processEvidence } from "../services/api";

export default function EvidenceView({ evidenceList = [], _activeCase, onRefresh, onNavigate }) {
  const [verifyingId, setVerifyingId] = useState(null);
  const [processingId, setProcessingId] = useState(null);
  const [integrityResult, setIntegrityResult] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);

  const handleVerify = async (evidenceId) => {
    setVerifyingId(evidenceId);
    try {
      const res = await verifyEvidenceIntegrity(evidenceId);
      setIntegrityResult(res);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Integrity verification check failed: " + err.message);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleProcess = async (evidenceId) => {
    setProcessingId(evidenceId);
    try {
      await processEvidence(evidenceId, { kind: "auto", timeline: true, run_analysis: true });
      if (onRefresh) onRefresh();
      if (onNavigate) onNavigate("processing");
    } catch (err) {
      alert("Failed to start processing: " + err.message);
      if (onNavigate) onNavigate("processing");
    } finally {
      setProcessingId(null);
    }
  };

  const copyToClipboard = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatSize = (bytesStr) => {
    if (!bytesStr) return "N/A";
    const bytes = parseInt(bytesStr);
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const getTypeBadge = (type) => {
    switch (type) {
      case "DISK_IMAGE":
        return <span className="badge-tag badge-cyan">Disk Image (E01)</span>;
      case "MEMORY_DUMP":
        return <span className="badge-tag badge-indigo">Memory Dump (RAW)</span>;
      case "EVTX":
        return <span className="badge-tag badge-emerald">Windows EVTX</span>;
      case "PCAP":
        return <span className="badge-tag badge-amber">Network PCAP</span>;
      default:
        return <span className="badge-tag badge-cyan">{type}</span>;
    }
  };

  const getStatusBadge = (status) => {
    const s = (status || "PENDING").toUpperCase();
    switch (s) {
      case "COMPLETED":
        return <span className="badge-tag badge-emerald" style={{ fontSize: "10px" }}><CheckCircle2 size={11} /> COMPLETED</span>;
      case "FAILED":
        return <span className="badge-tag badge-rose" style={{ fontSize: "10px" }}><AlertTriangle size={11} /> FAILED</span>;
      case "EXTRACTING":
      case "NORMALIZING":
      case "INGESTING":
      case "ANALYZING":
        return <span className="badge-tag badge-cyan" style={{ fontSize: "10px" }}><RotateCw size={11} className="spin" /> {s}</span>;
      default:
        return <span className="badge-tag badge-amber" style={{ fontSize: "10px" }}>PENDING</span>;
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
            <HardDrive size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Digital Evidence Vault & Integrity Engine
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Module 1 & 2: Bit-stream acquisition records, cryptographic SHA-256 verification, and forensic extraction triggers.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <span className="badge-tag badge-emerald">
            <ShieldCheck size={13} /> Strict Chain of Custody
          </span>
          <button
            className="btn btn-primary"
            onClick={() => onNavigate && onNavigate("evidence_upload")}
          >
            <Plus size={14} /> Acquire New Evidence
          </button>
        </div>
      </div>

      {/* Integrity Verification Result Banner (if triggered) */}
      {integrityResult && (
        <div style={{
          backgroundColor: integrityResult.is_valid ? "var(--emerald-subtle)" : "var(--rose-subtle)",
          border: `1px solid ${integrityResult.is_valid ? "var(--emerald-border)" : "var(--rose-border)"}`,
          borderRadius: "var(--radius-sm)",
          padding: "14px 18px",
          marginBottom: "20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "12px"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            {integrityResult.is_valid ? (
              <CheckCircle2 size={24} color="var(--emerald)" style={{ flexShrink: 0 }} />
            ) : (
              <AlertCircle size={24} color="var(--rose)" style={{ flexShrink: 0 }} />
            )}
            <div>
              <div style={{ fontSize: "14px", fontWeight: "700", color: integrityResult.is_valid ? "var(--emerald-text)" : "var(--rose-text)" }}>
                Cryptographic Integrity: {integrityResult.status}
              </div>
              <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "2px", fontFamily: "var(--font-mono)" }}>
                Target: {integrityResult.source_name} | SHA-256: {integrityResult.stored_hash_sha256}
              </div>
            </div>
          </div>
          <button className="btn btn-secondary" style={{ fontSize: "12px" }} onClick={() => setIntegrityResult(null)}>
            Dismiss
          </button>
        </div>
      )}

      {/* Evidence Table */}
      <div className="forensic-card" style={{ padding: "0", overflow: "hidden", marginBottom: "24px" }}>
        {evidenceList.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px 24px", color: "var(--text-muted)" }}>
            <HardDrive size={36} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <h3 style={{ fontSize: "15px", fontWeight: "600", color: "var(--text-main)", marginBottom: "4px" }}>
              No Evidence Containers Ingested
            </h3>
            <p style={{ fontSize: "13px", maxWidth: "440px", margin: "0 auto 16px" }}>
              Upload forensic disk images (E01), memory dumps, or event logs to establish chain of custody.
            </p>
            <button className="btn btn-primary" onClick={() => onNavigate && onNavigate("evidence_upload")}>
              <Plus size={14} /> Go to Evidence Acquisition
            </button>
          </div>
        ) : (
          <table className="forensic-table">
            <thead>
              <tr>
                <th>Evidence Container</th>
                <th>Category</th>
                <th>File Size</th>
                <th>Acquisition SHA-256 Hash</th>
                <th>Processing Status</th>
                <th>Ingested At</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {evidenceList.map((ev) => (
                <tr key={ev.evidence_id}>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <div style={{
                        width: "30px",
                        height: "30px",
                        borderRadius: "5px",
                        backgroundColor: "var(--bg-card-subtle)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        border: "1px solid var(--border)",
                        flexShrink: 0
                      }}>
                        <HardDrive size={15} color="var(--primary)" />
                      </div>
                      <div>
                        <div style={{ fontWeight: "600", color: "var(--text-main)", fontSize: "13.5px" }}>
                          {ev.source_name}
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          {ev.storage_path}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>{getTypeBadge(ev.evidence_type)}</td>
                  <td className="mono" style={{ fontSize: "12px", color: "var(--text-main)", fontWeight: "500" }}>
                    {formatSize(ev.byte_size)}
                  </td>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <span className="mono" style={{ fontSize: "11.5px", color: "var(--text-dim)" }}>
                        {ev.hash_sha256 ? `${ev.hash_sha256.substring(0, 14)}...${ev.hash_sha256.substring(50)}` : "—"}
                      </span>
                      {ev.hash_sha256 && (
                        <button
                          onClick={() => copyToClipboard(ev.hash_sha256)}
                          style={{
                            background: "none",
                            border: "none",
                            cursor: "pointer",
                            color: copiedHash === ev.hash_sha256 ? "var(--emerald)" : "var(--text-muted)",
                            padding: "2px 4px"
                          }}
                          title="Copy full SHA-256 hash"
                        >
                          <Copy size={13} />
                        </button>
                      )}
                    </div>
                  </td>
                  <td>{getStatusBadge(ev.processing_status)}</td>
                  <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    {ev.ingested_at ? new Date(ev.ingested_at).toLocaleString() : "—"}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "inline-flex", gap: "6px" }}>
                      <button
                        className="btn btn-secondary"
                        style={{ fontSize: "11.5px", padding: "4px 9px" }}
                        onClick={() => handleVerify(ev.evidence_id)}
                        disabled={verifyingId === ev.evidence_id}
                        title="Re-compute and verify SHA-256 bit-stream integrity"
                      >
                        <ShieldCheck size={12} />
                        {verifyingId === ev.evidence_id ? "Hashing..." : "Verify"}
                      </button>

                      <button
                        className="btn btn-primary"
                        style={{ fontSize: "11.5px", padding: "4px 9px" }}
                        onClick={() => handleProcess(ev.evidence_id)}
                        disabled={processingId === ev.evidence_id}
                        title="Trigger M1 extraction and Plaso normalization pipeline"
                      >
                        {processingId === ev.evidence_id ? (
                          <RotateCw size={12} className="spin" />
                        ) : (
                          <Play size={12} />
                        )}
                        {ev.processing_status === "COMPLETED" ? "Re-Analyze" : "Process"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Forensic Tool Orchestration */}
      <div className="forensic-card">
        <h3 style={{
          fontSize: "15px",
          fontWeight: "700",
          color: "var(--text-main)",
          marginBottom: "10px",
          display: "flex",
          alignItems: "center",
          gap: "8px"
        }}>
          <Layers size={16} color="var(--primary)" />
          Integrated Forensic Tool Orchestration
        </h3>
        <p style={{ fontSize: "13px", color: "var(--text-dim)", lineHeight: "1.55", marginBottom: "12px" }}>
          Forensight AI executes automated forensic artifact extraction without altering master disk images:
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "10px" }}>
          <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)" }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--cyan-text)" }}>The Sleuth Kit / Autopsy</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "2px" }}>NTFS $MFT parsing, file-system metadata, and deleted record carving.</div>
          </div>
          <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)" }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--primary-text)" }}>Volatility 3 Engine</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "2px" }}>Volatile memory process trees (windows.pstree), code injection (malfind).</div>
          </div>
          <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)" }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--emerald-text)" }}>Plaso (log2timeline)</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "2px" }}>Automated super-timeline extraction normalizing events to 17-field CEM schema.</div>
          </div>
        </div>
      </div>
    </div>
  );
}
