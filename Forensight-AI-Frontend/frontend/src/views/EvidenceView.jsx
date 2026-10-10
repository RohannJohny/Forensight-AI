import React, { useState } from "react";
import {
  HardDrive,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Copy,
  Layers
} from "lucide-react";
import { verifyEvidenceIntegrity } from "../services/api";

export default function EvidenceView({ evidenceList, activeCase, onRefresh, onNavigate }) {
  const [verifyingId, setVerifyingId] = useState(null);
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
              Digital Evidence Vault
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Cryptographically verified bit-stream forensic artifacts and chain of custody records.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button
            className="btn btn-primary"
            style={{ fontSize: "12px" }}
            onClick={() => onNavigate && onNavigate("evidence_upload")}
          >
            + Ingest New Evidence
          </button>
          <span className="badge-tag badge-emerald">
            <ShieldCheck size={13} /> Strict Chain of Custody
          </span>
        </div>
      </div>

      {/* Verification Result Banner */}
      {integrityResult && (
        <div style={{
          backgroundColor: integrityResult.is_valid ? "var(--emerald-subtle)" : "var(--rose-subtle)",
          border: `1px solid ${integrityResult.is_valid ? "var(--emerald-border)" : "var(--rose-border)"}`,
          borderRadius: "var(--radius-md)",
          padding: "16px 20px",
          marginBottom: "20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            {integrityResult.is_valid ? (
              <CheckCircle2 size={24} color="var(--emerald)" style={{ flexShrink: 0 }} />
            ) : (
              <AlertCircle size={24} color="var(--rose)" style={{ flexShrink: 0 }} />
            )}
            <div>
              <div style={{
                fontSize: "14px",
                fontWeight: "700",
                color: integrityResult.is_valid ? "var(--emerald-text)" : "var(--rose-text)"
              }}>
                Integrity Check: {integrityResult.status}
              </div>
              <div style={{
                fontSize: "12px",
                color: "var(--text-dim)",
                marginTop: "3px",
                fontFamily: "var(--font-mono)"
              }}>
                Item: {integrityResult.source_name} • SHA-256: {integrityResult.stored_hash_sha256}
              </div>
            </div>
          </div>
          <button className="btn btn-secondary" onClick={() => setIntegrityResult(null)}>
            Dismiss
          </button>
        </div>
      )}

      {/* Evidence Items Table */}
      <div className="forensic-card" style={{ padding: "0", overflow: "hidden", marginBottom: "24px" }}>
        <table className="forensic-table">
          <thead>
            <tr>
              <th>Evidence Artifact</th>
              <th>Category</th>
              <th>File Size</th>
              <th>SHA-256 Hash</th>
              <th>Ingested At</th>
              <th style={{ textAlign: "right" }}>Integrity Action</th>
            </tr>
          </thead>
          <tbody>
            {evidenceList?.map((ev) => (
              <tr key={ev.evidence_id}>
                <td>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <div style={{
                      width: "30px",
                      height: "30px",
                      borderRadius: "6px",
                      backgroundColor: "var(--bg-card-subtle)",
                      border: "1px solid var(--border)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
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
                      {ev.hash_sha256 ? `${ev.hash_sha256.substring(0, 16)}...${ev.hash_sha256.substring(48)}` : "—"}
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
                <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  {ev.ingested_at ? new Date(ev.ingested_at).toLocaleString() : "—"}
                </td>
                <td style={{ textAlign: "right" }}>
                  <button
                    className="btn btn-emerald"
                    style={{ fontSize: "11.5px", padding: "5px 11px" }}
                    onClick={() => handleVerify(ev.evidence_id)}
                    disabled={verifyingId === ev.evidence_id}
                  >
                    <ShieldCheck size={13} />
                    {verifyingId === ev.evidence_id ? "Verifying..." : "Verify SHA-256"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
        <p style={{ fontSize: "12.5px", color: "var(--text-dim)", lineHeight: "1.5", marginBottom: "14px" }}>
          Automated artifact extraction without altering bit-stream master images:
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "12px" }}>
          <div style={{
            backgroundColor: "var(--bg-card-subtle)",
            padding: "12px",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)"
          }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-main)" }}>The Sleuth Kit / Autopsy</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "4px" }}>NTFS $MFT parsing, file-system metadata, and deleted record carving.</div>
          </div>
          <div style={{
            backgroundColor: "var(--bg-card-subtle)",
            padding: "12px",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)"
          }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-main)" }}>Volatility 3 Engine</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "4px" }}>Volatile memory process trees (pstree), code injection (malfind), and DLLs.</div>
          </div>
          <div style={{
            backgroundColor: "var(--bg-card-subtle)",
            padding: "12px",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)"
          }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-main)" }}>RegRipper 3.0</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "4px" }}>Windows registry autorun keys, UserAssist execution history, and SAM hives.</div>
          </div>
          <div style={{
            backgroundColor: "var(--bg-card-subtle)",
            padding: "12px",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)"
          }}>
            <div style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-main)" }}>Zeek & Network Parsers</div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "4px" }}>PCAP protocol dissection, TCP stream reconstruction, and exfiltration tracking.</div>
          </div>
        </div>
      </div>
    </div>
  );
}
