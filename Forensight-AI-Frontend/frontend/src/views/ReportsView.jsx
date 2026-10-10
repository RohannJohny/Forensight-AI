import React, { useState } from "react";
import {
  FileLock2,
  KeyRound,
  CheckCircle2,
  FileText,
  Lock,
  Unlock,
  Printer,
  X
} from "lucide-react";
import { generateReport, decryptReport } from "../services/api";

export default function ReportsView({ reports, activeCase, onRefresh }) {
  const [reportTitle, setReportTitle] = useState("Operation Blackout - Forensic Dossier");
  const [examinerName, setExaminerName] = useState("Rohan Johny (Lead Forensic Examiner)");
  const [execSummary, setExecSummary] = useState(
    "Targeted multi-stage cyber intrusion against WS-FIN-04 resulting in macro execution, encoded PowerShell payload, registry persistence, credential dumping, SMB lateral movement, and data exfiltration."
  );
  const [generating, setGenerating] = useState(false);
  const [decryptingId, setDecryptingId] = useState(null);
  const [activeDecryptedReport, setActiveDecryptedReport] = useState(null);

  const handleGenerate = async () => {
    if (!reportTitle.trim() || !activeCase) return;
    setGenerating(true);
    try {
      await generateReport(activeCase.case_id, {
        case_id: activeCase.case_id,
        report_name: reportTitle,
        investigator_name: examinerName,
        executive_summary: execSummary,
        include_raw_hashes: true
      });
      alert("Forensic Dossier compiled and encrypted in the vault.");
      onRefresh();
    } catch (err) {
      alert("Report generation failed: " + err.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleDecrypt = async (reportId) => {
    setDecryptingId(reportId);
    try {
      const res = await decryptReport(reportId);
      setActiveDecryptedReport(res);
    } catch (err) {
      alert("Decryption failed: " + err.message);
    } finally {
      setDecryptingId(null);
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
            <FileLock2 size={20} color="var(--purple)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Forensic Reports & Encrypted Vault
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Courtroom dossier compilation with Two-Key cryptography (AES-256-GCM) and tamper verification.
          </p>
        </div>

        <span className="badge-tag badge-emerald">
          <KeyRound size={13} /> Two-Key Security Active
        </span>
      </div>

      {/* Grid: Compiler on Left, Vault on Right */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))",
        gap: "20px",
        marginBottom: "24px"
      }}>
        {/* Compiler Form */}
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
            <FileText size={16} color="var(--primary)" />
            Compile Forensic Dossier
          </h3>

          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <div>
              <label style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", display: "block", marginBottom: "5px" }}>
                REPORT TITLE
              </label>
              <input
                type="text"
                className="input-control"
                style={{ width: "100%" }}
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
              />
            </div>

            <div>
              <label style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", display: "block", marginBottom: "5px" }}>
                LEAD EXAMINER SIGN-OFF
              </label>
              <input
                type="text"
                className="input-control"
                style={{ width: "100%" }}
                value={examinerName}
                onChange={(e) => setExaminerName(e.target.value)}
              />
            </div>

            <div>
              <label style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", display: "block", marginBottom: "5px" }}>
                EXECUTIVE SUMMARY & ATTESTATION
              </label>
              <textarea
                className="input-control"
                rows={4}
                style={{ width: "100%", resize: "vertical" }}
                value={execSummary}
                onChange={(e) => setExecSummary(e.target.value)}
              />
            </div>

            <div style={{
              backgroundColor: "var(--purple-subtle)",
              border: "1px solid var(--purple-border)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 12px",
              fontSize: "12px",
              color: "var(--purple-text)"
            }}>
              Compiling extracts validated findings, generates a 256-bit REK, encrypts with AES-256-GCM, and stores in the vault.
            </div>

            <button
              className="btn btn-primary"
              style={{ padding: "10px", width: "100%", marginTop: "4px" }}
              onClick={handleGenerate}
              disabled={generating}
            >
              <FileLock2 size={15} />
              {generating ? "Encrypting & Storing..." : "Finalize & Encrypt Dossier"}
            </button>
          </div>
        </div>

        {/* Encrypted Reports Vault List */}
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
            <Lock size={16} color="var(--purple)" />
            Vault Records ({reports?.length || 0})
          </h3>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "420px", overflowY: "auto" }}>
            {(!reports || reports.length === 0) ? (
              <div style={{ textAlign: "center", padding: "36px 0", color: "var(--text-muted)", fontSize: "13px" }}>
                No finalized reports in the vault yet. Use the form to compile a dossier.
              </div>
            ) : (
              reports.map((rep) => (
                <div
                  key={rep.report_id}
                  style={{
                    backgroundColor: "var(--bg-card-subtle)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "14px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div>
                      <div style={{ fontSize: "13.5px", fontWeight: "700", color: "var(--text-main)" }}>
                        {rep.report_name}
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                        Finalized: {rep.finalized_at ? new Date(rep.finalized_at).toUTCString() : "—"}
                      </div>
                    </div>
                    <span className="badge-tag badge-emerald" style={{ fontSize: "10px" }}>
                      AES-256-GCM
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px" }}>
                    <span style={{ color: "var(--text-muted)" }}>SHA-256 Ledger:</span>
                    <span className="mono" style={{ color: "var(--primary-text)" }}>
                      {rep.integrity_hash ? `${rep.integrity_hash.substring(0, 16)}...${rep.integrity_hash.substring(48)}` : "—"}
                    </span>
                  </div>

                  <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "4px" }}>
                    <button
                      className="btn btn-emerald"
                      style={{ fontSize: "11.5px", padding: "5px 11px" }}
                      onClick={() => handleDecrypt(rep.report_id)}
                      disabled={decryptingId === rep.report_id}
                    >
                      <Unlock size={13} />
                      {decryptingId === rep.report_id ? "Decrypting..." : "Decrypt & Verify"}
                    </button>

                    <a
                      href={`http://localhost:8000/api/reports/${rep.report_id}/html`}
                      target="_blank"
                      rel="noreferrer"
                      className="btn btn-secondary"
                      style={{ fontSize: "11.5px", padding: "5px 11px", textDecoration: "none" }}
                    >
                      <Printer size={13} /> Dossier View
                    </a>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Decrypted Report Modal */}
      {activeDecryptedReport && (
        <div className="modal-overlay" onClick={() => setActiveDecryptedReport(null)}>
          <div className="modal-content" style={{ maxWidth: "850px" }} onClick={(e) => e.stopPropagation()}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "14px",
              borderBottom: "1px solid var(--border)",
              paddingBottom: "10px"
            }}>
              <div>
                <h3 style={{ fontSize: "17px", fontWeight: "700", color: "var(--text-main)" }}>
                  {activeDecryptedReport.report_name}
                </h3>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "4px" }}>
                  <span className="badge-tag badge-emerald">
                    <CheckCircle2 size={12} />
                    {activeDecryptedReport.is_tamper_free ? "Integrity Confirmed (Tamper Free)" : "Tamper Warning"}
                  </span>
                  <span className="mono" style={{ fontSize: "11px", color: "var(--primary-text)" }}>
                    SHA-256: {activeDecryptedReport.integrity_hash ? activeDecryptedReport.integrity_hash.substring(0, 24) + "..." : ""}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setActiveDecryptedReport(null)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Plaintext Content */}
            <div style={{
              maxHeight: "440px",
              overflowY: "auto",
              backgroundColor: "var(--bg-code)",
              padding: "16px",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border)",
              marginBottom: "14px"
            }}>
              <pre style={{
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "var(--text-main)",
                lineHeight: "1.55",
                whiteSpace: "pre-wrap"
              }}>
                {activeDecryptedReport.plaintext_content}
              </pre>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>
                Verified: {activeDecryptedReport.verified_at ? new Date(activeDecryptedReport.verified_at).toUTCString() : "—"}
              </span>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  className="btn btn-primary"
                  onClick={() => window.print()}
                >
                  <Printer size={13} /> Print
                </button>
                <button className="btn btn-secondary" onClick={() => setActiveDecryptedReport(null)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
