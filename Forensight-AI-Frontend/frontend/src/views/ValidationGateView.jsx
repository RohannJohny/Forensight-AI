import React, { useState } from "react";
import {
  ShieldCheck,
  CheckCircle,
  XCircle,
  Edit3,
  Info,
  X
} from "lucide-react";
import { validateFinding } from "../services/api";

export default function ValidationGateView({ findings, _activeCase, onRefresh }) {
  const [editingFinding, setEditingFinding] = useState(null);
  const [editNotes, setEditNotes] = useState("");
  const [editTitle, setEditTitle] = useState("");
  const [editStatus, setEditStatus] = useState("Accepted");
  const [submitting, setSubmitting] = useState(false);

  const handleQuickStatus = async (finding, newStatus) => {
    try {
      await validateFinding(finding.finding_id, {
        validation_status: newStatus,
        investigator_notes: `Validation updated to ${newStatus} by Lead Examiner.`
      });
      onRefresh();
    } catch (err) {
      alert("Validation update failed: " + err.message);
    }
  };

  const openEditModal = (finding) => {
    setEditingFinding(finding);
    setEditTitle(finding.finding_title);
    setEditNotes(finding.investigator_notes || "");
    setEditStatus(finding.validation_status);
  };

  const saveEdit = async () => {
    if (!editingFinding) return;
    setSubmitting(true);
    try {
      await validateFinding(editingFinding.finding_id, {
        validation_status: editStatus,
        finding_title: editTitle,
        investigator_notes: editNotes
      });
      setEditingFinding(null);
      onRefresh();
    } catch (err) {
      alert("Failed to save changes: " + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const acceptedCount = findings ? findings.filter(f => f.validation_status === "Accepted").length : 0;
  const totalCount = findings ? findings.length : 0;

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
            <ShieldCheck size={20} color="var(--emerald)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Examiner Validation Gate
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Forensic governance checkpoint: AI suggests correlations; the lead examiner verifies, accepts, or modifies findings.
          </p>
        </div>

        <span className="badge-tag badge-emerald">
          {acceptedCount} of {totalCount} Accepted
        </span>
      </div>

      {/* Info Notice */}
      <div style={{
        backgroundColor: "var(--primary-subtle)",
        border: "1px solid var(--primary-border)",
        borderRadius: "var(--radius-sm)",
        padding: "12px 16px",
        marginBottom: "20px",
        display: "flex",
        alignItems: "center",
        gap: "10px",
        fontSize: "13px",
        color: "var(--text-dim)"
      }}>
        <Info size={16} color="var(--primary)" style={{ flexShrink: 0 }} />
        <div>
          <strong>Forensic Admissibility:</strong> Under ISO/IEC 27037 forensic standards, only findings explicitly marked as <strong>"Accepted"</strong> will be codified into the finalized encrypted report dossier.
        </div>
      </div>

      {/* Findings List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {findings?.map((f) => {
          const isAccepted = f.validation_status === "Accepted";
          const isRejected = f.validation_status === "Rejected";

          return (
            <div
              key={f.finding_id}
              className="forensic-card"
              style={{
                padding: "18px 20px",
                borderLeftWidth: "4px",
                borderLeftColor: isAccepted ? "var(--emerald)" : isRejected ? "var(--rose)" : "var(--amber)"
              }}
            >
              <div style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: "8px",
                flexWrap: "wrap",
                gap: "10px"
              }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                    <span className="badge-tag badge-cyan" style={{ fontSize: "10.5px" }}>
                      {f.finding_type}
                    </span>
                    <span className={`badge-tag ${isAccepted ? "badge-emerald" : isRejected ? "badge-rose" : "badge-amber"}`}>
                      {f.validation_status}
                    </span>
                    <span style={{ fontSize: "11.5px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      AI Confidence: {(f.confidence_score * 100).toFixed(0)}%
                    </span>
                  </div>
                  <h3 style={{ fontSize: "15.5px", fontWeight: "700", color: "var(--text-main)" }}>
                    {f.finding_title}
                  </h3>
                </div>

                {/* Examiner Action Buttons */}
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <button
                    className="btn btn-emerald"
                    style={{ padding: "5px 11px", fontSize: "12px" }}
                    onClick={() => handleQuickStatus(f, "Accepted")}
                    disabled={isAccepted}
                  >
                    <CheckCircle size={13} /> Accept
                  </button>
                  <button
                    className="btn btn-rose"
                    style={{ padding: "5px 11px", fontSize: "12px" }}
                    onClick={() => handleQuickStatus(f, "Rejected")}
                    disabled={isRejected}
                  >
                    <XCircle size={13} /> Reject
                  </button>
                  <button
                    className="btn btn-secondary"
                    style={{ padding: "5px 11px", fontSize: "12px" }}
                    onClick={() => openEditModal(f)}
                  >
                    <Edit3 size={13} /> Edit
                  </button>
                </div>
              </div>

              {/* Description */}
              <p style={{ fontSize: "13px", color: "var(--text-dim)", lineHeight: "1.55", marginBottom: "10px" }}>
                {f.description}
              </p>

              {/* Footer Citations and Examiner Notes */}
              <div style={{
                backgroundColor: "var(--bg-card-subtle)",
                border: "1px solid var(--border)",
                padding: "9px 12px",
                borderRadius: "var(--radius-sm)",
                display: "flex",
                flexWrap: "wrap",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "8px",
                fontSize: "12px"
              }}>
                <div style={{ color: "var(--text-muted)" }}>
                  <strong>Linked Event ID:</strong>{" "}
                  <span className="mono" style={{ color: "var(--primary-text)" }}>
                    {f.event_id || "Cross-artifact cluster"}
                  </span>
                </div>
                <div style={{ color: "var(--text-dim)" }}>
                  <strong>Examiner Notes:</strong>{" "}
                  <span>{f.investigator_notes || "Awaiting examiner notes."}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Edit Finding Modal */}
      {editingFinding && (
        <div className="modal-overlay" onClick={() => setEditingFinding(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              borderBottom: "1px solid var(--border)",
              paddingBottom: "10px"
            }}>
              <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)" }}>
                Examiner Review: Edit Finding
              </h3>
              <button
                onClick={() => setEditingFinding(null)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "18px" }}>
              <div>
                <label style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", display: "block", marginBottom: "5px" }}>
                  FINDING TITLE
                </label>
                <input
                  type="text"
                  className="input-control"
                  style={{ width: "100%" }}
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                />
              </div>

              <div>
                <label style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", display: "block", marginBottom: "5px" }}>
                  VALIDATION STATUS
                </label>
                <select
                  className="input-control"
                  style={{ width: "100%" }}
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                >
                  <option value="Accepted">Accepted (Included in Final Dossier)</option>
                  <option value="Rejected">Rejected (Excluded)</option>
                  <option value="Modified">Modified (Custom Investigator Narrative)</option>
                  <option value="Pending">Pending Review</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600", display: "block", marginBottom: "5px" }}>
                  EXAMINER VERIFICATION NOTES
                </label>
                <textarea
                  className="input-control"
                  rows={4}
                  style={{ width: "100%", resize: "vertical" }}
                  placeholder="Record forensic methodology, tool cross-checks, and reason for acceptance/rejection..."
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                />
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
              <button className="btn btn-secondary" onClick={() => setEditingFinding(null)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={saveEdit} disabled={submitting}>
                {submitting ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
