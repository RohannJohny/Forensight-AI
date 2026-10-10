import React, { useState } from "react";
import { Search, X, ArrowRight } from "lucide-react";

export default function GlobalSearchModal({ isOpen, onClose, cases, evidenceList, events, findings, reports, onNavigateToItem }) {
  const [query, setQuery] = useState("");

  if (!isOpen) return null;

  const q = query.trim().toLowerCase();

  const caseMatches = q ? (cases || []).filter(c => c.case_name.toLowerCase().includes(q) || c.case_number.toLowerCase().includes(q)) : [];
  const evidenceMatches = q ? (evidenceList || []).filter(e => e.source_name.toLowerCase().includes(q) || e.hash_sha256.toLowerCase().includes(q)) : [];
  const eventMatches = q ? (events || []).filter(ev => ev.event_type.toLowerCase().includes(q) || JSON.stringify(ev.details || {}).toLowerCase().includes(q)) : [];
  const findingMatches = q ? (findings || []).filter(f => f.finding_title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q)) : [];
  const reportMatches = q ? (reports || []).filter(r => r.report_name.toLowerCase().includes(q) || r.integrity_hash.toLowerCase().includes(q)) : [];

  const totalResults = caseMatches.length + evidenceMatches.length + eventMatches.length + findingMatches.length + reportMatches.length;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: "750px", maxHeight: "80vh" }} onClick={(e) => e.stopPropagation()}>
        {/* Search Input Bar */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", borderBottom: "1px solid var(--border)", paddingBottom: "12px", marginBottom: "16px" }}>
          <Search size={18} color="var(--primary)" />
          <input
            type="text"
            className="input-control"
            style={{ flex: 1, fontSize: "14px", border: "none", boxShadow: "none", padding: "6px 0" }}
            placeholder="Case-wide search across cases, evidence, artifacts, events, findings, and reports..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
          />
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
            <X size={18} />
          </button>
        </div>

        {/* Results Stream */}
        <div style={{ maxHeight: "480px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "16px" }}>
          {!q ? (
            <div style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)", fontSize: "13px" }}>
              Type any keyword, command, hash, IP, or finding title to search the entire investigation.
            </div>
          ) : totalResults === 0 ? (
            <div style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)", fontSize: "13px" }}>
              No forensic records matching "{query}".
            </div>
          ) : (
            <>
              {/* Case Matches */}
              {caseMatches.length > 0 && (
                <div>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                    CASES ({caseMatches.length})
                  </div>
                  {caseMatches.map(c => (
                    <div
                      key={c.case_id}
                      onClick={() => { onNavigateToItem("cases", c); onClose(); }}
                      style={{ padding: "8px 10px", backgroundColor: "var(--bg-card-subtle)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", marginBottom: "4px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
                    >
                      <div>
                        <span className="mono" style={{ fontSize: "11px", color: "var(--primary-text)", fontWeight: "700" }}>{c.case_number}: </span>
                        <span style={{ fontSize: "12.5px", fontWeight: "600", color: "var(--text-main)" }}>{c.case_name}</span>
                      </div>
                      <ArrowRight size={13} color="var(--text-muted)" />
                    </div>
                  ))}
                </div>
              )}

              {/* Evidence Matches */}
              {evidenceMatches.length > 0 && (
                <div>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                    EVIDENCE CONTAINERS ({evidenceMatches.length})
                  </div>
                  {evidenceMatches.map(ev => (
                    <div
                      key={ev.evidence_id}
                      onClick={() => { onNavigateToItem("evidence", ev); onClose(); }}
                      style={{ padding: "8px 10px", backgroundColor: "var(--bg-card-subtle)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", marginBottom: "4px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
                    >
                      <div>
                        <span style={{ fontSize: "12.5px", fontWeight: "600", color: "var(--text-main)" }}>{ev.source_name}</span>
                        <div className="mono" style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>SHA-256: {ev.hash_sha256.substring(0, 24)}...</div>
                      </div>
                      <ArrowRight size={13} color="var(--text-muted)" />
                    </div>
                  ))}
                </div>
              )}

              {/* Event Matches */}
              {eventMatches.length > 0 && (
                <div>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                    NORMALIZED EVENTS ({eventMatches.length})
                  </div>
                  {eventMatches.map(ev => (
                    <div
                      key={ev.event_id}
                      onClick={() => { onNavigateToItem("timeline", ev); onClose(); }}
                      style={{ padding: "8px 10px", backgroundColor: "var(--bg-card-subtle)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", marginBottom: "4px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
                    >
                      <div>
                        <span className="badge-tag badge-cyan" style={{ fontSize: "9.5px", marginRight: "6px" }}>{ev.event_type}</span>
                        <span style={{ fontSize: "12px", color: "var(--text-main)", fontFamily: "var(--font-mono)" }}>
                          {ev.details?.command_line?.substring(0, 60) || ev.source_entity}
                        </span>
                      </div>
                      <ArrowRight size={13} color="var(--text-muted)" />
                    </div>
                  ))}
                </div>
              )}

              {/* Finding Matches */}
              {findingMatches.length > 0 && (
                <div>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                    FINDINGS ({findingMatches.length})
                  </div>
                  {findingMatches.map(f => (
                    <div
                      key={f.finding_id}
                      onClick={() => { onNavigateToItem("findings", f); onClose(); }}
                      style={{ padding: "8px 10px", backgroundColor: "var(--bg-card-subtle)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", marginBottom: "4px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
                    >
                      <div>
                        <span style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-main)" }}>{f.finding_title}</span>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Status: {f.validation_status}</div>
                      </div>
                      <ArrowRight size={13} color="var(--text-muted)" />
                    </div>
                  ))}
                </div>
              )}

              {/* Report Matches */}
              {reportMatches.length > 0 && (
                <div>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                    ENCRYPTED REPORTS ({reportMatches.length})
                  </div>
                  {reportMatches.map(r => (
                    <div
                      key={r.report_id}
                      onClick={() => { onNavigateToItem("reports", r); onClose(); }}
                      style={{ padding: "8px 10px", backgroundColor: "var(--bg-card-subtle)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", marginBottom: "4px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
                    >
                      <div>
                        <span style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-main)" }}>{r.report_name}</span>
                        <div className="mono" style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>SHA-256 Ledger: {r.integrity_hash.substring(0, 24)}...</div>
                      </div>
                      <ArrowRight size={13} color="var(--text-muted)" />
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
