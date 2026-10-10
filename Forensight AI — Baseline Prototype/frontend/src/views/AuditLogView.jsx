import React from "react";
import { FileText, Shield, User } from "lucide-react";

export default function AuditLogView({ auditLogs, _activeCase }) {
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
            <FileText size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Forensic Chain of Custody & Audit Trail
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Immutable chronological audit record of evidence ingestions, verifications, and examiner validations.
          </p>
        </div>

        <span className="badge-tag badge-emerald">
          <Shield size={13} /> Tamper-Evident Ledger
        </span>
      </div>

      {/* Audit Log Table */}
      <div className="forensic-card" style={{ padding: "0", overflow: "hidden" }}>
        <table className="forensic-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Investigator / System</th>
              <th>Forensic Action</th>
              <th>Action Details & Ledger Reference</th>
            </tr>
          </thead>
          <tbody>
            {(!auditLogs || auditLogs.length === 0) ? (
              <tr>
                <td colSpan={4} style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                  No audit log entries recorded.
                </td>
              </tr>
            ) : (
              auditLogs.map((log) => (
                <tr key={log.log_id}>
                  <td className="mono" style={{ fontSize: "12px", color: "var(--primary-text)", whiteSpace: "nowrap" }}>
                    {log.timestamp ? new Date(log.timestamp).toUTCString().replace("GMT", "UTC") : "—"}
                  </td>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12.5px" }}>
                      <User size={13} color="var(--emerald)" />
                      <span style={{ fontWeight: "600", color: "var(--text-main)" }}>{log.user_name}</span>
                    </div>
                  </td>
                  <td>
                    <span className="badge-tag badge-cyan" style={{ fontSize: "10.5px" }}>
                      {log.action}
                    </span>
                  </td>
                  <td style={{ fontSize: "12.5px", color: "var(--text-dim)", lineHeight: "1.45" }}>
                    {log.details}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
