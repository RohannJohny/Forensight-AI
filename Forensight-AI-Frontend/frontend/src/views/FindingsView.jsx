import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Search
} from "lucide-react";

export default function FindingsView({ findings, activeCase, onNavigate }) {
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const acceptedCount = findings?.filter((f) => f.validation_status === "Accepted").length || 0;
  const rejectedCount = findings?.filter((f) => f.validation_status === "Rejected").length || 0;
  const pendingCount = findings?.filter((f) => f.validation_status === "Pending").length || 0;

  const getMitreForFinding = (f) => {
    const title = (f.finding_title || "").toLowerCase();
    if (title.includes("powershell") || title.includes("stager")) return "T1059.001: PowerShell Execution";
    if (title.includes("registry") || title.includes("persistence")) return "T1547.001: Registry Run Keys";
    if (title.includes("lsass") || title.includes("credential")) return "T1003.001: LSASS Memory Dump";
    if (title.includes("smb") || title.includes("lateral")) return "T1021.002: SMB Admin$ Shares";
    if (title.includes("exfiltration") || title.includes("c2")) return "T1048.002: Encrypted Non-C2 Protocol";
    return "T1566.001: Spearphishing Attachment";
  };

  const getSeverity = (f) => {
    const conf = f.confidence_score || 0.85;
    if (conf >= 0.95) return { label: "CRITICAL", badge: "badge-rose" };
    if (conf >= 0.85) return { label: "HIGH", badge: "badge-amber" };
    return { label: "MEDIUM", badge: "badge-cyan" };
  };

  const filteredFindings = findings?.filter((f) => {
    const matchStatus = statusFilter === "ALL" || f.validation_status?.toUpperCase() === statusFilter.toUpperCase();
    const matchSearch =
      (f.finding_title || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.description || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.finding_type || "").toLowerCase().includes(searchQuery.toLowerCase());
    return matchStatus && matchSearch;
  }) || [];

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
            <ShieldCheck size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Investigative Findings Summary
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Confirmed, rejected, and pending forensic findings with confidence scores, MITRE ATT&CK alignment, and evidentiary traceability.
          </p>
        </div>

        <button className="btn btn-emerald" onClick={() => onNavigate && onNavigate("validation")}>
          <ShieldCheck size={14} />
          Go to Validation Gate
        </button>
      </div>

      {/* Metrics Row */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
        gap: "14px",
        marginBottom: "20px"
      }}>
        <div className="stat-widget" onClick={() => setStatusFilter("ALL")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Total Findings</div>
            <div className="stat-value" style={{ color: "var(--primary-text)" }}>
              {findings?.length || 0}
            </div>
          </div>
        </div>

        <div className="stat-widget" onClick={() => setStatusFilter("Accepted")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Confirmed / Accepted</div>
            <div className="stat-value" style={{ color: "var(--emerald-text)" }}>
              {acceptedCount}
            </div>
          </div>
          <CheckCircle2 size={24} color="var(--emerald)" />
        </div>

        <div className="stat-widget" onClick={() => setStatusFilter("Pending")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Pending Review</div>
            <div className="stat-value" style={{ color: "var(--amber-text)" }}>
              {pendingCount}
            </div>
          </div>
          <Clock size={24} color="var(--amber)" />
        </div>

        <div className="stat-widget" onClick={() => setStatusFilter("Rejected")} style={{ cursor: "pointer" }}>
          <div>
            <div className="stat-title">Rejected Findings</div>
            <div className="stat-value" style={{ color: "var(--rose-text)" }}>
              {rejectedCount}
            </div>
          </div>
          <XCircle size={24} color="var(--rose)" />
        </div>
      </div>

      {/* Filter and Search Toolbar */}
      <div className="forensic-card" style={{ padding: "14px 18px", marginBottom: "20px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ position: "relative", flex: "1 1 300px" }}>
            <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "12px", top: "10px" }} />
            <input
              type="text"
              className="input-control"
              style={{ width: "100%", paddingLeft: "34px" }}
              placeholder="Search findings by title, description, or MITRE mapping..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <span style={{ fontSize: "11.5px", color: "var(--text-muted)", fontWeight: "600" }}>STATUS:</span>
            {["ALL", "Accepted", "Pending", "Rejected"].map((st) => (
              <button
                key={st}
                className={`btn ${statusFilter === st ? "btn-primary" : "btn-secondary"}`}
                style={{ fontSize: "11.5px", padding: "4px 10px" }}
                onClick={() => setStatusFilter(st)}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Findings Cards List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        {filteredFindings.map((f) => {
          const isAccepted = f.validation_status === "Accepted";
          const isRejected = f.validation_status === "Rejected";
          const sev = getSeverity(f);
          const mitre = getMitreForFinding(f);

          return (
            <div
              key={f.finding_id}
              className="forensic-card"
              style={{
                padding: "18px 22px",
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
                gap: "8px"
              }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                    <span className={`badge-tag ${sev.badge}`} style={{ fontSize: "10px" }}>
                      {sev.label}
                    </span>
                    <span className="badge-tag badge-cyan" style={{ fontSize: "10px" }}>
                      {f.finding_type}
                    </span>
                    <span className={`badge-tag ${isAccepted ? "badge-emerald" : isRejected ? "badge-rose" : "badge-amber"}`} style={{ fontSize: "10px" }}>
                      {f.validation_status}
                    </span>
                    <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      AI Confidence: {((f.confidence_score || 0.85) * 100).toFixed(0)}%
                    </span>
                  </div>

                  <h3 style={{ fontSize: "15.5px", fontWeight: "700", color: "var(--text-main)" }}>
                    {f.finding_title}
                  </h3>
                </div>

                <div style={{
                  backgroundColor: "var(--bg-card-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "4px 8px",
                  fontSize: "11.5px",
                  fontFamily: "var(--font-mono)",
                  color: "var(--primary-text)"
                }}>
                  {mitre}
                </div>
              </div>

              <p style={{ fontSize: "13px", color: "var(--text-dim)", lineHeight: "1.55", marginBottom: "12px" }}>
                {f.description}
              </p>

              {/* Evidentiary Provenance and Examiner Notes */}
              <div style={{
                backgroundColor: "var(--bg-card-subtle)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "10px 14px",
                display: "flex",
                flexWrap: "wrap",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "8px",
                fontSize: "12px"
              }}>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Linked CEM Event ID: </span>
                  <span className="mono" style={{ color: "var(--primary-text)", fontWeight: "600" }}>
                    {f.event_id || "Multi-event cluster"}
                  </span>
                </div>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Examiner Notes: </span>
                  <span style={{ color: "var(--text-dim)", fontWeight: "500" }}>
                    {f.investigator_notes || "Awaiting examiner notes."}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
