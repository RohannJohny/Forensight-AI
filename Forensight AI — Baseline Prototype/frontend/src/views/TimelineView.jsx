import React, { useState } from "react";
import {
  Clock,
  Search,
  AlertTriangle,
  Terminal,
  Wifi,
  FileCode,
  Key,
  User,
  Server,
  Maximize2,
  X,
  Copy,
  Check
} from "lucide-react";

export default function TimelineView({ events, _activeCase, onFilterChange, filterParams }) {
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [copiedModalJson, setCopiedModalJson] = useState(false);

  const getEventIcon = (type) => {
    switch (type) {
      case "PROCESS_CREATE":
        return <Terminal size={14} color="var(--rose-text)" />;
      case "NETWORK_CONNECTION":
        return <Wifi size={14} color="var(--cyan-text)" />;
      case "REGISTRY_PERSISTENCE":
      case "REGISTRY_WRITE":
        return <Key size={14} color="var(--purple-text)" />;
      case "FILE_DROP":
        return <FileCode size={14} color="var(--amber-text)" />;
      default:
        return <Clock size={14} color="var(--emerald-text)" />;
    }
  };

  const copyEventJson = (ev) => {
    navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    setCopiedModalJson(true);
    setTimeout(() => setCopiedModalJson(false), 2000);
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
            <Clock size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Chronological Forensic Timeline
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Multi-source event sequencing normalized to the Common Event Model (CEM).
          </p>
        </div>

        <span className="badge-tag badge-cyan">
          {events?.length || 0} Normalized Events
        </span>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="forensic-card" style={{ padding: "14px 18px", marginBottom: "20px" }}>
        <div style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "12px",
          alignItems: "center",
          justifyContent: "space-between"
        }}>
          {/* Search bar */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flex: "1 1 300px" }}>
            <div style={{ position: "relative", width: "100%" }}>
              <Search
                size={14}
                color="var(--text-muted)"
                style={{ position: "absolute", left: "12px", top: "10px" }}
              />
              <input
                type="text"
                className="input-control"
                style={{ width: "100%", paddingLeft: "34px" }}
                placeholder="Search commands, hashes, IPs, users, or event IDs..."
                value={filterParams.search || ""}
                onChange={(e) => onFilterChange({ ...filterParams, search: e.target.value })}
              />
            </div>
          </div>

          {/* Filter Controls */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <select
              className="input-control"
              value={filterParams.event_type || ""}
              onChange={(e) => onFilterChange({ ...filterParams, event_type: e.target.value })}
            >
              <option value="">All Event Types</option>
              <option value="PROCESS_CREATE">Process Execution</option>
              <option value="REGISTRY_PERSISTENCE">Registry Persistence</option>
              <option value="NETWORK_CONNECTION">Network Connections</option>
              <option value="FILE_DROP">File Drops</option>
            </select>

            <button
              className={`btn ${filterParams.only_anomalous ? "btn-rose" : "btn-secondary"}`}
              onClick={() => onFilterChange({ ...filterParams, only_anomalous: !filterParams.only_anomalous })}
            >
              <AlertTriangle size={14} />
              {filterParams.only_anomalous ? "Anomalies Only (Active)" : "Filter Anomalies"}
            </button>
          </div>
        </div>
      </div>

      {/* Timeline Stream */}
      <div style={{ position: "relative", paddingLeft: "24px" }}>
        {(!events || events.length === 0) ? (
          <div className="forensic-card" style={{ textAlign: "center", padding: "48px 24px" }}>
            <Clock size={36} color="var(--text-muted)" style={{ margin: "0 auto 12px" }} />
            <h3 style={{ fontSize: "16px", fontWeight: "600", color: "var(--text-main)", marginBottom: "6px" }}>
              No Normalized Timeline Events
            </h3>
            <p style={{ fontSize: "13px", color: "var(--text-muted)", maxWidth: "440px", margin: "0 auto" }}>
              No forensic events found matching the active filters. Ingest and process an evidence container to populate the super-timeline.
            </p>
          </div>
        ) : (
          <>
            {/* Continuous timeline line */}
            <div style={{
              position: "absolute",
              left: "8px",
              top: "14px",
              bottom: "14px",
              width: "2px",
              backgroundColor: "var(--border)"
            }} />

            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              {events.map((ev) => {
            const isAnom = ev.is_anomalous === 1;
            const details = ev.details || {};
            const timeFormatted = ev.timestamp ? new Date(ev.timestamp).toUTCString().replace("GMT", "UTC") : "—";

            return (
              <div
                key={ev.event_id}
                className="forensic-card"
                style={{
                  position: "relative",
                  padding: "16px 20px",
                  borderColor: isAnom ? "var(--rose-border)" : "var(--border)",
                  borderLeftWidth: "4px",
                  borderLeftColor: isAnom ? "var(--rose)" : "var(--primary)"
                }}
              >
                {/* Node dot on timeline */}
                <div style={{
                  position: "absolute",
                  left: "-25px",
                  top: "20px",
                  width: "16px",
                  height: "16px",
                  borderRadius: "50%",
                  backgroundColor: isAnom ? "var(--rose)" : "var(--primary)",
                  border: "2px solid var(--bg-surface)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center"
                }}>
                  <span style={{ width: "4px", height: "4px", borderRadius: "50%", backgroundColor: "#ffffff" }} />
                </div>

                {/* Event Header */}
                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: "8px",
                  flexWrap: "wrap",
                  gap: "8px"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                    <span className="mono" style={{ fontSize: "12px", color: "var(--primary-text)", fontWeight: "600" }}>
                      {timeFormatted}
                    </span>
                    <span className="badge-tag badge-cyan" style={{ gap: "5px" }}>
                      {getEventIcon(ev.event_type)}
                      {ev.event_type}
                    </span>
                    <span style={{ fontSize: "11.5px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      Source: {ev.source_entity}
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    {isAnom && (
                      <span className="badge-tag badge-rose">
                        <AlertTriangle size={12} /> Threat Score: {(ev.anomaly_score * 100).toFixed(0)}%
                      </span>
                    )}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: "4px 8px", fontSize: "11.5px" }}
                      onClick={() => setSelectedEvent(ev)}
                      title="Inspect full normalized record"
                    >
                      <Maximize2 size={12} /> Details
                    </button>
                  </div>
                </div>

                {/* Event Command / Data Snippet */}
                <div style={{
                  backgroundColor: "var(--bg-code)",
                  border: "1px solid var(--border)",
                  padding: "9px 12px",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "12px",
                  fontFamily: "var(--font-mono)",
                  color: isAnom ? "var(--rose-text)" : "var(--text-main)",
                  marginBottom: "8px",
                  wordBreak: "break-all"
                }}>
                  {details.command_line || details.decoded_command || details.value_data || details.target_filename ||
                   (details.dst_ip ? `Connection: ${details.src_ip}:${details.src_port} -> ${details.dst_ip}:${details.dst_port} (${details.protocol})` : JSON.stringify(details))}
                </div>

                {/* Event Footer */}
                <div style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "16px",
                  fontSize: "11.5px",
                  color: "var(--text-muted)"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                    <User size={13} color="var(--text-muted)" />
                    <span>User: <strong style={{ color: "var(--text-dim)" }}>{ev.user_account || "SYSTEM"}</strong></span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                    <Server size={13} color="var(--text-muted)" />
                    <span>Host: <strong style={{ color: "var(--text-dim)" }}>{ev.host_ip || "127.0.0.1"}</strong></span>
                  </div>
                  <div style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                    ID: {ev.event_id ? ev.event_id.substring(0, 8) : "—"}
                  </div>
                </div>
              </div>
            );
          })}
            </div>
          </>
        )}
      </div>

      {/* Deep Event Inspection Modal */}
      {selectedEvent && (
        <div className="modal-overlay" onClick={() => setSelectedEvent(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              borderBottom: "1px solid var(--border)",
              paddingBottom: "12px"
            }}>
              <div>
                <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)" }}>
                  Event Record Inspection
                </h3>
                <span className="mono" style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>
                  ID: {selectedEvent.event_id}
                </span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Event Properties Grid */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "10px",
              marginBottom: "16px"
            }}>
              <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px", borderRadius: "6px", border: "1px solid var(--border)" }}>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Timestamp (UTC)</div>
                <div className="mono" style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px" }}>
                  {new Date(selectedEvent.timestamp).toUTCString()}
                </div>
              </div>
              <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px", borderRadius: "6px", border: "1px solid var(--border)" }}>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Event Type</div>
                <div style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px", fontWeight: "600" }}>
                  {selectedEvent.event_type}
                </div>
              </div>
              <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px", borderRadius: "6px", border: "1px solid var(--border)" }}>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Source Entity</div>
                <div style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px" }}>
                  {selectedEvent.source_entity}
                </div>
              </div>
              <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "10px", borderRadius: "6px", border: "1px solid var(--border)" }}>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Anomaly Score</div>
                <div style={{ fontSize: "12px", color: selectedEvent.is_anomalous ? "var(--rose-text)" : "var(--emerald-text)", marginTop: "2px", fontWeight: "600" }}>
                  {(selectedEvent.anomaly_score * 100).toFixed(0)}% ({selectedEvent.is_anomalous ? "Anomalous" : "Baseline"})
                </div>
              </div>
            </div>

            {/* Raw JSON Details Payload */}
            <div style={{ marginBottom: "16px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <div style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-main)" }}>
                  Extracted Normalized Payload (JSON)
                </div>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: "11px", padding: "4px 8px" }}
                  onClick={() => copyEventJson(selectedEvent)}
                >
                  {copiedModalJson ? <Check size={12} color="var(--emerald)" /> : <Copy size={12} />}
                  {copiedModalJson ? "Copied" : "Copy JSON"}
                </button>
              </div>

              <pre style={{
                backgroundColor: "var(--bg-code)",
                border: "1px solid var(--border)",
                padding: "12px",
                borderRadius: "var(--radius-sm)",
                fontSize: "11.5px",
                fontFamily: "var(--font-mono)",
                color: "var(--text-main)",
                maxHeight: "220px",
                overflowY: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all"
              }}>
                {JSON.stringify(selectedEvent.details, null, 2)}
              </pre>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button className="btn btn-secondary" onClick={() => setSelectedEvent(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
