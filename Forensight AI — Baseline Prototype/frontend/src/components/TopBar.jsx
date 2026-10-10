import React from "react";
import {
  FolderCheck,
  ShieldAlert,
  Sparkles,
  Sun,
  Moon,
  RotateCcw,
  Search,
  Edit3
} from "lucide-react";

export default function TopBar({
  activeCase,
  cases,
  onSelectCase,
  onReseed,
  onCorrelate,
  isCorrelating,
  theme,
  toggleTheme,
  onOpenSearch,
  onOpenNotes,
  currentTab
}) {
  const getTabLabel = (tab) => {
    switch (tab) {
      case "dashboard": return "Overview";
      case "cases": return "Case Management";
      case "evidence_upload": return "Evidence Acquisition";
      case "evidence": return "Evidence Vault";
      case "processing": return "Processing Engines";
      case "artifacts": return "Artifact Explorer";
      case "normalization": return "Event Normalization";
      case "timeline": return "Forensic Timeline";
      case "anomaly_detection": return "Anomaly Detection";
      case "ai_assistant": return "AI Assistant";
      case "correlation_graph": return "Correlation Graph";
      case "attack_path": return "MITRE Attack Path";
      case "validation": return "Validation Gate";
      case "findings": return "Findings Summary";
      case "reports": return "Reports & Vault";
      case "audit_log": return "Chain of Custody";
      default: return tab;
    }
  };

  return (
    <header className="top-header">
      {/* Active Case Selector */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
        {cases && cases.length > 1 ? (
          <div style={{ position: "relative" }}>
            <select
              className="input-control"
              style={{
                fontSize: "12px",
                fontWeight: "700",
                color: "var(--primary-text)",
                padding: "5px 24px 5px 10px",
                backgroundColor: "var(--bg-card-subtle)"
              }}
              value={activeCase?.case_id || ""}
              onChange={(e) => {
                const found = cases.find(c => c.case_id === e.target.value);
                if (found) onSelectCase(found);
              }}
            >
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id}>
                  {c.case_number}: {c.case_name}
                </option>
              ))}
            </select>
          </div>
        ) : activeCase ? (
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            backgroundColor: "var(--bg-card-subtle)",
            border: "1px solid var(--border)",
            padding: "5px 10px",
            borderRadius: "var(--radius-sm)",
            maxWidth: "520px",
            overflow: "hidden"
          }}>
            <FolderCheck size={14} color="var(--primary)" style={{ flexShrink: 0 }} />
            <span style={{
              fontSize: "12px",
              fontWeight: "700",
              color: "var(--primary-text)",
              fontFamily: "var(--font-mono)",
              flexShrink: 0
            }}>
              {activeCase.case_number}
            </span>
            <span style={{ color: "var(--border-strong)", fontSize: "11px" }}>|</span>
            <span style={{
              fontSize: "12px",
              fontWeight: "600",
              color: "var(--text-main)",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis"
            }}>
              {activeCase.case_name}
            </span>
          </div>
        ) : (
          <div style={{ fontSize: "12.5px", color: "var(--text-muted)" }}>
            Loading case data...
          </div>
        )}

        {activeCase && (
          <span className="badge-tag badge-rose" style={{ fontSize: "10.5px" }}>
            <ShieldAlert size={11} />
            {activeCase.status}
          </span>
        )}

        {currentTab && (
          <span className="badge-tag badge-cyan" style={{ fontSize: "10.5px", fontWeight: "600" }}>
            {getTabLabel(currentTab)}
          </span>
        )}
      </div>

      {/* Right Controls: Global Search, Notes, Theme Toggle & Actions */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
        {/* Case-Wide Search Button */}
        <button
          className="btn btn-secondary"
          onClick={onOpenSearch}
          title="Case-wide search across evidence, artifacts, events, and reports"
          style={{ fontSize: "12px", padding: "5px 10px" }}
        >
          <Search size={13} color="var(--primary)" />
          <span>Search</span>
        </button>

        {/* Examiner Notes Drawer Toggle */}
        <button
          className="btn btn-secondary"
          onClick={onOpenNotes}
          title="Examiner Notes throughout investigation"
          style={{ fontSize: "12px", padding: "5px 10px" }}
        >
          <Edit3 size={13} color="var(--text-muted)" />
          <span>Notes</span>
        </button>

        {/* Light / Dark Mode Switch */}
        <button
          className="theme-toggle-btn"
          onClick={toggleTheme}
          title={`Switch to ${theme === "light" ? "Dark" : "Light"} mode`}
          aria-label="Toggle theme"
          style={{ fontSize: "12px", padding: "5px 9px" }}
        >
          {theme === "light" ? (
            <>
              <Moon size={13} color="var(--text-dim)" />
              <span>Dark</span>
            </>
          ) : (
            <>
              <Sun size={13} color="#f59e0b" />
              <span>Light</span>
            </>
          )}
        </button>

        <button
          className="btn btn-secondary"
          onClick={onCorrelate}
          disabled={isCorrelating}
          title="Run behavioral anomaly correlation"
          style={{ fontSize: "12px", padding: "5px 10px" }}
        >
          <Sparkles size={13} color="var(--primary)" />
          {isCorrelating ? "Correlating..." : "Correlate"}
        </button>

        <button
          className="btn btn-secondary"
          onClick={onReseed}
          title="Reset demo case dataset to initial state"
          style={{ fontSize: "12px", padding: "5px 10px" }}
        >
          <RotateCcw size={13} />
          Reset Demo
        </button>
      </div>
    </header>
  );
}
