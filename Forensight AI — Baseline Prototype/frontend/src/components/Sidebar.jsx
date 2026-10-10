import React from "react";
import {
  LayoutDashboard,
  FolderCheck,
  UploadCloud,
  HardDrive,
  Activity,
  FileCode,
  Layers,
  Clock,
  AlertTriangle,
  Bot,
  GitFork,
  GitBranch,
  ShieldCheck,
  CheckCircle2,
  FileLock2,
  FileText,
  Shield,
  UserCheck
} from "lucide-react";

export default function Sidebar({ currentTab, setCurrentTab, stats, stagesCount, user, onLogout }) {
  const menuSections = [
    {
      title: "Core Operations",
      items: [
        { id: "dashboard", label: "Overview", icon: LayoutDashboard, badge: null },
        { id: "cases", label: "Case Management", icon: FolderCheck, badge: null }
      ]
    },
    {
      title: "Evidence & Processing",
      items: [
        { id: "evidence_upload", label: "Evidence Acquisition", icon: UploadCloud, badge: null },
        { id: "evidence", label: "Evidence Vault", icon: HardDrive, badge: stats?.evidence_count },
        { id: "processing", label: "Processing Status", icon: Activity, badge: null },
        { id: "artifacts", label: "Artifact Explorer", icon: FileCode, badge: null },
        { id: "normalization", label: "Event Normalization", icon: Layers, badge: null }
      ]
    },
    {
      title: "Analysis & Intelligence",
      items: [
        { id: "timeline", label: "Forensic Timeline", icon: Clock, badge: stats?.event_count },
        { id: "anomaly_detection", label: "Anomaly Detection", icon: AlertTriangle, badge: stats?.anomalous_events_count },
        { id: "ai_assistant", label: "AI Assistant", icon: Bot, badge: null },
        { id: "correlation_graph", label: "Correlation Graph", icon: GitFork, badge: null },
        { id: "attack_path", label: "Attack Path (MITRE)", icon: GitBranch, badge: stagesCount ? `${stagesCount}` : null }
      ]
    },
    {
      title: "Governance & Reports",
      items: [
        { id: "validation", label: "Validation Gate", icon: ShieldCheck, badge: stats ? `${stats.validated_findings}/${stats.total_findings}` : null },
        { id: "findings", label: "Findings Summary", icon: CheckCircle2, badge: stats?.total_findings },
        { id: "reports", label: "Reports & Vault", icon: FileLock2, badge: stats?.finalized_reports },
        { id: "audit_log", label: "Chain of Custody", icon: FileText, badge: null }
      ]
    }
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div style={{
        padding: "16px 18px",
        borderBottom: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        gap: "10px"
      }}>
        <div style={{
          width: "32px",
          height: "32px",
          borderRadius: "6px",
          backgroundColor: "var(--primary)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "#ffffff",
          flexShrink: 0
        }}>
          <Shield size={18} />
        </div>
        <div>
          <div style={{
            fontSize: "15px",
            fontWeight: "700",
            letterSpacing: "0.2px",
            color: "var(--text-main)"
          }}>
            Forensight
          </div>
          <div style={{
            fontSize: "11px",
            color: "var(--text-muted)"
          }}>
            Investigation Platform
          </div>
        </div>
      </div>

      {/* Navigation Sections */}
      <div style={{ padding: "10px 0", flex: 1, overflowY: "auto" }}>
        {menuSections.map((section, sIdx) => (
          <div key={sIdx} style={{ marginBottom: "12px" }}>
            <div style={{
              padding: "4px 18px 4px 18px",
              fontSize: "10.5px",
              fontWeight: "700",
              color: "var(--text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.6px"
            }}>
              {section.title}
            </div>

            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <div
                  key={item.id}
                  className={`nav-item ${isActive ? "active" : ""}`}
                  onClick={() => setCurrentTab(item.id)}
                  style={{ padding: "7px 12px", margin: "1px 8px", fontSize: "12.5px" }}
                >
                  <Icon size={16} color={isActive ? "var(--primary)" : "var(--text-muted)"} />
                  <span style={{ flex: 1 }}>{item.label}</span>
                  {item.badge !== null && item.badge !== undefined && (
                    <span style={{
                      fontSize: "10px",
                      padding: "1px 5px",
                      borderRadius: "4px",
                      backgroundColor: isActive ? "var(--primary-subtle)" : "var(--bg-card-subtle)",
                      color: isActive ? "var(--primary-text)" : "var(--text-muted)",
                      fontWeight: "600",
                      fontFamily: "var(--font-mono)"
                    }}>
                      {item.badge}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* Analyst Status Footer */}
      <div style={{
        padding: "12px 16px",
        borderTop: "1px solid var(--border)",
        backgroundColor: "var(--bg-card-subtle)"
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", overflow: "hidden" }}>
            <UserCheck size={15} color="var(--emerald)" style={{ flexShrink: 0 }} />
            <div style={{ overflow: "hidden" }}>
              <div style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-main)", whiteSpace: "nowrap", textOverflow: "ellipsis", overflow: "hidden" }}>
                {user?.name || "Rohan Johny"}
              </div>
              <div style={{ fontSize: "10.5px", color: "var(--text-muted)" }}>
                {user?.role || "Lead Forensic Examiner"}
              </div>
            </div>
          </div>
          {onLogout && (
            <button
              onClick={onLogout}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "var(--text-muted)",
                fontSize: "11px",
                fontWeight: "600",
                padding: "2px 6px"
              }}
              title="Log out of session"
            >
              Exit
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
