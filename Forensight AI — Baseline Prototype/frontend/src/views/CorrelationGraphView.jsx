import {
  GitFork,
  Info
} from "lucide-react";

export default function CorrelationGraphView({ _activeCase }) {
  const [selectedFilter, setSelectedFilter] = useState("ALL");
  const [selectedNode, setSelectedNode] = useState(null);

  const nodes = [
    { id: "user_jdoe", label: "CORP\\jdoe", type: "USER", threat: "COMPROMISED", x: 100, y: 160, details: "Compromised standard domain user account utilized for weaponized macro execution." },
    { id: "host_wsfin04", label: "WS-FIN-04 (10.0.4.15)", type: "HOST", threat: "HIGH", x: 260, y: 160, details: "Target finance department workstation. Source of initial access and staging." },
    { id: "file_docm", label: "Invoice_Q3_Financials.docm", type: "FILE", threat: "MALICIOUS", x: 100, y: 310, details: "Initial access vector. Weaponized Office document with VBA dropper macro." },
    { id: "proc_winword", label: "WINWORD.EXE (PID: 4820)", type: "PROCESS", threat: "EXPLOITED", x: 260, y: 310, details: "Parent process executing weaponized document macro." },
    { id: "proc_powershell", label: "powershell.exe (PID: 5912)", type: "PROCESS", threat: "CRITICAL", x: 440, y: 310, details: "Encoded in-memory PowerShell stager bypassing standard script-block logging." },
    { id: "reg_run", label: "HKCU\\...\\Run\\WindowsUpdate", type: "REGISTRY", threat: "MALICIOUS", x: 440, y: 140, details: "Persistence registry key established to maintain reboot survivability." },
    { id: "proc_lsass", label: "lsass.exe (PID: 680)", type: "PROCESS", threat: "TARGET", x: 620, y: 220, details: "Target of credential extraction via injected memory read." },
    { id: "file_archive", label: "fin_archive.zip (84.5 MB)", type: "FILE", threat: "STAGED", x: 620, y: 390, details: "Encrypted ZIP archive staging proprietary financial reports and executive ledger." },
    { id: "net_c2", label: "198.51.100.45:443 (C2)", type: "NETWORK", threat: "ADVERSARY", x: 800, y: 390, details: "External Command and Control server receiving encrypted exfiltrated data archive." },
    { id: "host_dccorp", label: "DC-CORP-01 (10.0.4.2)", type: "HOST", threat: "LATERAL_TARGET", x: 800, y: 220, details: "Domain Controller targeted via SMB Admin$ lateral movement attempt." }
  ];

  const edges = [
    { from: "user_jdoe", to: "host_wsfin04", label: "LOGON_SESSION" },
    { from: "user_jdoe", to: "file_docm", label: "OPENS_ATTACHMENT" },
    { from: "file_docm", to: "proc_winword", label: "SPAWNED_BY" },
    { from: "proc_winword", to: "proc_powershell", label: "EXECUTES_SUBPROCESS" },
    { from: "proc_powershell", to: "reg_run", label: "CREATES_PERSISTENCE" },
    { from: "proc_powershell", to: "proc_lsass", label: "DUMPS_CREDENTIALS" },
    { from: "proc_powershell", to: "file_archive", label: "COMPRESSES_DATA" },
    { from: "proc_powershell", to: "host_dccorp", label: "SMB_ADMIN_CONNECT" },
    { from: "file_archive", to: "net_c2", label: "EXFILTRATES_TLS" },
    { from: "host_wsfin04", to: "net_c2", label: "TCP_PORT_443" }
  ];

  const getNodeColor = (type) => {
    switch (type) {
      case "USER": return "var(--indigo)";
      case "HOST": return "var(--cyan)";
      case "PROCESS": return "var(--rose)";
      case "FILE": return "var(--amber)";
      case "REGISTRY": return "var(--purple)";
      case "NETWORK": return "var(--rose)";
      default: return "var(--primary)";
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
            <GitFork size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Interactive Forensic Correlation Graph
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Visual graph mapping cross-artifact entity correlations between users, processes, files, hosts, and network streams.
          </p>
        </div>

        <span className="badge-tag badge-cyan">
          {nodes.length} Correlated Entities • {edges.length} Relationships
        </span>
      </div>

      {/* Filter Bar */}
      <div className="forensic-card" style={{ padding: "12px 16px", marginBottom: "18px" }}>
        <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)" }}>FILTER ENTITIES:</span>
          {["ALL", "PROCESS", "FILE", "NETWORK", "USER", "HOST", "REGISTRY"].map((type) => (
            <button
              key={type}
              className={`btn ${selectedFilter === type ? "btn-primary" : "btn-secondary"}`}
              style={{ fontSize: "11px", padding: "4px 9px" }}
              onClick={() => setSelectedFilter(type)}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* Graph Visual Canvas and Details Drawer */}
      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: "20px", marginBottom: "24px" }}>
        {/* SVG Graph Canvas */}
        <div className="forensic-card" style={{ padding: "16px", minHeight: "520px", display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
            <Info size={14} /> Click any entity node to inspect its forensic relationships and linked events.
          </div>

          <div style={{
            flex: 1,
            backgroundColor: "var(--bg-card-subtle)",
            borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)",
            position: "relative",
            overflow: "hidden",
            minHeight: "440px"
          }}>
            <svg style={{ width: "100%", height: "100%", minHeight: "440px" }}>
              <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--border-strong)" />
                </marker>
              </defs>

              {/* Render Connecting Edges */}
              {edges.map((e, idx) => {
                const source = nodes.find((n) => n.id === e.from);
                const target = nodes.find((n) => n.id === e.to);
                if (!source || !target) return null;

                const isConnected = selectedNode?.id === source.id || selectedNode?.id === target.id;

                return (
                  <g key={idx}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke={isConnected ? "var(--primary)" : "var(--border-strong)"}
                      strokeWidth={isConnected ? "2.5" : "1.5"}
                      strokeDasharray={isConnected ? "none" : "3,3"}
                      markerEnd="url(#arrow)"
                    />
                    <text
                      x={(source.x + target.x) / 2}
                      y={(source.y + target.y) / 2 - 4}
                      fill="var(--text-muted)"
                      fontSize="9"
                      fontFamily="var(--font-mono)"
                      textAnchor="middle"
                    >
                      {e.label}
                    </text>
                  </g>
                );
              })}

              {/* Render Nodes */}
              {nodes.map((node) => {
                const isSelected = selectedNode?.id === node.id;
                const isDimmed = selectedFilter !== "ALL" && node.type !== selectedFilter;
                const color = getNodeColor(node.type);

                return (
                  <g
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    style={{ cursor: "pointer", opacity: isDimmed ? 0.3 : 1 }}
                  >
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={isSelected ? 18 : 14}
                      fill="var(--bg-card)"
                      stroke={color}
                      strokeWidth={isSelected ? 3 : 2}
                    />
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={6}
                      fill={color}
                    />
                    <text
                      x={node.x}
                      y={node.y + 25}
                      fill="var(--text-main)"
                      fontSize="10.5"
                      fontWeight={isSelected ? "700" : "600"}
                      fontFamily="var(--font-sans)"
                      textAnchor="middle"
                    >
                      {node.label.length > 22 ? node.label.substring(0, 20) + "..." : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Selected Entity Inspection Drawer */}
        <div className="forensic-card" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)" }}>
            Entity Forensic Attributes
          </h3>

          {selectedNode ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{
                backgroundColor: "var(--bg-card-subtle)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "14px"
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                  <span className="badge-tag badge-cyan" style={{ fontSize: "10px" }}>
                    {selectedNode.type}
                  </span>
                  <span className="badge-tag badge-rose" style={{ fontSize: "10px" }}>
                    Threat: {selectedNode.threat}
                  </span>
                </div>
                <div style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)" }}>
                  {selectedNode.label}
                </div>
                <p style={{ fontSize: "12.5px", color: "var(--text-dim)", lineHeight: "1.5", marginTop: "8px" }}>
                  {selectedNode.details}
                </p>
              </div>

              <div>
                <div style={{ fontSize: "11.5px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "8px" }}>
                  CORRELATED GRAPH RELATIONSHIPS
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {edges
                    .filter((e) => e.from === selectedNode.id || e.to === selectedNode.id)
                    .map((e, idx) => {
                      const otherId = e.from === selectedNode.id ? e.to : e.from;
                      const otherNode = nodes.find((n) => n.id === otherId);
                      const isOutgoing = e.from === selectedNode.id;

                      return (
                        <div
                          key={idx}
                          style={{
                            backgroundColor: "var(--bg-code)",
                            border: "1px solid var(--border)",
                            padding: "8px 10px",
                            borderRadius: "4px",
                            fontSize: "11.5px",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center"
                          }}
                        >
                          <span className="mono" style={{ color: "var(--primary-text)", fontWeight: "600" }}>
                            {e.label}
                          </span>
                          <span style={{ color: "var(--text-dim)" }}>
                            {isOutgoing ? "➔ " : "⬅ "} {otherNode?.label}
                          </span>
                        </div>
                      );
                    })}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)", fontSize: "13px" }}>
              Click any node in the correlation graph to view connected artifacts, process trees, and threat intelligence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
