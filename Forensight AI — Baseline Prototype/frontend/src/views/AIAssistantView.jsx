import React, { useState, useEffect, useRef } from "react";
import {
  Bot,
  Send,
  Sparkles,
  Link2,
  ShieldCheck,
  User,
  Loader2
} from "lucide-react";
import { queryAI } from "../services/api";

export default function AIAssistantView({ activeCase }) {
  const caseNum = activeCase?.case_number || "FS-2026-001";
  const [messages, setMessages] = useState([
    {
      sender: "ai",
      text: `Hello Examiner. I am your Forensight Assistant for Case ${caseNum}.\n\nAll my responses are grounded in normalized evidence artifacts (Windows Event logs, Sysmon, Registry hives, Volatility memory records, and Zeek network flows). Every claim is cited with verifiable Event IDs.\n\nHow can I assist your investigation?`,
      citations: [],
      confidence: 1.0,
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [inputText, setInputText] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (activeCase) {
      setMessages([
        {
          sender: "ai",
          text: `Hello Examiner. I am your Forensight Assistant for Case ${activeCase.case_number} (${activeCase.case_name || "Active Case"}).\n\nAll my responses are grounded in normalized evidence artifacts for this investigation. Every claim is cited with verifiable Event IDs.\n\nHow can I assist your investigation?`,
          citations: [],
          confidence: 1.0,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
    }
  }, [activeCase?.case_id]);

  const quickPrompts = [
    "Summarize the complete incident timeline and attack sequence",
    "Show suspicious PowerShell activity and commands",
    "Which evidence indicates registry persistence?",
    "Show network connections related to data exfiltration",
    "What credentials were targeted and harvested?"
  ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async (queryText) => {
    const textToSend = queryText || inputText;
    if (!textToSend.trim() || loading || !activeCase) return;

    const userMsg = {
      sender: "user",
      text: textToSend,
      timestamp: new Date().toLocaleTimeString()
    };
    setMessages((prev) => [...prev, userMsg]);
    setInputText("");
    setLoading(true);

    try {
      const res = await queryAI(activeCase.case_id, textToSend);
      const aiMsg = {
        sender: "ai",
        text: res.response,
        citations: res.citations || [],
        confidence: res.confidence_score || 0.90,
        timestamp: new Date().toLocaleTimeString()
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      const errorMsg = {
        sender: "ai",
        text: `Error connecting to AI service: ${err.message}. Please verify the backend API is active.`,
        citations: [],
        confidence: 0.0,
        timestamp: new Date().toLocaleTimeString()
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      padding: "24px 28px",
      maxWidth: "1200px",
      margin: "0 auto",
      width: "100%",
      height: "calc(100vh - 60px)",
      display: "flex",
      flexDirection: "column"
    }}>
      {/* Header */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "14px",
        flexShrink: 0,
        flexWrap: "wrap",
        gap: "10px"
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <Bot size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Evidence-Grounded AI Assistant
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Conversational investigative query engine citing verifiable Event IDs and timestamps.
          </p>
        </div>

        <span className="badge-tag badge-cyan">
          <ShieldCheck size={13} /> Evidence Grounded
        </span>
      </div>

      {/* Suggested Quick Queries */}
      <div style={{
        display: "flex",
        gap: "8px",
        overflowX: "auto",
        paddingBottom: "8px",
        marginBottom: "8px",
        flexShrink: 0
      }}>
        {quickPrompts.map((prompt, idx) => (
          <button
            key={idx}
            className="btn btn-secondary"
            style={{ fontSize: "11.5px", padding: "5px 11px", whiteSpace: "nowrap", borderRadius: "16px" }}
            onClick={() => handleSend(prompt)}
            disabled={loading}
          >
            <Sparkles size={12} color="var(--primary)" />
            {prompt}
          </button>
        ))}
      </div>

      {/* Chat Messages Stream */}
      <div className="forensic-card" style={{
        flex: 1,
        overflowY: "auto",
        display: "flex",
        flexDirection: "column",
        gap: "16px",
        padding: "18px 20px",
        marginBottom: "14px"
      }}>
        {messages.map((m, idx) => {
          const isUser = m.sender === "user";

          return (
            <div
              key={idx}
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: isUser ? "flex-end" : "flex-start",
                gap: "5px",
                maxWidth: "88%",
                alignSelf: isUser ? "flex-end" : "flex-start"
              }}
            >
              {/* Sender Name & Time */}
              <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "var(--text-muted)" }}>
                {isUser ? (
                  <>
                    <span>Examiner Rohan</span>
                    <User size={12} />
                  </>
                ) : (
                  <>
                    <Bot size={13} color="var(--primary)" />
                    <span style={{ color: "var(--primary-text)", fontWeight: "600" }}>Forensight Assistant</span>
                    {m.confidence > 0 && (
                      <span className="badge-tag badge-emerald" style={{ fontSize: "9.5px", padding: "1px 5px" }}>
                        Confidence: {(m.confidence * 100).toFixed(0)}%
                      </span>
                    )}
                  </>
                )}
                <span>• {m.timestamp}</span>
              </div>

              {/* Message Bubble */}
              <div style={{
                backgroundColor: isUser ? "var(--primary-subtle)" : "var(--bg-card-subtle)",
                border: `1px solid ${isUser ? "var(--primary-border)" : "var(--border)"}`,
                borderRadius: "var(--radius-md)",
                padding: "14px 18px",
                fontSize: "13.5px",
                color: "var(--text-main)",
                lineHeight: "1.55",
                whiteSpace: "pre-wrap"
              }}>
                {m.text}

                {/* Citations */}
                {m.citations && m.citations.length > 0 && (
                  <div style={{ marginTop: "14px", borderTop: "1px solid var(--border)", paddingTop: "10px" }}>
                    <div style={{
                      fontSize: "11px",
                      fontWeight: "700",
                      color: "var(--primary-text)",
                      textTransform: "uppercase",
                      letterSpacing: "0.4px",
                      marginBottom: "6px",
                      display: "flex",
                      alignItems: "center",
                      gap: "5px"
                    }}>
                      <Link2 size={12} />
                      Verifiable Forensic Citations ({m.citations.length})
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                      {m.citations.map((c, cIdx) => (
                        <div
                          key={cIdx}
                          style={{
                            backgroundColor: "var(--bg-card)",
                            border: "1px solid var(--border)",
                            borderRadius: "var(--radius-sm)",
                            padding: "8px 10px",
                            fontSize: "11.5px"
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "2px" }}>
                            <span className="mono" style={{ color: "var(--primary-text)", fontWeight: "600" }}>
                              Event: {c.event_id ? `${c.event_id.substring(0, 8)}...` : "—"}
                            </span>
                            <span className="mono" style={{ color: "var(--emerald-text)" }}>
                              {c.timestamp}
                            </span>
                          </div>
                          <div style={{ color: "var(--text-dim)" }}>
                            <strong style={{ color: "var(--text-main)" }}>{c.source_entity}:</strong> {c.summary}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {loading && (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--primary-text)", fontSize: "12.5px" }}>
            <Loader2 size={15} className="spin" style={{ animation: "spin 0.8s linear infinite" }} />
            <span>Cross-correlating evidence artifacts and compiling citations...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Bar */}
      <div style={{ display: "flex", gap: "10px", flexShrink: 0 }}>
        <input
          type="text"
          className="input-control"
          style={{ flex: 1, padding: "10px 14px", fontSize: "13px" }}
          placeholder="Ask a question (e.g., 'Show encoded PowerShell commands', 'Which registry key was altered?')..."
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          disabled={loading}
        />
        <button
          className="btn btn-primary"
          style={{ padding: "0 18px" }}
          onClick={() => handleSend()}
          disabled={loading || !inputText.trim()}
        >
          <Send size={15} /> Send
        </button>
      </div>
    </div>
  );
}
