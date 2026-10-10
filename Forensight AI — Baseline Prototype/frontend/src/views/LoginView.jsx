import React, { useState } from "react";
import { Shield, Lock, Mail, ArrowRight, AlertCircle, Sparkles } from "lucide-react";
import { loginUser } from "../services/api";

export default function LoginView({ onLoginSuccess }) {
  const [email, setEmail] = useState("rohan.investigator@forensight.ai");
  const [password, setPassword] = useState("forensight2026");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    if (!email.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await loginUser(email, password || "forensight2026");
      if (res && res.user) {
        onLoginSuccess(res.user, res.token);
      }
    } catch (err) {
      setError(err.message || "Authentication failed. Check examiner credentials.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = async (demoEmail, _demoName) => {
    setLoading(true);
    setError(null);
    try {
      const res = await loginUser(demoEmail, "forensight2026");
      if (res && res.user) {
        onLoginSuccess(res.user, res.token);
      } else {
        throw new Error("No user profile returned from auth service");
      }
    } catch (err) {
      setError(`Authentication failed: ${err.message}. Ensure backend is running.`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      backgroundColor: "var(--bg-app)",
      padding: "24px"
    }}>
      <div style={{
        maxWidth: "440px",
        width: "100%",
        display: "flex",
        flexDirection: "column",
        gap: "18px"
      }}>
        {/* Brand Header */}
        <div style={{ textAlign: "center", marginBottom: "4px" }}>
          <div style={{
            width: "48px",
            height: "48px",
            borderRadius: "12px",
            backgroundColor: "var(--primary)",
            color: "#ffffff",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            marginBottom: "12px",
            boxShadow: "0 8px 16px -4px rgba(59, 130, 246, 0.4)"
          }}>
            <Shield size={26} />
          </div>
          <h1 style={{ fontSize: "23px", fontWeight: "800", color: "var(--text-main)", letterSpacing: "-0.4px" }}>
            Forensight
          </h1>
          <p style={{ fontSize: "13px", color: "var(--text-muted)", marginTop: "3px" }}>
            Digital Forensic & Incident Response Investigation Platform
          </p>
        </div>

        {/* 1-Click Fast Login for Evaluators */}
        <button
          type="button"
          onClick={() => handleQuickLogin("rohan.investigator@forensight.ai", "Rohan Johny")}
          disabled={loading}
          style={{
            backgroundColor: "var(--primary)",
            color: "#ffffff",
            border: "none",
            borderRadius: "var(--radius-md)",
            padding: "13px 18px",
            fontSize: "13.5px",
            fontWeight: "700",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "9px",
            boxShadow: "0 4px 12px rgba(59, 130, 246, 0.3)",
            transition: "all 0.15s ease"
          }}
        >
          <Sparkles size={16} />
          <span>Quick Sign In: Lead Examiner (Rohan Johny)</span>
          <ArrowRight size={15} />
        </button>

        {/* Divider */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", margin: "2px 0" }}>
          <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600", textTransform: "uppercase" }}>
            Or Enter Credentials
          </span>
          <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
        </div>

        {/* Login Form Card */}
        <div className="forensic-card" style={{ padding: "22px 24px" }}>
          <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
            {error && (
              <div style={{
                backgroundColor: "var(--rose-subtle)",
                border: "1px solid var(--rose-border)",
                borderRadius: "var(--radius-sm)",
                padding: "10px 12px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                fontSize: "12.5px",
                color: "var(--rose-text)"
              }}>
                <AlertCircle size={15} style={{ flexShrink: 0 }} />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                EXAMINER EMAIL / ID
              </label>
              <div style={{ position: "relative" }}>
                <Mail size={15} color="var(--text-muted)" style={{ position: "absolute", left: "12px", top: "11px" }} />
                <input
                  type="email"
                  className="input-control"
                  style={{ width: "100%", paddingLeft: "36px" }}
                  placeholder="rohan.investigator@forensight.ai"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            </div>

            <div>
              <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                ACCESS TOKEN / PASSWORD
              </label>
              <div style={{ position: "relative" }}>
                <Lock size={15} color="var(--text-muted)" style={{ position: "absolute", left: "12px", top: "11px" }} />
                <input
                  type="password"
                  className="input-control"
                  style={{ width: "100%", paddingLeft: "36px" }}
                  placeholder="forensight2026"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-secondary"
              style={{ width: "100%", padding: "10px", fontSize: "13px", marginTop: "2px" }}
              disabled={loading}
            >
              {loading ? "Authenticating..." : "Enter Investigation Platform"}
            </button>
          </form>
        </div>

        {/* Security attestation footer */}
        <div style={{
          textAlign: "center",
          fontSize: "11px",
          color: "var(--text-muted)",
          display: "flex",
          justifyContent: "center",
          gap: "14px"
        }}>
          <span>ISO/IEC 27037 Compliant</span>
          <span>•</span>
          <span>AES-256-GCM Vault</span>
          <span>•</span>
          <span>Immutable Ledger</span>
        </div>
      </div>
    </div>
  );
}
