import { useState } from "react";

type MappingMatch = {
  control_id?: string;
  description?: string;
  technique_id?: string;
  name?: string;
  score?: number;
};

type MappingResp = {
  type: "mapping";
  direction: "MITRE→NIST" | "NIST→MITRE";
  query: any;
  matches: MappingMatch[];
};

type QAItem = {
  control_id?: string;
  description?: string;
  family?: string;
  technique_id?: string;
  name?: string;
  tactics?: string[];
  score: number;
};

type QAResp = {
  type: "qa";
  answer: string;
  nist_candidates: QAItem[];
  mitre_candidates: QAItem[];
};

type AuditFinding = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  remediation: string;
  description?: string;
  standard_refs?: string[];
  score?: number;
};

type AuditResp = {
  type: "audit_result";
  data: {
    overall_score: number;
    risk_level: "low" | "moderate" | "elevated" | "high";
    findings: AuditFinding[];
    summary: string;
  };
};

type ApiResp = MappingResp | QAResp | AuditResp;

const BASE_URL = "http://127.0.0.1:8000"; // change if you reverse-proxy

export default function ChatPanel() {
  const [mode, setMode] = useState<"" | "map" | "audit">("");
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resp, setResp] = useState<ApiResp | null>(null);

  const send = async () => {
    const message = input.trim();
    if (!message) return;

    setLoading(true);
    setError(null);
    setResp(null);
    try {
      const r = await fetch(`${BASE_URL}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, mode: mode || undefined, top_k: 5 }),
      });
      if (!r.ok) throw new Error(await r.text());
      const json = (await r.json()) as ApiResp;
      setResp(json);
    } catch (e: any) {
      setError(e?.message || "Request failed");
    } finally {
      setLoading(false);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: 16, marginTop: 24 }}>
      <h2 style={{ marginTop: 0 }}>Chatbot (MITRE↔NIST + Audit)</h2>

      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
        <label style={{ fontSize: 12, color: "#6b7280" }}>Mode</label>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as any)}
          style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid #e5e7eb" }}
        >
          <option value="">auto</option>
          <option value="map">map</option>
          <option value="audit">audit</option>
        </select>
        <div style={{ fontSize: 12, color: "#6b7280" }}>
          Try <code>T1059</code>, <code>AC-2</code>, or <code>audit {"{...json...}"}</code>
        </div>
      </div>

      {/* Input: single-line for map/qa; multiline is handy for audit JSON */}
      {mode === "audit" ? (
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={`audit {"policy": {"min_length": 10}, "mfa_factors": {"sms": true, "totp_app": false}, "mfa_enforcement": {"required_for_admins": false}}`}
          rows={4}
          style={{ width: "100%", padding: "8px 10px", borderRadius: 6, border: "1px solid #e5e7eb", fontFamily: "monospace" }}
        />
      ) : (
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder='e.g., "T1059", "AC-2", or a free-text question'
          style={{ width: "100%", padding: "8px 10px", borderRadius: 6, border: "1px solid #e5e7eb" }}
        />
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button onClick={send} disabled={loading} style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid #111827", background: "#111827", color: "#fff" }}>
          {loading ? "Sending…" : "Send"}
        </button>
        <button onClick={() => { setInput(""); setResp(null); setError(null); }} style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid #e5e7eb", background: "#f3f4f6" }}>
          Clear
        </button>
      </div>

      {/* Status */}
      {error && <div style={{ color: "#b91c1c", marginTop: 8 }}>{error}</div>}
      {loading && !error && <div style={{ color: "#6b7280", marginTop: 8 }}>Thinking…</div>}

      {/* Results */}
      {!loading && resp?.type === "mapping" && (
        <div style={{ marginTop: 16 }}>
          <div style={{ color: "#6b7280", fontSize: 12 }}>{resp.direction}</div>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 8 }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", borderBottom: "1px solid #e5e7eb", padding: 8 }}>ID / Name</th>
                <th style={{ textAlign: "left", borderBottom: "1px solid #e5e7eb", padding: 8 }}>Description</th>
                <th style={{ textAlign: "left", borderBottom: "1px solid #e5e7eb", padding: 8 }}>Score</th>
              </tr>
            </thead>
            <tbody>
              {resp.matches.map((m, i) => (
                <tr key={i}>
                  <td style={{ padding: 8, borderTop: "1px solid #e5e7eb" }}>
                    {(m.control_id || m.technique_id) ?? "—"} {m.name ? `— ${m.name}` : ""}
                  </td>
                  <td style={{ padding: 8, borderTop: "1px solid #e5e7eb" }}>{m.description ?? "—"}</td>
                  <td style={{ padding: 8, borderTop: "1px solid #e5e7eb" }}>{typeof m.score === "number" ? m.score.toFixed(2) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && resp?.type === "qa" && (
        <div style={{ marginTop: 16, display: "grid", gap: 16 }}>
          <div style={{ fontWeight: 600 }}>{resp.answer}</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: 12 }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>NIST candidates</div>
              {resp.nist_candidates.length ? (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {resp.nist_candidates.map((c, i) => (
                    <li key={i} style={{ margin: "6px 0" }}>
                      <div><strong>{c.control_id}</strong> — {c.description}</div>
                      <div style={{ color: "#6b7280", fontSize: 12 }}>
                        family: {c.family ?? "—"} • score: {c.score.toFixed(2)}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : <div style={{ color: "#6b7280" }}>No NIST matches.</div>}
            </div>

            <div style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: 12 }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>MITRE candidates</div>
              {resp.mitre_candidates.length ? (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {resp.mitre_candidates.map((c, i) => (
                    <li key={i} style={{ margin: "6px 0" }}>
                      <div><strong>{c.technique_id}</strong> — {c.name}</div>
                      <div style={{ color: "#6b7280", fontSize: 12 }}>
                        tactics: {Array.isArray(c.tactics) && c.tactics.length ? c.tactics.join(", ") : "—"} • score: {c.score.toFixed(2)}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : <div style={{ color: "#6b7280" }}>No MITRE matches.</div>}
            </div>
          </div>
        </div>
      )}

      {!loading && resp?.type === "audit_result" && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontWeight: 600 }}>Risk: {resp.data.risk_level} (score {resp.data.overall_score})</div>
          <div style={{ color: "#6b7280", marginTop: 4 }}>{resp.data.summary}</div>

          <div style={{ marginTop: 12, border: "1px solid #e5e7eb", borderRadius: 8, padding: 12 }}>
            <div style={{ fontWeight: 600, marginBottom: 8 }}>Findings</div>
            {resp.data.findings?.length ? (
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {resp.data.findings.map((f) => (
                  <li key={f.id} style={{ margin: "6px 0" }}>
                    <div><strong>{f.severity.toUpperCase()}</strong> — {f.title}</div>
                    <div style={{ color: "#6b7280", fontSize: 12 }}>{f.remediation}</div>
                    {f.standard_refs?.length ? (
                      <div style={{ color: "#6b7280", fontSize: 12 }}>refs: {f.standard_refs.join(", ")}</div>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <div style={{ color: "#6b7280" }}>No findings.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
