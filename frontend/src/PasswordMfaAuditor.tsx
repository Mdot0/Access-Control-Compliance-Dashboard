// src/PasswordMfaAuditor.tsx
import { useState } from "react";

type Finding = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  score: number;
  description: string;
  remediation: string;
  standard_refs: string[];
};

// --- helpers: pretty fields & checkboxes ---
function Field({
  label,
  hint,
  children,
}: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="text-gray-200 dark:text-gray-300">{label}</span>
      {hint && <span className="ml-2 text-xs text-gray-500">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

function Textbox(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={[
        "w-full rounded-xl border",
        "border-gray-300 dark:border-gray-700",
        "bg-white dark:bg-zinc-900",
        "px-3 py-2 text-sm shadow-sm",
        "placeholder-gray-400",
        "focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500",
        props.className || "",
      ].join(" ")}
    />
  );
}

function Check({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <label className="inline-flex items-center gap-2 text-sm select-none">
      <input
        type="checkbox"
        className="h-4 w-4 rounded-sm border-gray-300 dark:border-gray-600
                   accent-indigo-600 focus:outline-none focus:ring-2
                   focus:ring-indigo-500"
        checked={checked}
        onChange={onChange}
      />
      <span className="text-gray-200 dark:text-gray-300">{label}</span>
    </label>
  );
}

export default function PasswordMfaAuditor() {
  const [payload, setPayload] = useState({
    policy: {
      min_length: 12,
      require_upper: true,
      require_lower: true,
      require_digit: true,
      require_symbol: false,
      history_prevent_reuse: 5,
      lockout_threshold: 10,
      lockout_window_minutes: 15,
      lockout_duration_minutes: 15,
      dictionary_check_enabled: true,
      blocklist_enabled: true,
    },
    mfa_factors: {
      sms: false,
      totp_app: true,
      fido2_webauthn: false,
      push_approval: false,
      email_otp: false,
    },
    mfa_enforcement: {
      required_for_all_users: true,
      required_for_admins: true,
      conditional_by_risk: false,
      number_matching_enabled: true,
      device_binding_enabled: true,
      push_rate_limit_per_minute: 2,
      mfa_bypass_days_after_password_reset: 0,
    },
    environment: "prod" as const,
    user_count: 500,
  });

  const [res, setRes] = useState<null | {
    overall_score: number;
    risk_level: string;
    summary: string;
    findings: Finding[];
  }>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function runAudit() {
    setLoading(true);
    setErr(null);
    setRes(null);
    try {
      const r = await fetch("/api/policy/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const t = await r.text();
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${t}`);
      setRes(JSON.parse(t));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl p-4 sm:p-6 space-y-6">
      <header>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">
          Password & MFA Auditor
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Evaluate password policies and MFA configurations; returns findings
          with remediation and risk scoring.
        </p>
      </header>

      {/* Password policy */}
      <div className="rounded-2xl border p-4 space-y-3">
        <h2 className="font-medium">Password policy</h2>

        <div className="grid sm:grid-cols-3 gap-3">
          <Field label="Min length">
            <Textbox
              type="number"
              min={4}
              value={payload.policy.min_length}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  policy: { ...p.policy, min_length: +e.target.value },
                }))
              }
            />
          </Field>

          <Field label="Lockout threshold" hint="attempts">
            <Textbox
              type="number"
              min={0}
              value={payload.policy.lockout_threshold ?? 0}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  policy: { ...p.policy, lockout_threshold: +e.target.value },
                }))
              }
            />
          </Field>

          <Field label="Duration" hint="minutes">
            <Textbox
              type="number"
              min={0}
              value={payload.policy.lockout_duration_minutes ?? 0}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  policy: {
                    ...p.policy,
                    lockout_duration_minutes: +e.target.value,
                  },
                }))
              }
            />
          </Field>
        </div>

        <div className="flex flex-wrap gap-3">
          {[
            ["Upper", "require_upper"],
            ["Lower", "require_lower"],
            ["Digit", "require_digit"],
            ["Symbol", "require_symbol"],
            ["Dict check", "dictionary_check_enabled"],
            ["Blocklist", "blocklist_enabled"],
          ].map(([label, key]) => (
            <Check
              key={key}
              label={label}
              checked={(payload.policy as any)[key]}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  policy: { ...p.policy, [key]: e.target.checked } as any,
                }))
              }
            />
          ))}
        </div>
      </div>

      {/* MFA factors */}
      <div className="rounded-2xl border p-4 space-y-2">
        <h2 className="font-medium">MFA factors</h2>
        <div className="flex flex-wrap gap-3">
          {[
            ["SMS", "sms"],
            ["Authenticator app (TOTP)", "totp_app"],
            ["WebAuthn (FIDO2)", "fido2_webauthn"],
            ["Push approval", "push_approval"],
            ["Email OTP", "email_otp"],
          ].map(([label, key]) => (
            <Check
              key={key}
              label={label}
              checked={(payload.mfa_factors as any)[key]}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  mfa_factors: {
                    ...p.mfa_factors,
                    [key]: e.target.checked,
                  } as any,
                }))
              }
            />
          ))}
        </div>
      </div>

      {/* MFA enforcement */}
      <div className="rounded-2xl border p-4 space-y-2">
        <h2 className="font-medium">MFA enforcement</h2>
        <div className="flex flex-wrap gap-3">
          {[
            ["Require for all users", "required_for_all_users"],
            ["Require for admins", "required_for_admins"],
            ["Conditional by risk", "conditional_by_risk"],
            ["Number matching", "number_matching_enabled"],
            ["Device binding", "device_binding_enabled"],
          ].map(([label, key]) => (
            <Check
              key={key}
              label={label}
              checked={(payload.mfa_enforcement as any)[key]}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  mfa_enforcement: {
                    ...p.mfa_enforcement,
                    [key]: e.target.checked,
                  } as any,
                }))
              }
            />
          ))}
        </div>

        <div className="grid sm:grid-cols-2 gap-3 mt-2">
          <Field label="Push rate / min">
            <Textbox
              type="number"
              min={0}
              value={payload.mfa_enforcement.push_rate_limit_per_minute ?? 0}
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  mfa_enforcement: {
                    ...p.mfa_enforcement,
                    push_rate_limit_per_minute: +e.target.value,
                  },
                }))
              }
            />
          </Field>

          <Field label="MFA bypass days after PWD reset">
            <Textbox
              type="number"
              min={0}
              value={
                payload.mfa_enforcement.mfa_bypass_days_after_password_reset ?? 0
              }
              onChange={(e) =>
                setPayload((p) => ({
                  ...p,
                  mfa_enforcement: {
                    ...p.mfa_enforcement,
                    mfa_bypass_days_after_password_reset: +e.target.value,
                  },
                }))
              }
            />
          </Field>
        </div>
      </div>

      {/* Run audit */}
      <div>
        <button
          onClick={runAudit}
          disabled={loading}
          className="rounded-xl bg-indigo-600 text-white text-sm px-4 py-2 shadow hover:bg-indigo-700 disabled:opacity-60"
        >
          {loading ? "Auditing…" : "Run audit"}
        </button>
        {err && (
          <div className="mt-2 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {err}
          </div>
        )}
      </div>

      {/* Results */}
      {res && (
        <div className="rounded-2xl border p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-gray-500">Overall score</div>
              <div className="text-xl font-semibold">
                {res.overall_score.toFixed(3)} ({res.risk_level})
              </div>
            </div>
            <div className="w-48 h-3 bg-gray-100 rounded overflow-hidden">
              <div
                className="h-3 bg-green-500"
                style={{ width: `${Math.round(res.overall_score * 100)}%` }}
              />
            </div>
          </div>
          <p className="text-sm text-gray-700">{res.summary}</p>

          <h3 className="font-medium mt-2">Findings</h3>
          <ul className="space-y-2">
            {res.findings.map((f) => (
              <li key={f.id} className="rounded-xl border p-3">
                <div className="flex items-center justify-between">
                  <div className="font-medium">{f.title}</div>
                  <code className="text-xs bg-gray-100 rounded px-2 py-1">
                    {f.severity} • {f.score.toFixed(2)}
                  </code>
                </div>
                <p className="text-sm mt-1">{f.description}</p>
                <div className="text-sm mt-2">
                  <span className="font-medium">Remediation:</span>{" "}
                  {f.remediation}
                </div>
                {f.standard_refs?.length > 0 && (
                  <div className="text-xs text-gray-500 mt-2">
                    Refs: {f.standard_refs.join(", ")}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
