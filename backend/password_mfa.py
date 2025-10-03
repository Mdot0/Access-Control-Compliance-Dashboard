# backend/password_mfa.py
from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import List, Literal, Optional, Dict, Any

# --- define the router that api.py will import ---
router = APIRouter()

# ====== SCHEMAS (minimal, expand as needed) ======
class PasswordPolicy(BaseModel):
    min_length: int = Field(ge=0, default=12)
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = False
    history_prevent_reuse: int = 5
    lockout_threshold: Optional[int] = 10
    lockout_window_minutes: Optional[int] = 15
    lockout_duration_minutes: Optional[int] = 15
    dictionary_check_enabled: bool = True
    blocklist_enabled: bool = True

class MFAFactors(BaseModel):
    sms: bool = False
    totp_app: bool = True
    push_approval: bool = False
    fido2_webauthn: bool = False
    email_otp: bool = False

class MFAEnforcement(BaseModel):
    required_for_all_users: bool = True
    required_for_admins: bool = True
    conditional_by_risk: bool = False
    number_matching_enabled: bool = False
    device_binding_enabled: bool = False
    push_rate_limit_per_minute: Optional[int] = None

class PolicyInput(BaseModel):
    policy: PasswordPolicy
    mfa_factors: MFAFactors
    mfa_enforcement: MFAEnforcement
    environment: Literal["prod","staging","dev"] = "prod"
    user_count: Optional[int] = 0
    raw_policy_text: Optional[str] = None

class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["low","medium","high","critical"]
    description: str
    remediation: str
    standard_refs: List[str] = []
    evidence: Dict[str, Any] = {}
    score: float = 0.5

class AuditResponse(BaseModel):
    overall_score: float
    risk_level: Literal["low","moderate","elevated","high"]
    findings: List[Finding]
    summary: str

# ====== YOUR CORE AUDIT (put your ML/LLM use here) ======
def run_audit(inp: PolicyInput) -> AuditResponse:
    findings: List[Finding] = []

    # (sample rules — replace/augment with your real checks/ML)
    if inp.policy.min_length < 12:
        findings.append(Finding(
            id="PW_MINLEN", title="Password minimum length below 12",
            severity="high",
            description=f"Configured min length = {inp.policy.min_length}.",
            remediation="Increase to ≥ 12 (preferably 14+).",
            standard_refs=["NIST SP 800-63B §5.1.1.2"],
            evidence={"min_length": inp.policy.min_length},
            score=0.8
        ))

    if inp.mfa_factors.sms and not (inp.mfa_factors.totp_app or inp.mfa_factors.fido2_webauthn):
        findings.append(Finding(
            id="MFA_SMS_ONLY", title="SMS is the only MFA factor",
            severity="high",
            description="SMS OTP is vulnerable to SIM swap/interception.",
            remediation="Enable TOTP and/or FIDO2/WebAuthn; phase out SMS.",
            standard_refs=["NIST SP 800-63B §5.2.10"], score=0.85
        ))

    if not inp.mfa_enforcement.required_for_admins:
        findings.append(Finding(
            id="MFA_ADMINS", title="MFA not enforced for admins",
            severity="critical",
            description="Privileged accounts lack MFA enforcement.",
            remediation="Require MFA for all admin accounts.",
            standard_refs=["NIST SP 800-53 IA-2(1)"], score=0.95
        ))

    # simple combine
    weights = {"low":0.25,"medium":0.5,"high":0.8,"critical":1.0}
    penalty = sum(weights[f.severity]*f.score for f in findings) / max(len(findings),1) if findings else 0
    overall = max(0.0, 1.0 - penalty)
    if   overall >= 0.85: risk = "low"
    elif overall >= 0.65: risk = "moderate"
    elif overall >= 0.45: risk = "elevated"
    else:                 risk = "high"

    top = ", ".join(f.title for f in sorted(findings, key=lambda x: weights[x.severity]*x.score, reverse=True)[:3]) or "No material issues"
    summary = f"Overall risk: {risk}. Top issues: {top}."

    return AuditResponse(overall_score=round(overall,3), risk_level=risk, findings=findings, summary=summary)

# ====== ROUTE ======
@router.post("/audit", response_model=AuditResponse)
def audit_policy(inp: PolicyInput) -> AuditResponse:
    return run_audit(inp)
