from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sentence_transformers.util import semantic_search
from . import mitre, nist
import requests
from typing import Optional

router = APIRouter()

# Preload catalogs + embeddings at import
df_mitre = mitre.load_mitre()
mitre_emb = mitre.cache_embeddings(df_mitre, "description", "mitre_emb.pkl")
df_nist  = nist.load_nist()
nist_emb = nist.cache_embeddings(df_nist, "description", "nist_emb.pkl")

class ChatMsg(BaseModel):
    message: str
    mode: Optional[str] = None  # "map", "audit", or None
    top_k: int = 5

@router.post("/chat")
def chat(m: ChatMsg):
    text = m.message.strip()

    # Try MITRE ID → NIST
    q = df_mitre[df_mitre["technique_id"] == text.upper()]
    if m.mode == "map" and not q.empty:
        q_emb = mitre.embedder.encode([q.iloc[0]["description"]], convert_to_tensor=True)
        hits = semantic_search(q_emb, nist_emb, top_k=m.top_k)[0]
        return {
            "type": "mapping", "direction": "MITRE→NIST",
            "query": {"technique_id": text.upper(), "name": q.iloc[0]["name"]},
            "matches": [{
                "control_id": df_nist.iloc[h["corpus_id"]]["control_id"],
                "description": df_nist.iloc[h["corpus_id"]]["description"],
                "score": float(h["score"])
            } for h in hits]
        }

    # Try NIST ID → MITRE
    q = df_nist[df_nist["control_id"] == text.upper()]
    if m.mode == "map" and not q.empty:
        q_emb = nist.embedder.encode([q.iloc[0]["description"]], convert_to_tensor=True)
        hits = semantic_search(q_emb, mitre_emb, top_k=m.top_k)[0]
        return {
            "type": "mapping", "direction": "NIST→MITRE",
            "query": {"control_id": text.upper(), "description": q.iloc[0]["description"]},
            "matches": [{
                "technique_id": df_mitre.iloc[h["corpus_id"]]["technique_id"],
                "name": df_mitre.iloc[h["corpus_id"]]["name"],
                "score": float(h["score"])
            } for h in hits]
        }

    # Audit passthrough: send “audit {json}”
    if m.mode == "audit" or text.lower().startswith("audit "):
        try:
            import json
            payload = json.loads(text.split(" ",1)[1]) if " " in text else {}
        except Exception:
            raise HTTPException(400, "Send `audit { ...policy json... }` or use the UI form.")
        r = requests.post("http://127.0.0.1:8000/api/audit", json=payload, timeout=25)
        return {"type": "audit_result", "data": r.json()}

    # Fallback: retrieval QA (top refs from both)
    q_emb = nist.embedder.encode([text], convert_to_tensor=True)
    n_hits = semantic_search(q_emb, nist_emb, top_k=3)[0]
    m_hits = semantic_search(q_emb, mitre_emb, top_k=3)[0]

    def pack(df, hits, keys):
        out = []
        for h in hits:
            row = df.iloc[h["corpus_id"]]
            out.append({k: row[k] for k in keys} | {"score": float(h["score"])})
        return out

    return {
        "type": "qa",
        "answer": "Closest references in NIST and MITRE:",
        "nist_candidates": pack(df_nist, n_hits, ["control_id","description","family"]),
        "mitre_candidates": pack(df_mitre, m_hits, ["technique_id","name","tactics"])
    }
