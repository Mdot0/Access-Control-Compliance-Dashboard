# backend/api.py
import os
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from sentence_transformers.util import semantic_search

from . import mitre, nist

# ---------- Paths & caches ----------
HERE = os.path.dirname(__file__)
CACHE_DIR = os.path.join(HERE, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

MITRE_CACHE = os.path.join(CACHE_DIR, "mitre_emb.pkl")
NIST_CACHE  = os.path.join(CACHE_DIR, "nist_emb.pkl")

# ---------- App ----------
app = FastAPI(title="Access & Compliance API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ---------- Warm load on startup (same logic as your CLI) ----------
print("Loading MITRE ATT&CK (startup)…")
DF_MITRE = mitre.load_mitre()
MITRE_EMB = mitre.cache_embeddings(DF_MITRE, "description", MITRE_CACHE)

print("Loading NIST 800-53 (startup)…")
DF_NIST = nist.load_nist()
NIST_EMB = nist.cache_embeddings(DF_NIST, "description", NIST_CACHE)

# ---------- Helpers ----------
def _topk_semantic(query_text: str, corpus_emb, top_k: int = 10):
    q_emb = mitre.embedder.encode([query_text], convert_to_tensor=True)
    hits = semantic_search(q_emb, corpus_emb, top_k=top_k)[0]
    return hits

# ---------- Endpoints ----------
@app.get("/api/technique")
def technique_to_nist(q: str = Query(..., description="ATT&CK technique ID (e.g., T1110)")):
    # Find technique row
    row = DF_MITRE[DF_MITRE["technique_id"].str.upper() == q.strip().upper()]
    if row.empty:
        return {"technique": q.upper(), "name": None, "exact": [], "semantic": []}

    name = row.iloc[0]["name"]
    desc = row.iloc[0]["description"]

    # Semantic match technique description -> NIST controls
    hits = _topk_semantic(desc, NIST_EMB, top_k=10)
    semantic = []
    for h in hits:
        n = DF_NIST.iloc[h["corpus_id"]]
        semantic.append({
            "id": n["control_id"],
            "name": n.get("description", ""),
            "score": float(h["score"]),
        })

    # You don't have exact CTID mappings wired here (only semantic), so exact = []
    return {"technique": q.upper(), "name": name, "exact": [], "semantic": semantic}

@app.get("/api/nist")
def nist_to_technique(q: str = Query(..., description="NIST control ID (e.g., AC-2)")):
    # Find control row
    row = DF_NIST[DF_NIST["control_id"].str.upper() == q.strip().upper()]
    if row.empty:
        return {"control": q.upper(), "name": None, "exact": [], "semantic": []}

    desc = row.iloc[0]["description"]
    name = row.iloc[0].get("family", "")  # you store family + description; name is optional

    # Semantic match control description -> MITRE techniques
    hits = _topk_semantic(desc, MITRE_EMB, top_k=10)
    semantic = []
    for h in hits:
        m = DF_MITRE.iloc[h["corpus_id"]]
        semantic.append({
            "id": m["technique_id"],
            "name": m["name"],
            "score": float(h["score"]),
        })

    # exact = [] (no CTID mapping wired here)
    return {"control": q.upper(), "name": name, "exact": [], "semantic": semantic}