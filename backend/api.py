# backend/api.py
import os
import logging, traceback
from typing import List
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sentence_transformers.util import semantic_search
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware
from .chat_api import router as chat_router
from . import mitre, nist
from .password_mfa import router as policy_router

# ---------- Paths & caches ----------
HERE = os.path.dirname(__file__)
CACHE_DIR = os.path.join(HERE, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

MITRE_CACHE = os.path.join(CACHE_DIR, "mitre_emb.pkl")
NIST_CACHE  = os.path.join(CACHE_DIR, "nist_emb.pkl")

# ---------- App ----------
app = FastAPI(title="Access & Compliance API")

# CORS (explicit origins for dev/prod)
FRONTEND_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,   # set False if you switch to "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compression
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Error logging middleware
logger = logging.getLogger("uvicorn.error")
class ErrorLogger(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception:
            logger.error("Unhandled error on %s %s\n%s",
                         request.method, request.url.path, traceback.format_exc())
            return JSONResponse({"detail": "server error"}, status_code=500)

app.add_middleware(ErrorLogger)

# Include Password/MFA routes
app.include_router(policy_router, prefix="/api/policy", tags=["policy"])

# ---------- Warm load on startup ----------
print("Loading MITRE ATT&CK (startup)…")
DF_MITRE = mitre.load_mitre()
MITRE_EMB = mitre.cache_embeddings(DF_MITRE, "description", MITRE_CACHE)

print("Loading NIST 800-53 (startup)…")
DF_NIST = nist.load_nist()
NIST_EMB = nist.cache_embeddings(DF_NIST, "description", NIST_CACHE)

# ---------- Helpers ----------
def _topk_semantic(query_text: str, corpus_emb, top_k: int = 10):
    if not getattr(mitre, "embedder", None):
        raise RuntimeError("SentenceTransformer embedder not initialized in mitre module.")
    q_emb = mitre.embedder.encode([query_text], convert_to_tensor=True)
    hits = semantic_search(q_emb, corpus_emb, top_k=top_k)[0]
    return hits

# ---------- Endpoints ----------
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/api/version")
def version():
    return {"name": "Access & Compliance API", "version": "0.1.0"}

@app.get("/api/technique")
def technique_to_nist(
    q: str = Query(..., description="ATT&CK technique ID (e.g., T1110)"),
    top_k: int = Query(10, ge=1, le=50),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
):
    # Find technique row
    row = DF_MITRE[DF_MITRE["technique_id"].str.upper() == q.strip().upper()]
    if row.empty:
        return {"technique": q.upper(), "name": None, "exact": [], "semantic": []}

    name = row.iloc[0]["name"]
    desc = row.iloc[0]["description"]

    hits = _topk_semantic(desc, NIST_EMB, top_k=top_k)
    semantic = []
    for h in hits:
        s = float(h["score"])
        if s < min_score:
            continue
        n = DF_NIST.iloc[h["corpus_id"]]
        semantic.append({
            "id": n["control_id"],
            "name": n.get("description", ""),
            "score": s,
        })

    return {"technique": q.upper(), "name": name, "exact": [], "semantic": semantic}

@app.get("/api/nist")
def nist_to_technique(
    q: str = Query(..., description="NIST control ID (e.g., AC-2)"),
    top_k: int = Query(10, ge=1, le=50),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
):
    # Find control row
    row = DF_NIST[DF_NIST["control_id"].str.upper() == q.strip().upper()]
    if row.empty:
        return {"control": q.upper(), "name": None, "exact": [], "semantic": []}

    desc = row.iloc[0]["description"]
    name = row.iloc[0].get("family", "")

    hits = _topk_semantic(desc, MITRE_EMB, top_k=top_k)
    semantic = []
    for h in hits:
        s = float(h["score"])
        if s < min_score:
            continue
        m = DF_MITRE.iloc[h["corpus_id"]]
        semantic.append({
            "id": m["technique_id"],
            "name": m["name"],
            "score": s,
        })

    return {"control": q.upper(), "name": name, "exact": [], "semantic": semantic}

@app.get("/api/semantic")
def generic_semantic(
    dataset: str = Query(..., pattern="^(nist|mitre)$"),
    text: str = Query(..., min_length=3),
    top_k: int = Query(10, ge=1, le=50),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
):
    if dataset == "nist":
        hits = _topk_semantic(text, NIST_EMB, top_k=top_k)
        out = []
        for h in hits:
            s = float(h["score"])
            if s < min_score: 
                continue
            n = DF_NIST.iloc[h["corpus_id"]]
            out.append({"id": n["control_id"], "name": n.get("description", ""), "score": s})
        return {"dataset": "nist", "query": text, "results": out}
    else:
        hits = _topk_semantic(text, MITRE_EMB, top_k=top_k)
        out = []
        for h in hits:
            s = float(h["score"])
            if s < min_score: 
                continue
            m = DF_MITRE.iloc[h["corpus_id"]]
            out.append({"id": m["technique_id"], "name": m["name"], "score": s})
        return {"dataset": "mitre", "query": text, "results": out}
app.include_router(chat_router, prefix="/api")