import requests
import pandas as pd
from sentence_transformers import SentenceTransformer
import pickle
import os

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Load SentenceTransformer model once
embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

def load_mitre():
    """Load full MITRE ATT&CK techniques from STIX dataset"""
    data = requests.get(MITRE_URL).json()
    techniques = []
    for obj in data["objects"]:
        if obj["type"] == "attack-pattern":
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
            if technique_id:
                techniques.append({
                    "technique_id": technique_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
                })
    return pd.DataFrame(techniques)

def cache_embeddings(df, text_column, cache_file):
    """Cache embeddings to avoid recomputing every run"""
    if os.path.exists(cache_file):
        with open(cache_file, "rb") as f:
            embeddings = pickle.load(f)
    else:
        embeddings = embedder.encode(df[text_column].tolist(), convert_to_tensor=True)
        with open(cache_file, "wb") as f:
            pickle.dump(embeddings, f)
    return embeddings
