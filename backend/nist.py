import requests
import pandas as pd
from sentence_transformers import SentenceTransformer
import pickle
import os

NIST_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"

embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

def load_nist():
    """Load full NIST 800-53 Rev 5 controls from OSCAL catalog"""
    data = requests.get(NIST_URL).json()
    controls = []
    for group in data["catalog"]["groups"]:
        for ctrl in group.get("controls", []):
            control_id = ctrl["id"]
            title = ctrl.get("title", "")
            desc = ""
            for p in ctrl.get("props", []):
                if p.get("name") == "label":
                    desc = p.get("value", "")
            controls.append({
                "control_id": control_id,
                "family": group["id"],
                "description": f"{title} - {desc}"
            })
    return pd.DataFrame(controls)

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
