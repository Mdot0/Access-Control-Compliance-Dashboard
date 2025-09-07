import requests
import pandas as pd
from nist import nist_mapping
from sentence_transformers import SentenceTransformer, util

# === Load embedding model (local, no API key required) ===
embedder = SentenceTransformer("all-MiniLM-L6-v2")

# === Example NIST controls (replace with your full set or load from CSV) ===
df_nist = pd.DataFrame([
    {"control_id": "AC-2", "title": "Account Management", "description": "Manage information system accounts"},
    {"control_id": "SI-3", "title": "Malicious Code Protection", "description": "Detect and mitigate malicious code"},
    {"control_id": "AU-2", "title": "Audit Events", "description": "Define auditable events for logging"},
    {"control_id": "IA-5", "title": "Authenticator Management", "description": "Manage and protect authenticators"},
])

# Precompute embeddings for NIST controls
nist_embeddings = embedder.encode(
    (df_nist["title"] + ". " + df_nist["description"]).tolist(),
    convert_to_tensor=True
)

def ai_map_to_nist(tech_id, name, description):
    """
    Map a MITRE technique to the closest NIST control using embeddings.
    Falls back to nist_mapping dict if available.
    """
    # Check static mapping first
    if tech_id in nist_mapping:
        return nist_mapping[tech_id]

    # Otherwise, AI retrieval
    if pd.isna(description):
        description = ""
    text = f"{tech_id} {name}. {description}"
    emb = embedder.encode(text, convert_to_tensor=True)
    sims = util.cos_sim(emb, nist_embeddings)[0].cpu().numpy()
    best_idx = sims.argmax()
    best_control = df_nist.iloc[best_idx]
    return best_control["control_id"]

def run_mitre_checks():
    url_import_mitre = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url_import_mitre)
    data = response.json()

    techniques, mitigations, relationships = [], [], []

    # === Step 2: Extract Techniques ===
    for obj in data["objects"]:
        if obj["type"] == "attack-pattern":
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")

            description = obj.get("description", "")
            platforms = obj.get("x_mitre_platforms", [])
            tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]

            techniques.append({
                "stix_id": obj["id"],
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": description,
                "platforms": platforms,
                "tactics": tactics
            })

    # === Step 3: Extract Mitigations ===
    for obj in data["objects"]:
        if obj["type"] == "course-of-action":
            mitigation_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitigation_id = ref.get("external_id")
            mitigations.append({
                "stix_id": obj["id"],
                "mitigation_id": mitigation_id,
                "name": obj.get("name", "")
            })

    # === Step 4: Extract Relationships ===
    for obj in data["objects"]:
        if obj["type"] == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append({
                "source_ref": obj["source_ref"],  # mitigation
                "target_ref": obj["target_ref"]   # technique
            })

    # === Step 5: Convert to DataFrames ===
    df_techniques = pd.DataFrame(techniques)
    df_mitigations = pd.DataFrame(mitigations)
    df_relationships = pd.DataFrame(relationships)

    # === Step 6: Merge Relationships ===
    df_rel = df_relationships.merge(df_techniques, left_on="target_ref", right_on="stix_id", how="left")
    df_rel = df_rel.merge(df_mitigations, left_on="source_ref", right_on="stix_id", how="left", suffixes=("_technique", "_mitigation"))

    # === Step 7: Map NIST controls (AI-assisted) ===
    df_rel["nist_controls_technique"] = df_rel.apply(
        lambda row: ai_map_to_nist(row["technique_id"], row["name_technique"], row["description"]),
        axis=1
    )
    df_rel["nist_controls_mitigation"] = df_rel.apply(
        lambda row: ai_map_to_nist(row["mitigation_id"], row["name_mitigation"], ""),
        axis=1
    )

    # === Step 8: Display sample ===
    print(df_rel[[
        "technique_id", "name_technique",
        "mitigation_id", "name_mitigation",
        "nist_controls_technique", "nist_controls_mitigation"
    ]].head(10))

if __name__ == "__main__":
    run_mitre_checks()
