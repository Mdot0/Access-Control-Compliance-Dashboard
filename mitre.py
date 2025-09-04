import requests
import json 
import pandas as pd 
from nist import nist_mapping

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

    # === Step 7: Map NIST controls from nist.py ===
    df_rel["nist_controls_technique"] = df_rel["technique_id"].map(nist_mapping)
    df_rel["nist_controls_mitigation"] = df_rel["mitigation_id"].map(nist_mapping)

    # === Step 8: Display sample ===
    print(df_rel[[
        "technique_id", "name_technique",
        "mitigation_id", "name_mitigation",
        "nist_controls_technique", "nist_controls_mitigation"
    ]].head(10))