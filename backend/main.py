import argparse
from sentence_transformers.util import semantic_search
import mitre
import nist
from iso import run_iso_checks
from password_mfa import run_password_mfa_checks

def run_checks():
    parser = argparse.ArgumentParser()
    parser.add_argument("--technique", help="MITRE technique ID")
    parser.add_argument("--nist", help="NIST control ID")
    args = parser.parse_args()

    print("Loading MITRE ATT&CK...")
    df_mitre = mitre.load_mitre()
    mitre_embeddings = mitre.cache_embeddings(df_mitre, "description", "mitre_emb.pkl")

    print("Loading NIST 800-53...")
    df_nist = nist.load_nist()
    nist_embeddings = nist.cache_embeddings(df_nist, "description", "nist_emb.pkl")

    if args.technique:
        query = df_mitre[df_mitre["technique_id"] == args.technique]
        if query.empty:
            print("No MITRE technique found")
        else:
            desc = query.iloc[0]["description"]
            q_emb = mitre.embedder.encode([desc], convert_to_tensor=True)
            hits = semantic_search(q_emb, nist_embeddings, top_k=3)[0]
            print(f"\nMITRE {args.technique} → {query.iloc[0]['name']}")
            print("Best NIST matches:")
            for h in hits:
                print("-", df_nist.iloc[h['corpus_id']]['control_id'],
                      df_nist.iloc[h['corpus_id']]['description'],
                      f"(score={h['score']:.2f})")

    elif args.nist:
        query = df_nist[df_nist["control_id"] == args.nist]
        if query.empty:
            print("No NIST control found")
        else:
            desc = query.iloc[0]["description"]
            q_emb = nist.embedder.encode([desc], convert_to_tensor=True)
            hits = semantic_search(q_emb, mitre_embeddings, top_k=3)[0]
            print(f"\nNIST {args.nist} → {query.iloc[0]['description']}")
            print("Best MITRE matches:")
            for h in hits:
                print("-", df_mitre.iloc[h['corpus_id']]['technique_id'],
                      df_mitre.iloc[h['corpus_id']]['name'],
                      f"(score={h['score']:.2f})")

    print("\nRunning ISO 27001/27002 validation...")
    run_iso_checks()

    print("Checking password policies & MFA...")
    run_password_mfa_checks()

    print("\nAll checks complete. Reports saved in ./reports")

if __name__ == "__main__":
    run_checks()
