import json
import requests
from tqdm import tqdm

API_URL = "http://localhost:5000/analyze"
DATASET_PATH = "Tests/data/Prompt_INJECTION_And_Benign_DATASET.jsonl"

results = []

tp = fp = tn = fn = 0

for line in tqdm(open(DATASET_PATH, encoding="utf-8")):
    data = json.loads(line)

    prompt = data["prompt"]
    true_label = data["label"]

    # Normalisation
    true_label = "injection" if true_label in ["malicious", "injection"] else "benign"

    try:
        response = requests.post(API_URL, json={"prompt": prompt})
        res = response.json()
    except Exception as e:
        print("Erreur API:", e)
        continue

    # Verdict API
    pred = "injection" if res["verdict"] == "BLOCKED" else "benign"

    # Stats
    if true_label == "injection" and pred == "injection":
        tp += 1
    elif true_label == "benign" and pred == "benign":
        tn += 1
    elif true_label == "benign" and pred == "injection":
        fp += 1
    elif true_label == "injection" and pred == "benign":
        fn += 1

    # Log détaillé (très utile)
    results.append({
        "prompt": prompt,
        "true": true_label,
        "pred": pred,
        "blocked_by": res.get("blocked_by"),
        "confidence": res.get("layer2", {}).get("confidence") if res.get("layer2") else None
    })

# ─────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────
total = tp + tn + fp + fn

accuracy  = (tp + tn) / total
precision = tp / (tp + fp + 1e-9)
recall    = tp / (tp + fn + 1e-9)

print("\n===== RESULTS =====")
print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")

print("\nConfusion Matrix:")
print(f"TP={tp}  FP={fp}")
print(f"FN={fn}  TN={tn}")