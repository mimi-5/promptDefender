"""
PromptDefender — Test Couche 3 (XLM-RoBERTa fine-tuné)
========================================================
Teste la couche 3 seule sur le dataset local JSONL,
exactement comme test2.py teste le pipeline L1+L2.

Usage :
    python test_model/test_layer3.py
    python test_model/test_layer3.py --dataset Tests/data/Prompt_INJECTION_And_Benign_DATASET.jsonl
    python test_model/test_layer3.py --save-errors
"""

import json
import argparse
import sys
import os
from tqdm import tqdm
from pathlib import Path

# ── Import de la couche 3 ─────────────────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from promptDefender_thirdLayer.llm_detector import LLMDetector

# ─── Config ───────────────────────────────────────────────────────────────────
DEFAULT_DATASET = "Tests/data/Prompt_INJECTION_And_Benign_DATASET.jsonl"
DEFAULT_ERRORS  = "Tests/errors_layer3.jsonl"


def main():
    parser = argparse.ArgumentParser(description="Test Couche 3 — XLM-RoBERTa")
    parser.add_argument("--dataset",     default=DEFAULT_DATASET)
    parser.add_argument("--errors-out",  default=DEFAULT_ERRORS)
    parser.add_argument("--save-errors", action="store_true",
                        help="Sauvegarde les erreurs dans errors_layer3.jsonl")
    parser.add_argument("--threshold",   type=float, default=None,
                        help="Override du threshold (défaut : celui de model_meta.json)")
    args = parser.parse_args()

    # ── Chargement du détecteur ───────────────────────────────────────────────
    print("\nChargement du modèle XLM-RoBERTa...")
    try:
        detector = LLMDetector()
        if args.threshold is not None:
            detector.threshold = args.threshold
        print(f"Modèle prêt — device={detector.device} | threshold={detector.threshold}")
    except FileNotFoundError as e:
        print(f"\nERREUR : {e}")
        sys.exit(1)

    # ── Chargement du dataset ─────────────────────────────────────────────────
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"\nERREUR : dataset introuvable → {dataset_path}")
        sys.exit(1)

    samples = []
    with open(dataset_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item  = json.loads(line)
            label = item.get("label", "")
            samples.append({
                "prompt": item["prompt"],
                "true":   "injection" if label in ["malicious", "injection"] else "benign",
              })
    
    print(f"Dataset charge : {len(samples)} exemples\n")

    # ── Inférence ─────────────────────────────────────────────────────────────
    tp = fp = tn = fn = 0
    errors = []
    total_ms = 0.0

    for item in tqdm(samples, desc="Layer 3"):
        prompt     = item["prompt"]
        true_label = item["true"]

        result = detector.predict(prompt)
        pred   = "injection" if result["is_injection"] else "benign"
        conf   = result["confidence"]
        total_ms += result.get("elapsed_ms") or 0.0

        if true_label == "injection" and pred == "injection":
            tp += 1
        elif true_label == "benign" and pred == "benign":
            tn += 1
        elif true_label == "benign" and pred == "injection":
            fp += 1
            errors.append({"type": "FP", "prompt": prompt, "confidence": conf})
        elif true_label == "injection" and pred == "benign":
            fn += 1
            errors.append({"type": "FN", "prompt": prompt, "confidence": conf})

    # ── Métriques ─────────────────────────────────────────────────────────────
    total     = tp + tn + fp + fn
    accuracy  = (tp + tn) / total
    precision = tp / (tp + fp + 1e-9)
    recall    = tp / (tp + fn + 1e-9)
    f1        = 2 * precision * recall / (precision + recall + 1e-9)
    avg_ms    = total_ms / total

    print(f"\n{'='*55}")
    print(f"  RÉSULTATS — Couche 3 (XLM-RoBERTa)")
    print(f"{'='*55}")
    print(f"  Threshold utilisé : {detector.threshold}")
    print(f"  Device            : {detector.device}")
    print(f"  Temps moyen/prompt: {avg_ms:.1f} ms")
    print(f"{'─'*55}")
    print(f"  Accuracy  : {accuracy:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1-score  : {f1:.4f}")
    print(f"{'─'*55}")
    print(f"  CONFUSION MATRIX")
    print(f"  TP: {tp:>4} | FP: {fp:>4}")
    print(f"  FN: {fn:>4} | TN: {tn:>4}")
    print(f"{'='*55}")

    # Comparaison avec les couches précédentes
    print(f"\n  COMPARAISON AVEC LES COUCHES PRÉCÉDENTES")
    print(f"{'─'*55}")
    print(f"  {'Couche':<30} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'─'*46}")
    print(f"  {'L1 — Regex':<30} {'1.0000':>10} {'0.8480':>8} {'0.9177':>8}")
    print(f"  {'L1+L2 — Regex+ML':<30} {'?':>10} {'?':>8} {'?':>8}")
    print(f"  {'L3 — XLM-RoBERTa (seule)':<30} {precision:>10.4f} {recall:>8.4f} {f1:>8.4f}")
    print(f"{'='*55}\n")

    # ── Sauvegarde des erreurs ─────────────────────────────────────────────────
    if args.save_errors and errors:
        out_path = Path(args.errors_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for e in errors:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"  {len(errors)} erreurs sauvegardées → {out_path}")

    # Aperçu des erreurs
    fp_list = [e for e in errors if e["type"] == "FP"]
    fn_list = [e for e in errors if e["type"] == "FN"]

    if fn_list:
        print(f"\n  FAUX NÉGATIFS (injections non détectées — DANGER) : {len(fn_list)}")
        for e in fn_list[:3]:
            print(f"  conf={e['confidence']:.3f} | {e['prompt'][:100]}")

    if fp_list:
        print(f"\n  FAUX POSITIFS (bénins bloqués à tort) : {len(fp_list)}")
        for e in fp_list[:3]:
            print(f"  conf={e['confidence']:.3f} | {e['prompt'][:100]}")


if __name__ == "__main__":
    main()