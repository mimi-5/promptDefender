import json
import re
import time
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ==============================
# IMPORT DETECTOR
# ==============================
# FIX: import the detection *function* directly.
# The original code called  PuppetryDetector(prompt)  which instantiates the
# class and always returns a truthy Python object → every sample was labelled 1.
from puppetry_detector.phases.malicious_detector import detect_malicious_policy  # import the function, not the module

# ==============================
# CONFIGph
# ==============================
DATASET_PATH = r"tests\data\Prompt_INJECTION_And_Benign_DATASET.jsonl"

# ==============================
# LOAD DATASET
# ==============================
def load_jsonl(path):
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data

# ==============================
# PREPROCESS
# ==============================
def preprocess(text):
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()

# ==============================
# LABEL MAPPING
# ==============================
def map_label(label):
    # Dataset uses "malicious" (and sometimes "injection") for the positive class.
    # The silent else: return 0 was making all "malicious" samples appear benign.
    if label in ("injection", "malicious"):
        return 1
    elif label == "benign":
        return 0
    else:
        raise ValueError(f"Unknown label: '{label}'. Expected 'malicious', 'injection', or 'benign'.")

# ==============================
# EVALUATION
# ==============================
def evaluate(data):
    y_true = []
    y_pred = []

    for sample in data:
        prompt = preprocess(sample["prompt"])
        true_label = map_label(sample["label"])

        # detect_malicious_policy returns True (injection) or False (benign)
        is_malicious = detect_malicious_policy(prompt)
        pred_label = 1 if is_malicious else 0

        y_true.append(true_label)
        y_pred.append(pred_label)

    return y_true, y_pred

# ==============================
# MAIN
# ==============================
def main():
    print("Chargement du dataset...")
    data = load_jsonl(DATASET_PATH)

    print(f"Nombre d'échantillons : {len(data)}")

    label_counts = {}
    for sample in data:
        label_counts[sample["label"]] = label_counts.get(sample["label"], 0) + 1
    print(f"Distribution des labels : {label_counts}")

    start = time.time()
    y_true, y_pred = evaluate(data)
    end = time.time()

    print("\n==============================")
    print("RÉSULTATS DE L'ÉVALUATION")
    print("==============================\n")

    print(classification_report(
        y_true,
        y_pred,
        target_names=["Benign (0)", "Injection (1)"],
        zero_division=0,
    ))

    print("Accuracy :", accuracy_score(y_true, y_pred))

    print("\nMatrice de confusion :")
    print(confusion_matrix(y_true, y_pred))

    print(f"\nTemps d'exécution : {round(end - start, 2)}s")

# ==============================
if __name__ == "__main__":
    main()
