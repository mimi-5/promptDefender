import json
import re
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import time

# 👉 IMPORT TON DETECTOR ICI
# adapte selon ton projet
from puppetry_detector.detector import PuppetryDetector  # ou ta fonction

# ==============================
# CONFIG
# ==============================
DATASET_PATH = "tests\data\Prompt_INJECTION_And_Benign_DATASET.jsonl"  # chemin vers ton fichier

# ==============================
# LOAD DATASET
# ==============================
def load_jsonl(path):
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
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
    if label == "injection":
        return 1
    elif label == "benign":
        return 0
    else:
        return 0

# ==============================
# EVALUATION
# ==============================
def evaluate(data):
    y_true = []
    y_pred = []

    for sample in data:
        prompt = preprocess(sample["prompt"])
        true_label = map_label(sample["label"])

        # 👉 appelle ton détecteur ici
        pred = PuppetryDetector(prompt)  # doit retourner True/False

        pred_label = 1 if pred else 0

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

    start = time.time()

    y_true, y_pred = evaluate(data)

    end = time.time()

    print("\n==============================")
    print("📊 RÉSULTATS DE L'ÉVALUATION")
    print("==============================\n")

    print(classification_report(
        y_true,
        y_pred,
        target_names=["Benign (0)", "Injection (1)"],
        zero_division=0
    ))

    print("Accuracy :", accuracy_score(y_true, y_pred))

    print("\nMatrice de confusion :")
    print(confusion_matrix(y_true, y_pred))

    print(f"\nTemps d'exécution : {round(end - start, 2)}s")

# ==============================
if __name__ == "__main__":
    main()