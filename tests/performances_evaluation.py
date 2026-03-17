import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from puppetry_detector.detector import PuppetryDetector

def run_performance_test(csv_path):
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Erreur : Le fichier {csv_path} est introuvable.")
        return

    print(f"--- Évaluation en cours sur {len(df)} échantillons ---")

    detector = PuppetryDetector()
    y_true = df['label'].map({'harmful': 1, 'safe': 0}).tolist()
    y_pred = []

    for prompt in df['prompt']:
        result = detector.detect(str(prompt))
        y_pred.append(1 if result["malicious"] else 0)

    # --- 1. GÉNÉRATION DU TABLEAU MARKDOWN POUR LE README ---
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average=None, labels=[0, 1])
    
    markdown_table = f"""
### 📊 Résultats de Performance (Module Regex)

| Métrique    | Safe (Légitime) | Harmful (Attaque) | Global (Macro) |
|-------------|-----------------|-------------------|----------------|
| **Précision** | {precision[0]:.2f}            | {precision[1]:.2f}              | {(precision[0]+precision[1])/2:.2f}           |
| **Rappel** | {recall[0]:.2f}            | {recall[1]:.2f}              | {(recall[0]+recall[1])/2:.2f}           |
| **F1-Score** | {f1[0]:.2f}            | {f1[1]:.2f}              | {(f1[0]+f1[1])/2:.2f}           |

*Dataset utilisé : {csv_path}*
"""
    
    print("\n--- COPIEZ CE TEXTE DANS VOTRE README.MD ---")
    print(markdown_table)
    print("-" * 45)

    # --- 2. VISUALISATION DE LA MATRICE DE CONFUSION (HÉAUTE QUALITÉ) ---
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 7))
    
    # Customisation du style
    sns.set_theme(style="white")
    ax = sns.heatmap(cm, annot=True, fmt='d', cmap='YlGnBu', 
                square=True, cbar_kws={"shrink": .8},
                annot_kws={"size": 16, "weight": "bold"})
    
    plt.title('Matrice de Confusion : Puppetry Regex Detector', fontsize=18, pad=20)
    plt.ylabel('Réalité (Ground Truth)', fontsize=14, labelpad=10)
    plt.xlabel('Prédiction du Système', fontsize=14, labelpad=10)
    ax.set_xticklabels(['SAFE', 'HARMFUL'], fontsize=12)
    ax.set_yticklabels(['SAFE', 'HARMFUL'], fontsize=12)

    # Ajout d'une note explicative sur l'image
    plt.figtext(0.5, 0.01, f"Total échantillons: {len(df)} | Précision Harmful: {precision[1]:.2%}", 
                ha="center", fontsize=10, bbox={"facecolor":"orange", "alpha":0.2, "pad":5})

    # Sauvegarde optimisée pour le Web/Markdown
    plt.tight_layout()
    plt.savefig('confusion_matrix_readme.png', dpi=300) # Haute résolution
    print("\nImage 'confusion_matrix_readme.png' générée pour votre README.")

if __name__ == "__main__":
    run_performance_test('tests/data/test.csv')