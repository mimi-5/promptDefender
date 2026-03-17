import pandas as pd
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
from puppetry_detector.detector import PuppetryDetector

def plot_confusion_matrix(cm, target_names, title='Matrice de Confusion (MPDD Regex)', cmap=None, normalize=True):
    """
    Génère et sauvegarde une image de la matrice de confusion.
    """
    accuracy = cm.trace() / float(cm.sum())
    misclass = 1 - accuracy

    if cmap is None:
        cmap = plt.get_cmap('Blues')

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap=cmap, cbar=False,
                xticklabels=target_names, yticklabels=target_names)

    plt.title(title)
    plt.ylabel('Vrai Label (Actual)')
    plt.xlabel('Label Prédit (Predicted)\n\naccuracy={:0.4f}; misclass={:0.4f}'.format(accuracy, misclass))

    # Sauvegarde l'image dans le dossier courant
    output_filename = 'confusion_matrix_mpdd.png'
    plt.savefig(output_filename, bbox_inches='tight', dpi=300)
    print(f"\n--- IMAGE GÉNÉRÉE : {output_filename} ---")
    plt.close() # Ferme la figure pour libérer de la mémoire

def run_evaluation(csv_path):
    print(f"--- Chargement du dataset : {csv_path} ---")
    
    # Lecture du CSV
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Erreur lors de la lecture : {e}")
        return

    # Définition des colonnes (Majuscules obligatoires selon ton fichier)
    col_text = 'Prompt'
    col_label = 'isMalicious' # Note la faute de frappe 'Malicius'

    # Vérification de sécurité
    if col_text not in df.columns or col_label not in df.columns:
        print(f"Erreur : Colonnes introuvables. Colonnes réelles : {df.columns.tolist()}")
        return

    # Initialisation du détecteur
    detector = PuppetryDetector()
    y_true = df[col_label].tolist()
    y_pred = []
    
    print(f"--- Analyse de {len(df)} échantillons en cours ---")
    print("Veuillez patienter, cela peut prendre quelques minutes...")
    start_time = time.time()

    # Boucle d'analyse
    for index, row in df.iterrows():
        # Utilisation de .detect()
        is_detected = detector.detect(str(row[col_text]))
        y_pred.append(1 if is_detected else 0)
        
        # Feedback de progression
        if index % 5000 == 0 and index > 0:
            print(f"Progression : {index}/{len(df)}...")

    end_time = time.time()

    # --- RÉSULTATS TEXTUELS ---
    print("\n" + "="*60)
    print("RÉSULTATS DE L'ÉVALUATION SUR MPDD")
    print("="*60)
    
    # Target names pour l'affichage
    target_names = ['Sain (0)', 'Malveillant (1)']
    
    print(classification_report(y_true, y_pred, target_names=target_names))
    
    # Calcul de la matrice de confusion (cm)
    cm = confusion_matrix(y_true, y_pred)
    print(f"Matrice de Confusion (Données brutes) :\n{cm}")
    print("="*60)
    print(f"Temps d'exécution : {end_time - start_time:.2f}s")

    # --- GÉNÉRATION DE L'IMAGE ---
    plot_confusion_matrix(cm, target_names)

if __name__ == "__main__":
    # Assure-toi que le chemin vers ton fichier MPDD.csv est correct
    run_evaluation("tests/data/MPDD.csv")