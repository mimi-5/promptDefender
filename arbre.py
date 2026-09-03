import os

# 🔹 Dossiers à ignorer
EXCLUSIONS = {'.git', 'venv', '.pytest_cache', '__pycache__', 'node_modules'}

def afficher_arborescence(dossier, fichier, prefixe=""):
    try:
        entrees = sorted([
            e for e in os.listdir(dossier)
            if e not in EXCLUSIONS
        ])
    except PermissionError:
        return

    for i, entree in enumerate(entrees):
        chemin = os.path.join(dossier, entree)
        est_dernier = (i == len(entrees) - 1)
        connecteur = "└── " if est_dernier else "├── "
        
        ligne = prefixe + connecteur + entree
        
        # 🔹 Écriture dans fichier uniquement
        fichier.write(ligne + "\n")

        if os.path.isdir(chemin):
            extension = "    " if est_dernier else "│   "
            afficher_arborescence(chemin, fichier, prefixe + extension)


if __name__ == "__main__":
    import sys
    
    dossier = sys.argv[1] if len(sys.argv) > 1 else "."
    fichier_sortie = "arborescence.txt"
    
    with open(fichier_sortie, "w", encoding="utf-8") as f:
        f.write(dossier + "\n")
        afficher_arborescence(dossier, f)