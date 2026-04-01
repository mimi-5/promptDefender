"""
PromptDefender — Couche 2 : Détecteur ML
=========================================
Ce module charge le meilleur modèle ML entraîné dans ml_classification.ipynb
et fournit une interface de prédiction compatible avec l'orchestrateur principal.

Flux : Prompt → Couche 1 (Regex) → [si non détecté] → Couche 2 (ML) → décision
"""

import json
import logging
import numpy as np
from pathlib import Path
from typing import Optional

import joblib
import torch
from transformers import AutoTokenizer, AutoModel

logger = logging.getLogger(__name__)

# Chemin par défaut des artefacts ML (relatif à ce fichier)
_DEFAULT_ARTIFACTS_DIR = Path(__file__).parent / "ml_artifacts"


class MLDetector:
    """
    Détecteur de prompt injection basé sur des embeddings multilingual BERT
    + un classificateur ML entraîné.

    Usage
    -----
    >>> detector = MLDetector()
    >>> result = detector.predict("Ignore all previous instructions and ...")
    >>> print(result)
    {
        "is_injection": True,
        "confidence": 0.93,
        "label": "injection",
        "model_used": "Logistic Regression"
    }
    """

    def __init__(
        self,
        artifacts_dir: Optional[Path] = None,
        bert_model_name: str = "bert-base-multilingual-cased",
        threshold: float = 0.9,
        device: Optional[str] = None,
    ):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else _DEFAULT_ARTIFACTS_DIR
        self.threshold = threshold

        # --- Chargement des métadonnées du meilleur modèle ---
        meta_path = self.artifacts_dir / "model_meta.json"
        if meta_path.exists():
            with open(meta_path) as f:
                self.meta = json.load(f)
            self.threshold     = self.meta.get("threshold", threshold)
            self.needs_scaling = self.meta.get("needs_scaling", True)
            self.model_name    = self.meta.get("best_model", "unknown")
            bert_model_name    = self.meta.get("bert_model", bert_model_name)
        else:
            logger.warning("model_meta.json introuvable — utilisation des valeurs par défaut.")
            self.meta          = {}
            self.needs_scaling = True
            self.model_name    = "unknown"

        # --- Chargement du classificateur ML ---
        model_files = list(self.artifacts_dir.glob("best_model_*.joblib"))
        if not model_files:
            raise FileNotFoundError(
                f"Aucun fichier best_model_*.joblib trouvé dans {self.artifacts_dir}. "
                "Lance d'abord le notebook ml_classification.ipynb."
            )
        self.classifier = joblib.load(model_files[0])
        logger.info(f"Classificateur chargé : {model_files[0].name}")

        # --- Chargement du scaler (si nécessaire) ---
        scaler_path = self.artifacts_dir / "scaler.joblib"
        if self.needs_scaling and scaler_path.exists():
            self.scaler = joblib.load(scaler_path)
        elif self.needs_scaling:
            logger.warning("scaler.joblib introuvable — pas de normalisation appliquée.")
            self.scaler = None
        else:
            self.scaler = None

        # --- Chargement de BERT multilingue ---
        self.device = torch.device(
            device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        logger.info(f"Device : {self.device}")

        self.tokenizer = AutoTokenizer.from_pretrained(bert_model_name)
        self.bert_model = AutoModel.from_pretrained(bert_model_name)
        self.bert_model.eval()
        self.bert_model = self.bert_model.to(self.device)
        logger.info(f"BERT chargé : {bert_model_name}")

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    def _embed(self, text: str, max_length: int = 128) -> np.ndarray:
        """Retourne le vecteur CLS-token d'un texte (shape: [768])."""
        encoded = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        encoded = {k: v.to(self.device) for k, v in encoded.items()}

        with torch.no_grad():
            outputs = self.bert_model(**encoded)

        cls_vec = outputs.last_hidden_state[:, 0, :].cpu().numpy()
        return cls_vec  # shape (1, 768)

    # ------------------------------------------------------------------
    # Prétraitement (cohérent avec la couche 1)
    # ------------------------------------------------------------------

    @staticmethod
    def _preprocess(text: str) -> str:
        import re
        text = text.lower()
        text = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    # ------------------------------------------------------------------
    # Prédiction principale
    # ------------------------------------------------------------------

    def predict(self, prompt: str) -> dict:
        """
        Prédit si un prompt est une injection.

        Parameters
        ----------
        prompt : str
            Texte à analyser (qui a déjà passé la couche 1 sans être détecté).

        Returns
        -------
        dict avec les clés :
            - is_injection (bool)
            - confidence   (float, probabilité classe injection)
            - label        (str, "injection" ou "benign")
            - model_used   (str)
        """
        clean = self._preprocess(prompt)
        embedding = self._embed(clean)  # (1, 768)

        if self.needs_scaling and self.scaler is not None:
            embedding = self.scaler.transform(embedding)

        prob_injection = float(self.classifier.predict_proba(embedding)[0][1])
        is_injection   = prob_injection >= self.threshold

        return {
            "is_injection": is_injection,
            "confidence":   round(prob_injection, 4),
            "label":        "injection" if is_injection else "benign",
            "model_used":   self.model_name,
        }

    def predict_batch(self, prompts: list[str]) -> list[dict]:
        """Prédit sur une liste de prompts."""
        return [self.predict(p) for p in prompts]
