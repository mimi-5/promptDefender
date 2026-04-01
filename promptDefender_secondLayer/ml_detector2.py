"""
PromptDefender — Couche 2 : Détecteur ML (FIXED)
==================================================
Corrections :
  - Scaling systématiquement appliqué avant SVM / LR
  - Chargement robuste des artefacts avec vérification explicite
  - Threshold configurable post-entraînement (ROC-optimal)
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

_DEFAULT_ARTIFACTS_DIR = Path(__file__).parent / "ml_artifacts2"


class MLDetector:

    def __init__(
        self,
        artifacts_dir: Optional[Path] = None,
        bert_model_name: str = "bert-base-multilingual-cased",
        threshold: Optional[float] = None,   # None = lire depuis model_meta.json
        device: Optional[str] = None,
    ):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else _DEFAULT_ARTIFACTS_DIR

        # ── 1. Métadonnées ────────────────────────────────────────────────────
        meta_path = self.artifacts_dir / "model_meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(
                f"model_meta.json introuvable dans {self.artifacts_dir}.\n"
                "Lance d'abord ml_classification.ipynb et copie les artefacts."
            )
        with open(meta_path) as f:
            self.meta = json.load(f)

        self.model_name    = self.meta["best_model"]
        self.needs_scaling = self.meta["needs_scaling"]   # True pour SVM / LR
        bert_model_name    = self.meta.get("bert_model", bert_model_name)

        # threshold : priorité à l'argument, sinon meta, sinon 0.5
        if threshold is not None:
            self.threshold = threshold
        else:
            self.threshold = self.meta.get("threshold", 0.5)

        logger.info(
            f"Modèle : {self.model_name} | "
            f"needs_scaling={self.needs_scaling} | threshold={self.threshold}"
        )

        # ── 2. Classificateur ML ──────────────────────────────────────────────
        model_files = sorted(self.artifacts_dir.glob("best_model_*.joblib"))
        if not model_files:
            raise FileNotFoundError(
                f"Aucun best_model_*.joblib dans {self.artifacts_dir}."
            )
        self.classifier = joblib.load(model_files[0])
        logger.info(f"Classificateur chargé : {model_files[0].name}")

        # ── 3. Scaler — CRITIQUE pour SVM / LR ───────────────────────────────
        if self.needs_scaling:
            scaler_path = self.artifacts_dir / "scaler.joblib"
            if not scaler_path.exists():
                raise FileNotFoundError(
                    f"scaler.joblib introuvable dans {self.artifacts_dir}.\n"
                    f"Le modèle '{self.model_name}' requiert needs_scaling=True.\n"
                    "Vérifie que la cellule de sauvegarde du notebook a été exécutée."
                )
            self.scaler = joblib.load(scaler_path)
            logger.info("Scaler chargé.")
        else:
            self.scaler = None
            logger.info("Pas de scaler (Naive Bayes / Random Forest).")

        # ── 4. BERT multilingue ───────────────────────────────────────────────
        self.device = torch.device(
            device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        logger.info(f"Device : {self.device}")

        self.tokenizer  = AutoTokenizer.from_pretrained(bert_model_name)
        self.bert_model = AutoModel.from_pretrained(bert_model_name)
        self.bert_model.eval()
        self.bert_model = self.bert_model.to(self.device)
        logger.info(f"BERT chargé : {bert_model_name}")

    # ──────────────────────────────────────────────────────────────────────────
    # Embedding
    # ──────────────────────────────────────────────────────────────────────────

    def _embed(self, text: str, max_length: int = 128) -> np.ndarray:
        """Retourne le vecteur CLS-token, shape (1, 768)."""
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
        return outputs.last_hidden_state[:, 0, :].cpu().numpy()  # (1, 768)

    # ──────────────────────────────────────────────────────────────────────────
    # Prétraitement (identique couche 1)
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _preprocess(text: str) -> str:
        import re
        text = text.lower()
        text = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    # ──────────────────────────────────────────────────────────────────────────
    # Prédiction
    # ──────────────────────────────────────────────────────────────────────────

    def predict(self, prompt: str) -> dict:
        clean     = self._preprocess(prompt)
        embedding = self._embed(clean)          # (1, 768) NON scalé

        # ── Scaling AVANT le classifieur (SVM / LR uniquement) — FIX PRINCIPAL
        if self.needs_scaling and self.scaler is not None:
            embedding_input = self.scaler.transform(embedding)
        else:
            embedding_input = embedding

        prob_injection = float(self.classifier.predict_proba(embedding_input)[0][1])
        is_injection   = prob_injection >= self.threshold

        logger.debug(
            f"ML predict | conf={prob_injection:.4f} | threshold={self.threshold} "
            f"| {'INJECTION' if is_injection else 'BENIGN'}"
        )

        return {
            "is_injection": is_injection,
            "confidence":   round(prob_injection, 4),
            "label":        "injection" if is_injection else "benign",
            "model_used":   self.model_name,
            "threshold":    self.threshold,
        }

    def predict_batch(self, prompts: list) -> list:
        return [self.predict(p) for p in prompts]
