"""
PromptDefender — API Flask Full-Duplex
========================================
Orchestrateur des trois couches de sécurité :
  - Couche 1 : Détection par regex/signatures (PromptInjectionDetector)
  - Couche 2 : Détection ML BERT (MLDetector)
  - Couche 3 : Détection Transformer XLM-RoBERTa (TransformerDetector)

Architecture du flux Ingress :
  Client → POST /analyze → [Layer 1 Regex] ──► BLOCKED (puppetry)
                                           └──► [Layer 2 ML] ──► BLOCKED (conf > 0.9)
                                                              └──► [Layer 3 XLM-RoBERTa] ──► BLOCKED / ALLOWED

Endpoints :
  POST /analyze        — analyse complète (couche 1 + 2 + 3 si nécessaire)
  POST /layer1         — couche 1 seule (debug)
  POST /layer2         — couche 2 seule (debug)
  POST /layer3         — couche 3 seule (debug)
  GET  /health         — statut de l'API
"""

from flask import Flask, request, jsonify
import logging
import time

# ── Couche 1 ──────────────────────────────────────────────────────────────────
from promptDefender_firstLayer.detector import PromptInjectionDetector

# ── Couche 2 ──────────────────────────────────────────────────────────────────
from promptDefender_secondLayer.ml_detector2 import MLDetector

# ── Couche 3 ──────────────────────────────────────────────────────────────────
from promptDefender_thirdLayer.Transformer_detector import TransformerDetector

# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─── Initialisation des détecteurs ───────────────────────────────────────────
logger.info("Chargement de la couche 1 (regex)…")
layer1 = PromptInjectionDetector()

logger.info("Chargement de la couche 2 (ML BERT)…")
try:
    layer2 = MLDetector()
    LAYER2_AVAILABLE = True
    logger.info("Couche 2 prête.")
except FileNotFoundError as e:
    logger.warning(f"Couche 2 indisponible : {e}")
    layer2 = None
    LAYER2_AVAILABLE = False

# ── Initialisation Layer 3 ────────────────────────────────────────────────────
logger.info("Chargement de la couche 3 (XLM-RoBERTa)…")
try:
    layer3 = TransformerDetector()
    LAYER3_AVAILABLE = True
    logger.info("Couche 3 prête.")
except FileNotFoundError as e:
    logger.warning(f"Couche 3 indisponible : {e}")
    layer3 = None
    LAYER3_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_response(
    prompt: str,
    layer1_result: dict,
    layer2_result: dict | None,
    layer3_result: dict | None,
    elapsed_ms: float,
) -> dict:
    """Construit la réponse JSON finale."""

    # ── Décision finale ───────────────────────────────────────────────────────
    if layer1_result["is_puppetry"]:
        verdict    = "BLOCKED"
        blocked_by = "layer1_regex"
        reason     = "Policy puppetry détectée par signatures"

    elif (
        layer2_result is not None
        and layer2_result["confidence"] > 0.9
    ):
        verdict    = "BLOCKED"
        blocked_by = "layer2_ml"
        reason     = (
            f"Injection détectée par ML "
            f"({layer2_result['model_used']}, conf={layer2_result['confidence']})"
        )

    elif (
        layer3_result is not None
        and layer3_result.get("is_injection")
        and layer3_result["confidence"] > 0.9
    ):
        verdict    = "BLOCKED"
        blocked_by = "layer3_transformer"
        reason     = (
            f"Injection détectée par XLM-RoBERTa "
            f"(conf={layer3_result['confidence']})"
        )

    else:
        verdict    = "ALLOWED"
        blocked_by = None
        reason     = "Aucune menace détectée"

    return {
        "verdict":    verdict,
        "blocked_by": blocked_by,
        "reason":     reason,
        "layer1": {
            "policy_like":     layer1_result["policy_like"],
            "malicious":       layer1_result["malicious"],
            "is_puppetry":     layer1_result["is_puppetry"],
            "malicious_score": layer1_result["malicious_score"],
            "matches": {
                "structure": layer1_result["structure_matches"],
                "malicious": layer1_result["malicious_matches"],
            },
        },
        "layer2": layer2_result,
        "layer3": layer3_result,
        "metadata": {
            "layer2_triggered": layer2_result is not None,
            "layer3_triggered": layer3_result is not None,
            "elapsed_ms":       round(elapsed_ms, 2),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "layer1": "ready",
        "layer2": "ready" if LAYER2_AVAILABLE else "unavailable",
        "layer3": "ready" if LAYER3_AVAILABLE else "unavailable",
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyse complète : couche 1 → couche 2 → couche 3.
    Chaque couche n'est appelée que si la précédente ne bloque pas.

    Body JSON : { "prompt": "..." }
    """
    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    prompt = str(data["prompt"]).strip()
    if not prompt:
        return jsonify({"error": "Le prompt est vide."}), 400

    t0 = time.perf_counter()

    # ── Couche 1 ──────────────────────────────────────────────────────────────
    l1 = layer1.detect(prompt)

    # ── Couche 2 (uniquement si couche 1 ne bloque pas) ───────────────────────
    l2 = None
    if not l1["is_puppetry"] and LAYER2_AVAILABLE:
        try:
            l2 = layer2.predict(prompt)
        except Exception as e:
            logger.error(f"Erreur couche 2 : {e}")
            l2 = None

    # ── Couche 3 (uniquement si couche 2 ne bloque pas) ───────────────────────
    l3 = None
    l2_blocked = l2 is not None and l2["confidence"] > 0.9
    if not l1["is_puppetry"] and not l2_blocked and LAYER3_AVAILABLE:
        try:
            l3 = layer3.predict(prompt)
        except Exception as e:
            logger.error(f"Erreur couche 3 : {e}")
            l3 = None

    elapsed  = (time.perf_counter() - t0) * 1000
    response = _build_response(prompt, l1, l2, l3, elapsed)

    status_code = 200 if response["verdict"] == "ALLOWED" else 403
    return jsonify(response), status_code


@app.route("/layer1", methods=["POST"])
def debug_layer1():
    """Debug : couche 1 seule."""
    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    result = layer1.detect(str(data["prompt"]))
    return jsonify(result)


@app.route("/layer2", methods=["POST"])
def debug_layer2():
    """Debug : couche 2 seule (BERT + ML)."""
    if not LAYER2_AVAILABLE:
        return jsonify({"error": "Couche 2 non disponible."}), 503

    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    try:
        result = layer2.predict(str(data["prompt"]))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Erreur couche 2 : {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/layer3", methods=["POST"])
def debug_layer3():
    """Debug : couche 3 seule (XLM-RoBERTa)."""
    if not LAYER3_AVAILABLE:
        return jsonify({"error": "Couche 3 non disponible (modèle non entraîné)."}), 503

    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    try:
        result = layer3.predict(str(data["prompt"]))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Erreur couche 3 : {e}")
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)