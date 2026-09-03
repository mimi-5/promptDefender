"""
PromptDefender — API Flask Full-Duplex + Egress
================================================
Orchestrateur des quatre couches de sécurité :
  - Couche 1 : Détection par regex/signatures (PromptInjectionDetector)
  - Couche 2 : Détection ML BERT (MLDetector)
  - Couche 3 : Détection Transformer XLM-RoBERTa (TransformerDetector)
  - Couche 4 : Egress LLM (EgressLLMClassifier) — vérifie la réponse LLM

Architecture du flux :
  Client → POST /analyze (prompt)  → [L1 L2 L3] → BLOCKED ou ALLOWED
  Client → POST /classify_response (response) → [L4 Egress] → SAFE ou UNSAFE

Endpoints :
  POST /analyze              — analyse complète Ingress (L1 + L2 + L3)
  POST /classify_response    — Egress seul (L4 Egress)
  POST /full_security        — Ingress + LLM response + Egress complet
  POST /layer1..3            — debug individuel
  GET  /health               — statut de l'API
"""

from flask import Flask, request, jsonify
import logging
import time
import os


# ── Couche 1 ──────────────────────────────────────────────────────────────────
from promptDefender_firstLayer.detector import PromptInjectionDetector

# ── Couche 2 ──────────────────────────────────────────────────────────────────
from promptDefender_secondLayer.ml_detector2 import MLDetector

# ── Couche 3 ──────────────────────────────────────────────────────────────────
from promptDefender_thirdLayer.Transformer_detector import TransformerDetector

# ── Couche 4 (EGRESS) ─────────────────────────────────────────────────────────
from promptDefender_egress.egress_llm_classifier import EgressLLMClassifier

# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route("/")
def home():
    return {"status": "API is running"}

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

logger.info("Chargement de la couche 3 (XLM-RoBERTa)…")
try:
    layer3 = TransformerDetector()
    LAYER3_AVAILABLE = True
    logger.info("Couche 3 prête.")
except FileNotFoundError as e:
    logger.warning(f"Couche 3 indisponible : {e}")
    layer3 = None
    LAYER3_AVAILABLE = False

# ── Couche 4 (EGRESS) ─────────────────────────────────────────────────────
logger.info("Chargement de la couche 4 (Egress LLM)…")
try:
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    egress_model = os.getenv("EGRESS_MODEL", "phi3")
    egress_clf = EgressLLMClassifier(
        ollama_url=ollama_url,
        model=egress_model,
    )
    EGRESS_AVAILABLE = True
    logger.info(f"Couche 4 prête (modèle={egress_model})")
except Exception as e:
    logger.warning(f"Couche 4 indisponible : {e}")
    egress_clf = None
    EGRESS_AVAILABLE = False

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
    """Construit la réponse JSON finale (Ingress uniquement)."""

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
    # ── Couche 4 : phi3 ou regex fallback ? ──────────────────────────────────
    egress_status = "unavailable"
    if EGRESS_AVAILABLE and egress_clf:
        if egress_clf._ollama_available():
            egress_status = "ready — phi3 (LLM actif)"
        else:
            egress_status = "ready — regex fallback (Ollama KO)"

    return jsonify({
        "status": "ok",
        "layer1": "ready",
        "layer2": "ready" if LAYER2_AVAILABLE else "unavailable",
        "layer3": "ready" if LAYER3_AVAILABLE else "unavailable",
        "layer4_egress": egress_status,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyse complète INGRESS : couche 1 → couche 2 → couche 3.
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


@app.route("/classify_response", methods=["POST"])
def classify_response():
    """
    Egress SEUL : analyse la réponse du LLM.
    
    Body JSON : { "response": "texte de réponse LLM" }
    Retour : { "is_unsafe": bool, "label": "SAFE" ou "UNSAFE", ... }
    """
    if not EGRESS_AVAILABLE or not egress_clf:
        return jsonify({"error": "Egress non disponible."}), 503

    data = request.get_json(silent=True)
    if not data or "response" not in data:
        return jsonify({"error": "Champ 'response' manquant."}), 400

    llm_response = str(data["response"]).strip()
    if not llm_response:
        return jsonify({"error": "La réponse est vide."}), 400

    result = egress_clf.classify(llm_response)
    return jsonify(result), (403 if result["is_unsafe"] else 200)


@app.route("/full_security", methods=["POST"])
def full_security():
    """
    Pipeline COMPLET : Ingress (L1+L2+L3) + Egress (L4).
    
    Body JSON : 
    {
      "prompt": "user input",
      "llm_response": "LLM generated text"  (optionnel)
    }
    
    Si llm_response fourni → analyse Ingress + Egress
    Si llm_response non fourni → analyse Ingress seulement
    """
    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    prompt = str(data["prompt"]).strip()
    if not prompt:
        return jsonify({"error": "Le prompt est vide."}), 400

    llm_response = data.get("llm_response", "").strip()

    t0 = time.perf_counter()

    # ── INGRESS ───────────────────────────────────────────────────────────────
    l1 = layer1.detect(prompt)

    l2 = None
    if not l1["is_puppetry"] and LAYER2_AVAILABLE:
        try:
            l2 = layer2.predict(prompt)
        except Exception as e:
            logger.error(f"Erreur couche 2 : {e}")

    l3 = None
    l2_blocked = l2 is not None and l2["confidence"] > 0.9
    if not l1["is_puppetry"] and not l2_blocked and LAYER3_AVAILABLE:
        try:
            l3 = layer3.predict(prompt)
        except Exception as e:
            logger.error(f"Erreur couche 3 : {e}")

    # ── EGRESS ────────────────────────────────────────────────────────────────
    l4 = None
    ingress_blocked = (
        l1["is_puppetry"] or
        (l2 is not None and l2["confidence"] > 0.9) or
        (l3 is not None and l3.get("is_injection") and l3["confidence"] > 0.9)
    )

    if llm_response and not ingress_blocked and EGRESS_AVAILABLE and egress_clf:
        try:
            l4 = egress_clf.classify(llm_response)
        except Exception as e:
            logger.error(f"Erreur couche 4 (Egress) : {e}")
            l4 = None

    elapsed = (time.perf_counter() - t0) * 1000   # ← BUG CORRIGÉ : perf_counter()

    # ── Verdict final ─────────────────────────────────────────────────────────
    if l1["is_puppetry"]:
        verdict    = "BLOCKED"
        blocked_by = "layer1_regex"
        reason     = "Injection détectée par signatures (L1)"

    elif l2 is not None and l2["confidence"] > 0.9:
        verdict    = "BLOCKED"
        blocked_by = "layer2_ml"
        reason     = f"Injection détectée par ML (L2) conf={l2['confidence']:.0%}"

    elif l3 is not None and l3.get("is_injection") and l3["confidence"] > 0.9:
        verdict    = "BLOCKED"
        blocked_by = "layer3_transformer"
        reason     = f"Injection détectée par XLM-RoBERTa (L3) conf={l3['confidence']:.0%}"

    elif l4 is not None and l4.get("is_unsafe"):
        verdict    = "BLOCKED"
        blocked_by = "layer4_egress"
        reason     = f"Réponse dangereuse détectée par Egress (L4) : {l4.get('reason', '')}"

    else:
        verdict    = "ALLOWED"
        blocked_by = None
        reason     = "Aucune menace détectée (Ingress + Egress OK)"

    return jsonify({
        "verdict": verdict,
        "blocked_by": blocked_by,
        "reason": reason,
        "layer1": {
            "policy_like": l1.get("policy_like", False),
            "malicious": l1.get("malicious", False),
            "is_puppetry": l1.get("is_puppetry", False),
            "malicious_score": l1.get("malicious_score", 0),
        },
        "layer2": l2,
        "layer3": l3,
        "layer4_egress": l4,
        "metadata": {
            "prompt_analyzed": True,
            "response_analyzed": bool(llm_response),
            "elapsed_ms": round(elapsed, 2),
            "egress_method": l4.get("method") if l4 else None,
        }
    }), (403 if verdict == "BLOCKED" else 200)


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
        return jsonify({"error": "Couche 3 non disponible."}), 503

    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    try:
        result = layer3.predict(str(data["prompt"]))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Erreur couche 3 : {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/layer4", methods=["POST"])
def debug_layer4():
    """Debug : couche 4 seule (Egress)."""
    if not EGRESS_AVAILABLE or not egress_clf:
        return jsonify({"error": "Couche 4 (Egress) non disponible."}), 503

    data = request.get_json(silent=True)
    if not data or "response" not in data:
        return jsonify({"error": "Champ 'response' manquant."}), 400

    try:
        result = egress_clf.classify(str(data["response"]))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Erreur couche 4 (Egress) : {e}")
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)