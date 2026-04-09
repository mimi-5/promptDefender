"""
PromptDefender — Flask Orchestrator
====================================
Full-duplex firewall: Layer 1 (Regex) → Layer 2 (ML/BERT) → Layer 3 (XLM-RoBERTa)

Endpoints
---------
POST /analyze   Full pipeline
POST /layer1    Layer 1 only  (debug)
POST /layer2    Layer 2 only  (debug)
POST /layer3    Layer 3 only  (debug)
GET  /health    Service status
"""

import time

from flask import Flask, jsonify, request

from promptDefender_firstLayer.detector import PromptInjectionDetector
from promptDefender_secondLayer.ml_detector2 import MLDetector
from promptDefender_thirdLayer.llm_detector import LLMDetector

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Load detectors once at startup
# ---------------------------------------------------------------------------
print("[PromptDefender] Loading Layer 1 (Regex)…")
layer1 = PromptInjectionDetector()

print("[PromptDefender] Loading Layer 2 (ML/BERT)…")
layer2 = MLDetector()

print("[PromptDefender] Loading Layer 3 (XLM-RoBERTa)…")
try:
    layer3 = LLMDetector()
    LAYER3_AVAILABLE = True
    print("[PromptDefender] Layer 3 ready.")
except FileNotFoundError as e:
    layer3 = None
    LAYER3_AVAILABLE = False
    print(f"[PromptDefender] WARNING: Layer 3 not available — {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_prompt(req) -> tuple[str, dict | None]:
    """Extract prompt from JSON body. Returns (prompt, error_response)."""
    data = req.get_json(silent=True)
    if not data or "prompt" not in data:
        return "", jsonify({"error": "Missing 'prompt' field in JSON body"}), 400
    return data["prompt"], None


def _run_layer1(prompt: str) -> dict:
    result = layer1.analyze(prompt)
    return {
        "is_puppetry":     result.get("is_puppetry", False),
        "malicious_score": result.get("malicious_score", 0),
    }


def _run_layer2(prompt: str) -> dict:
    result = layer2.predict(prompt)
    return {
        "is_injection": result.get("is_injection", False),
        "confidence":   result.get("confidence", 0.0),
        "model_used":   result.get("model_used", "unknown"),
        "threshold":    result.get("threshold", 0.5),
    }


def _run_layer3(prompt: str) -> dict:
    if not LAYER3_AVAILABLE:
        return {
            "is_injection": False,
            "confidence":   None,
            "threshold":    None,
            "elapsed_ms":   None,
            "error":        "Layer 3 artifacts not found. Run the fine-tuning notebook first.",
        }
    result = layer3.predict(prompt)
    return {
        "is_injection": result["is_injection"],
        "confidence":   result["confidence"],
        "threshold":    result["threshold"],
        "elapsed_ms":   result["elapsed_ms"],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Full pipeline: Layer 1 → Layer 2 → Layer 3.
    Each layer is only called if the previous one did not block the prompt.
    """
    t_start = time.perf_counter()

    prompt, err = _get_prompt(request)
    if err:
        return err

    # ── Layer 1 ─────────────────────────────────────────────────────────────
    l1 = _run_layer1(prompt)
    if l1["is_puppetry"]:
        return jsonify({
            "verdict":    "BLOCKED",
            "blocked_by": "layer1_regex",
            "reason":     "Policy puppetry detected by regex engine",
            "layer1":     l1,
            "layer2":     None,
            "layer3":     None,
            "metadata": {
                "layer2_triggered": False,
                "layer3_triggered": False,
                "elapsed_ms":       round((time.perf_counter() - t_start) * 1000, 2),
            },
        })

    # ── Layer 2 ─────────────────────────────────────────────────────────────
    l2 = _run_layer2(prompt)
    if l2["is_injection"]:
        return jsonify({
            "verdict":    "BLOCKED",
            "blocked_by": "layer2_ml",
            "reason":     f"Injection detected by ML ({l2['model_used']}, conf={l2['confidence']})",
            "layer1":     l1,
            "layer2":     l2,
            "layer3":     None,
            "metadata": {
                "layer2_triggered": True,
                "layer3_triggered": False,
                "elapsed_ms":       round((time.perf_counter() - t_start) * 1000, 2),
            },
        })

    # ── Layer 3 ─────────────────────────────────────────────────────────────
    l3 = _run_layer3(prompt)
    if l3.get("is_injection"):
        return jsonify({
            "verdict":    "BLOCKED",
            "blocked_by": "layer3_llm",
            "reason":     f"Injection detected by fine-tuned XLM-RoBERTa (conf={l3['confidence']})",
            "layer1":     l1,
            "layer2":     l2,
            "layer3":     l3,
            "metadata": {
                "layer2_triggered": True,
                "layer3_triggered": True,
                "elapsed_ms":       round((time.perf_counter() - t_start) * 1000, 2),
            },
        })

    # ── ALLOWED ──────────────────────────────────────────────────────────────
    return jsonify({
        "verdict":    "ALLOWED",
        "blocked_by": None,
        "reason":     "No injection detected by any layer",
        "layer1":     l1,
        "layer2":     l2,
        "layer3":     l3,
        "metadata": {
            "layer2_triggered": True,
            "layer3_triggered": True,
            "elapsed_ms":       round((time.perf_counter() - t_start) * 1000, 2),
        },
    })


@app.route("/layer1", methods=["POST"])
def debug_layer1():
    prompt, err = _get_prompt(request)
    if err:
        return err
    return jsonify(_run_layer1(prompt))


@app.route("/layer2", methods=["POST"])
def debug_layer2():
    prompt, err = _get_prompt(request)
    if err:
        return err
    return jsonify(_run_layer2(prompt))


@app.route("/layer3", methods=["POST"])
def debug_layer3():
    prompt, err = _get_prompt(request)
    if err:
        return err
    return jsonify(_run_layer3(prompt))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":           "ok",
        "layer1":           "ready",
        "layer2":           "ready",
        "layer3":           "ready" if LAYER3_AVAILABLE else "unavailable (artifacts missing)",
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
