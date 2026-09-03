"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       PromptDefender — app_configurable.py  (BACKEND ONLY)                 ║
║                                                                              ║
║  L1  — Regex / Signatures (Ingress)                                         ║
║  L2  — BERT ML             (Ingress)                                        ║
║  L3  — XLM-RoBERTa         (Ingress)                                        ║
║  L4  — Egress (réponse LLM)                                                 ║
║                                                                              ║
║  DÉMARRAGE :                                                                 ║
║    Terminal 1 : python api.py               (port 5000)                    ║
║    Terminal 2 : ollama serve                (port 11434)                   ║
║    Terminal 3 : python app_configurable.py  (port 5003)                    ║
║    Navigateur : http://localhost:5003        → sert static/index.html       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import logging
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("PromptDefender.Configurable")

# L'interface HTML est servie depuis le dossier static/
STATIC_DIR = ROOT / "static"
app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION GLOBALE
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_API_URL = os.getenv("SECURITY_API_URL", "http://localhost:5000")
OLLAMA_URL       = os.getenv("OLLAMA_URL",        "http://localhost:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL",      "tinyllama")

ML_BLOCK_THRESHOLD_COMBINED = 0.92
ML_BLOCK_THRESHOLD_ALONE    = 0.97

# ─────────────────────────────────────────────────────────────────────────────
# ÉTAT DES COUCHES (modifiable à chaud via /config)
# ─────────────────────────────────────────────────────────────────────────────
layer_config = {
    "layer1_enabled": True,   # Regex / Signatures
    "layer2_enabled": True,   # BERT ML
    "layer3_enabled": True,   # XLM-RoBERTa
    "layer4_enabled": True,   # Egress
}

# ─────────────────────────────────────────────────────────────────────────────
# STATISTIQUES DE SESSION
# ─────────────────────────────────────────────────────────────────────────────
session_stats = {
    "total":             0,
    "blocked_ingress":   0,
    "blocked_egress":    0,
    "allowed":           0,
    "blocked_by_layer1": 0,
    "blocked_by_layer2": 0,
    "blocked_by_layer3": 0,
    "blocked_by_layer4": 0,
    "started_at":        datetime.now().isoformat(),
}
analysis_history: list = []


# ─────────────────────────────────────────────────────────────────────────────
# UTILITAIRES HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _http_post(url: str, payload: dict, timeout: int = 60) -> tuple:
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return None, str(e)


def _security_api_healthy() -> bool:
    try:
        with urllib.request.urlopen(f"{SECURITY_API_URL}/health", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def _ollama_available() -> bool:
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2):
            return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# APPELS API SÉCURITÉ
# ─────────────────────────────────────────────────────────────────────────────

def _call_security_api(prompt: str) -> dict:
    """Appelle /analyze pour obtenir les résultats bruts des 3 couches Ingress."""
    url = f"{SECURITY_API_URL}/analyze"
    logger.info(f"[SECURITE] → /analyze  prompt={prompt[:60]!r}")
    status, result = _http_post(url, {"prompt": prompt})
    if status is None:
        logger.error(f"[SECURITE] API inaccessible : {result}")
        return {
            "verdict": "ERROR", "blocked_by": None,
            "reason": f"API sécurité inaccessible ({SECURITY_API_URL}). Lance api.py.",
            "layer1": {
                "is_puppetry": False, "malicious": False, "malicious_score": 0,
                "policy_like": False, "matches": {"malicious": [], "structure": []},
            },
            "layer2": None, "layer3": None,
            "metadata": {"elapsed_ms": 0, "layer2_triggered": False, "layer3_triggered": False},
            "_api_error": True,
        }
    logger.info(f"[SECURITE] ← HTTP {status}  verdict={result.get('verdict', '?')}")
    return result


def _call_egress_api(llm_response: str) -> dict:
    """Appelle /classify_response pour l'analyse Egress (L4)."""
    url = f"{SECURITY_API_URL}/classify_response"
    logger.info(f"[EGRESS] → /classify_response  response={llm_response[:60]!r}")
    status, result = _http_post(url, {"response": llm_response})
    if status is None:
        return {
            "is_unsafe": False, "label": "UNKNOWN", "confidence": "low",
            "reason": "Egress API inaccessible - traité comme sûr",
            "elapsed_ms": 0, "_api_error": True,
        }
    logger.info(f"[EGRESS] ← HTTP {status}  label={result.get('label', '?')}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# INTERPRÉTATION DES VERDICTS (avec respect de layer_config)
# ─────────────────────────────────────────────────────────────────────────────

def _interpret_verdict(security_result: dict) -> tuple:
    """
    Interprète /analyze en tenant compte des couches activées.
    Retourne : (verdict, blocked_by, reason, layer_details)
    """
    if security_result.get("_api_error"):
        return "ERROR", None, security_result["reason"], {}

    l1 = security_result.get("layer1", {})
    l2 = security_result.get("layer2")
    l3 = security_result.get("layer3")

    layer_details = {
        "layer1": {"active": layer_config["layer1_enabled"], "triggered": False, "info": {}},
        "layer2": {"active": layer_config["layer2_enabled"], "triggered": False, "info": {}},
        "layer3": {"active": layer_config["layer3_enabled"], "triggered": False, "info": {}},
    }

    # ── Couche 1 — Regex ────────────────────────────────────────────────────
    if l1:
        layer_details["layer1"]["info"] = {
            "is_puppetry":     l1.get("is_puppetry", False),
            "malicious_score": l1.get("malicious_score", 0),
            "policy_like":     l1.get("policy_like", False),
            "matches":         l1.get("matches", {}),
        }
        if l1.get("is_puppetry"):
            layer_details["layer1"]["triggered"] = True
            if layer_config["layer1_enabled"]:
                return (
                    "BLOCKED", "layer1_regex",
                    f"Injection détectée par signatures ({l1.get('malicious_score', 0)} pattern(s)).",
                    layer_details,
                )

    # ── Couche 2 — BERT ML ──────────────────────────────────────────────────
    if l2 is not None:
        confidence = l2.get("confidence", 0)
        mal_score  = l1.get("malicious_score", 0)
        triggered  = (
            (confidence >= ML_BLOCK_THRESHOLD_COMBINED and mal_score > 0)
            or (confidence >= ML_BLOCK_THRESHOLD_ALONE)
        )
        layer_details["layer2"]["info"] = {
            "confidence": confidence,
            "label":      l2.get("label", "unknown"),
            "model":      l2.get("model_used", "?"),
        }
        if triggered:
            layer_details["layer2"]["triggered"] = True
            if layer_config["layer2_enabled"]:
                return (
                    "BLOCKED", "layer2_ml",
                    f"Injection ML ({l2.get('model_used', '?')}) confiance={confidence:.0%}.",
                    layer_details,
                )

    # ── Couche 3 — XLM-RoBERTa ─────────────────────────────────────────────
    if l3 is not None:
        conf3 = l3.get("confidence", 0)
        layer_details["layer3"]["info"] = {
            "is_injection": l3.get("is_injection", False),
            "confidence":   conf3,
        }
        if l3.get("is_injection") and conf3 > 0.9:
            layer_details["layer3"]["triggered"] = True
            if layer_config["layer3_enabled"]:
                return (
                    "BLOCKED", "layer3_transformer",
                    f"Injection XLM-RoBERTa (conf={conf3:.0%}).",
                    layer_details,
                )

    return "ALLOWED", None, "Aucune menace détectée (Ingress OK).", layer_details


def _interpret_egress_verdict(egress_result: dict) -> tuple:
    if egress_result.get("_api_error"):
        return "UNKNOWN", None, egress_result.get("reason", "Egress error")
    if egress_result.get("is_unsafe"):
        return (
            "BLOCKED_EGRESS", "layer4_egress",
            f"Réponse dangereuse : {egress_result.get('reason', 'unsafe content')}",
        )
    return "SAFE", None, "Réponse OK (Egress)."


# ─────────────────────────────────────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────────────────────────────────────

def _call_ollama(prompt: str, history: list = None) -> str:
    messages = [{
        "role": "system",
        "content": (
            "You are a helpful, precise and friendly AI assistant. "
            "Always respond in the same language as the user. "
            "You are integrated in PromptDefender, a configurable security system for LLMs."
        )
    }]
    for turn in (history or [])[-6:]:
        if turn.get("role") in ("user", "assistant"):
            messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": prompt})

    body = json.dumps({
        "model": OLLAMA_MODEL, "messages": messages,
        "stream": False, "options": {"temperature": 0.7, "num_predict": 512}
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat", data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["message"]["content"].strip()


def _mock_response(prompt: str) -> str:
    import re
    p = prompt.lower().strip()
    if any(w in p for w in ["bonjour", "salut", "hello", "hi", "hey", "salam"]):
        return "Bonjour ! Comment puis-je vous aider ?"
    math_match = re.search(r'(\d+(?:\.\d+)?)\s*([+\-*/])\s*(\d+(?:\.\d+)?)', p)
    if math_match:
        try:
            a, op, b = float(math_match.group(1)), math_match.group(2), float(math_match.group(3))
            ops = {'+': a + b, '-': a - b, '*': a * b}
            if op == '/' and b != 0:
                ops['/'] = a / b
            res = ops.get(op)
            if res is not None:
                return f"{a} {op} {b} = {int(res) if res == int(res) else round(res, 6)}"
        except Exception:
            pass
    return f"Mode mock actif (Ollama non disponible). Lance 'ollama serve' puis 'ollama pull {OLLAMA_MODEL}'."


def _get_llm_response(prompt: str, history: list = None) -> str:
    if _ollama_available():
        try:
            resp = _call_ollama(prompt, history)
            logger.info(f"[LLM] Ollama → {len(resp)} chars")
            return resp
        except Exception as e:
            logger.warning(f"[LLM] Ollama erreur : {e}")
    return _mock_response(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────────────────────────────────────

def _update_stats(verdict: str, blocked_by: str = None):
    session_stats["total"] += 1
    if verdict == "BLOCKED":
        session_stats["blocked_ingress"] += 1
        key = {
            "layer1_regex":       "blocked_by_layer1",
            "layer2_ml":          "blocked_by_layer2",
            "layer3_transformer": "blocked_by_layer3",
        }.get(blocked_by)
        if key:
            session_stats[key] += 1
    elif verdict == "BLOCKED_EGRESS":
        session_stats["blocked_egress"] += 1
        session_stats["blocked_by_layer4"] += 1
    elif verdict in ("ALLOWED", "BYPASSED"):
        session_stats["allowed"] += 1


def _add_history(prompt: str, verdict: str, blocked_by: str):
    analysis_history.append({
        "ts":           datetime.now().isoformat(),
        "prompt":       prompt[:200],
        "verdict":      verdict,
        "blocked_by":   blocked_by,
        "layers_active": {k: v for k, v in layer_config.items()},
    })
    if len(analysis_history) > 100:
        analysis_history.pop(0)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_response_body(security_result, egress_result, verdict,
                          blocked_by, reason, layer_details=None) -> dict:
    l1   = security_result.get("layer1", {})
    l2   = security_result.get("layer2")
    l3   = security_result.get("layer3")
    meta = security_result.get("metadata", {})

    return {
        "verdict":    verdict,
        "blocked_by": blocked_by,
        "reason":     reason,
        "layer_config": dict(layer_config),
        "layer1": {
            "policy_like":     l1.get("policy_like", False),
            "malicious":       l1.get("malicious", False),
            "is_puppetry":     l1.get("is_puppetry", False),
            "malicious_score": l1.get("malicious_score", 0),
            "active":          layer_config["layer1_enabled"],
            "matches":         l1.get("matches", {}),
        },
        "layer2": {
            "is_injection": l2.get("is_injection", False),
            "confidence":   l2.get("confidence", 0),
            "label":        l2.get("label", "unknown"),
            "model_used":   l2.get("model_used", "?"),
            "active":       layer_config["layer2_enabled"],
        } if l2 else None,
        "layer3": {
            "is_injection": l3.get("is_injection", False),
            "confidence":   l3.get("confidence", 0),
            "active":       layer_config["layer3_enabled"],
        } if l3 else None,
        "layer4_egress": {
            **(egress_result or {}),
            "active": layer_config["layer4_enabled"],
        },
        "layer_details": layer_details or {},
        "metadata": {
            "elapsed_ms":       meta.get("elapsed_ms", 0),
            "layer2_triggered": meta.get("layer2_triggered", False),
            "layer3_triggered": meta.get("layer3_triggered", False),
            "llm_backend":      f"ollama:{OLLAMA_MODEL}" if _ollama_available() else "mock",
            "security_api":     SECURITY_API_URL,
            "active_layers":    [k for k, v in layer_config.items() if v],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES FLASK
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Sert l'interface HTML depuis static/index.html"""
    return send_from_directory(str(STATIC_DIR), "index.html")


# ── Config des couches ────────────────────────────────────────────────────────

@app.route("/config", methods=["GET"])
def get_config():
    return jsonify(layer_config)


@app.route("/config", methods=["POST"])
def set_config():
    data = request.get_json(silent=True) or {}
    changed = []
    for key in ("layer1_enabled", "layer2_enabled", "layer3_enabled", "layer4_enabled"):
        if key in data:
            old = layer_config[key]
            layer_config[key] = bool(data[key])
            if old != layer_config[key]:
                changed.append(f"{key}: {old} → {layer_config[key]}")
    if changed:
        logger.info(f"[CONFIG] Changements: {', '.join(changed)}")
    active = [k for k, v in layer_config.items() if v]
    return jsonify({
        **layer_config,
        "active_layers": active,
        "changed":       changed,
    })


# ── Chat principal ────────────────────────────────────────────────────────────

@app.route("/chat", methods=["POST"])
def chat():
    data    = request.get_json(silent=True) or {}
    prompt  = str(data.get("prompt", "")).strip()
    history = data.get("history", [])

    if not prompt:
        return jsonify({"error": "Champ 'prompt' manquant ou vide."}), 400

    t_start = time.perf_counter()
    active_layers = [k for k, v in layer_config.items() if v]
    logger.info(f"[CHAT] Couches actives: {active_layers}")

    # ── Si AUCUNE couche Ingress active → aller directement au LLM ──────────
    any_ingress = (
        layer_config["layer1_enabled"]
        or layer_config["layer2_enabled"]
        or layer_config["layer3_enabled"]
    )

    security_result = None
    verdict         = "ALLOWED"
    blocked_by      = None
    reason          = "Ingress désactivé (toutes les couches Ingress sont off)."
    layer_details   = {}

    if any_ingress:
        security_result = _call_security_api(prompt)
        verdict, blocked_by, reason, layer_details = _interpret_verdict(security_result)
    else:
        security_result = {
            "layer1": {
                "is_puppetry": False, "malicious": False, "malicious_score": 0,
                "policy_like": False, "matches": {"malicious": [], "structure": []},
            },
            "layer2": None, "layer3": None,
            "metadata": {"elapsed_ms": 0, "layer2_triggered": False, "layer3_triggered": False},
        }

    _update_stats(verdict, blocked_by)
    _add_history(prompt, verdict, blocked_by)

    if verdict == "BLOCKED":
        logger.info(f"[BLOCKED] [{blocked_by}] — {prompt[:80]!r}")
        body = _build_response_body(security_result, None, verdict, blocked_by, reason, layer_details)
        return jsonify(body), 403

    if verdict == "ERROR":
        body = _build_response_body(security_result, None, verdict, blocked_by, reason, layer_details)
        body["response"] = f"Erreur : {reason}"
        return jsonify(body), 503

    # ── LLM ─────────────────────────────────────────────────────────────────
    llm_response = _get_llm_response(prompt, history)

    # ── Egress (L4) ─────────────────────────────────────────────────────────
    egress_result = None
    if layer_config["layer4_enabled"]:
        egress_result = _call_egress_api(llm_response)
        egress_verdict, egress_blocked_by, egress_reason = _interpret_egress_verdict(egress_result)
        if egress_verdict == "BLOCKED_EGRESS":
            logger.warning(f"[EGRESS] Bloqué — {egress_reason}")
            _update_stats("BLOCKED_EGRESS", "layer4_egress")
            _add_history(prompt, "BLOCKED_EGRESS", "layer4_egress")
            body = _build_response_body(
                security_result, egress_result,
                "BLOCKED_EGRESS", "layer4_egress", egress_reason, layer_details,
            )
            body["response"] = None
            return jsonify(body), 403
    else:
        egress_result = {"is_unsafe": False, "label": "SKIPPED", "reason": "Egress désactivé"}

    # ── Succès ───────────────────────────────────────────────────────────────
    body = _build_response_body(
        security_result, egress_result,
        "ALLOWED", None, "Aucune menace détectée.", layer_details,
    )
    body["response"] = llm_response
    body["metadata"]["total_elapsed_ms"] = round((time.perf_counter() - t_start) * 1000, 2)
    body["metadata"]["active_layers"]    = active_layers

    logger.info(f"[ALLOWED] {prompt[:60]!r} → {len(llm_response)} chars")
    return jsonify(body), 200


# ── Analyze proxy ─────────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    if not prompt:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    security_result = _call_security_api(prompt)
    verdict, blocked_by, reason, layer_details = _interpret_verdict(security_result)
    _update_stats(verdict, blocked_by)

    body = _build_response_body(security_result, None, verdict, blocked_by, reason, layer_details)
    return jsonify(body), (403 if verdict == "BLOCKED" else 200)


# ── Health / Stats ────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    sec_ok    = _security_api_healthy()
    ollama_ok = _ollama_available()
    return jsonify({
        "status":        "ok",
        "app":           "PromptDefender Configurable",
        "security_api":  "ready" if sec_ok else "DOWN",
        "security_url":  SECURITY_API_URL,
        "ollama":        "ready" if ollama_ok else "not running",
        "ollama_model":  OLLAMA_MODEL,
        "llm_backend":   f"ollama:{OLLAMA_MODEL}" if ollama_ok else "mock",
        "layer_config":  layer_config,
        "active_layers": [k for k, v in layer_config.items() if v],
        "stats":         session_stats,
    })


@app.route("/stats", methods=["GET"])
def stats_route():
    total = session_stats["total"]
    blk   = session_stats["blocked_ingress"] + session_stats["blocked_egress"]
    return jsonify({
        **session_stats,
        "block_rate_pct":  round(blk / total * 100, 1) if total > 0 else 0,
        "ollama_ready":    _ollama_available(),
        "layer_config":    layer_config,
        "recent_history":  analysis_history[-10:],
    })


@app.route("/stats/reset", methods=["POST"])
def reset_stats():
    session_stats.update({
        "total": 0, "blocked_ingress": 0, "blocked_egress": 0, "allowed": 0,
        "blocked_by_layer1": 0, "blocked_by_layer2": 0,
        "blocked_by_layer3": 0, "blocked_by_layer4": 0,
        "started_at": datetime.now().isoformat(),
    })
    analysis_history.clear()
    return jsonify({"status": "reset ok"})


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PromptDefender — Couches Configurables")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5003)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # Crée le dossier static s'il n'existe pas
    STATIC_DIR.mkdir(exist_ok=True)

    print("\n" + "=" * 64)
    print("  PromptDefender — Couches Configurables (port 5003)")
    print("=" * 64)
    print(f"  Racine projet   : {ROOT}")
    print(f"  Interface HTML  : {STATIC_DIR}/index.html")

    sec_ok = _security_api_healthy()
    print(f"  API sécurité    : {'OK ✓' if sec_ok else 'ABSENT ✗ — lance api.py'}")
    print(f"  Ollama          : {'OK ✓' if _ollama_available() else 'absent — mode mock'}")

    print(f"""
  Couches actives :
    L1 Regex        : {'ON' if layer_config['layer1_enabled'] else 'OFF'}
    L2 BERT ML      : {'ON' if layer_config['layer2_enabled'] else 'OFF'}
    L3 XLM-RoBERTa  : {'ON' if layer_config['layer3_enabled'] else 'OFF'}
    L4 Egress       : {'ON' if layer_config['layer4_enabled'] else 'OFF'}

  Config API      : POST /config  {{"layer1_enabled": true/false, ...}}
  Interface       : http://localhost:{args.port}/
    """)
    print("=" * 64 + "\n")

    app.run(host=args.host, port=args.port, debug=args.debug)
