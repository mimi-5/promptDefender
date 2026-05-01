"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          PromptDefender — app_chat.py (MODULE APP — Couches 1+2+3)         ║
║                                                                              ║
║  CE QUE FAIT CE FICHIER :                                                   ║
║    1. Reçoit les messages de l'interface HTML (navigateur)                  ║
║    2. Envoie chaque prompt à api.py (port 5000) pour analyse de sécurité   ║
║    3. Si BLOCKED → retourne l'erreur 403 à l'interface                     ║
║    4. Si ALLOWED → envoie le prompt à Ollama (LLM local) → retourne répons ║
║                                                                              ║
║  FLUX COMPLET :                                                              ║
║    Navigateur → POST /chat (5001)                                           ║
║         │                                                                    ║
║         ▼                                                                    ║
║    api.py:5000/analyze  (L1 Regex + L2 ML + L3 XLM-RoBERTa)               ║
║         │                                                                    ║
║    BLOCKED? → 403 → Interface affiche ⛔                                   ║
║    ALLOWED? → Ollama:11434 → réponse → Interface affiche 💬                ║
║                                                                              ║
║  DÉMARRAGE (3 terminaux) :                                                  ║
║    Terminal 1 : python api.py           (port 5000)                        ║
║    Terminal 2 : ollama serve            (LLM local, port 11434)            ║
║    Terminal 3 : python app/app_chat.py  (port 5001)                        ║
║    Navigateur : http://localhost:5001                                        ║
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

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, request, jsonify
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("PromptDefender.App")

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_API_URL = os.getenv("SECURITY_API_URL", "http://localhost:5000")
OLLAMA_URL       = os.getenv("OLLAMA_URL",        "http://localhost:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL",      "tinyllama")    # génère
EGRESS_MODEL     = os.getenv("EGRESS_MODEL",       "phi3")        # classifie

# ─────────────────────────────────────────────────────────────────────────────
# EGRESS — Chargement du classifieur de sortie
# Analyse la réponse de tinyllama AVANT de l'afficher à l'utilisateur.
# Utilise few-shot prompting — aucun entraînement requis.
# ─────────────────────────────────────────────────────────────────────────────
try:
    from promptDefender_egress.egress_llm_classifier import EgressLLMClassifier
    egress_clf       = EgressLLMClassifier(
        ollama_url = OLLAMA_URL,
        model      = EGRESS_MODEL,
    )
    EGRESS_AVAILABLE = True
    logger.info("✅ Egress LLM Classifier prêt")
except Exception as _e:
    egress_clf       = None
    EGRESS_AVAILABLE = False
    logger.warning(f"⚠ Egress non disponible : {_e}")

ML_BLOCK_THRESHOLD_COMBINED = 0.92
ML_BLOCK_THRESHOLD_ALONE    = 0.97

# ─────────────────────────────────────────────────────────────────────────────
# STATISTIQUES DE SESSION
# ─────────────────────────────────────────────────────────────────────────────
session_stats = {
    "total":             0,
    "blocked":           0,
    "allowed":           0,
    "blocked_by_layer1": 0,
    "blocked_by_layer2": 0,
    "blocked_by_layer3": 0,
    "started_at": datetime.now().isoformat(),
}

analysis_history: list = []


# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 3) -> tuple:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return None, str(e)


def _http_post(url: str, payload: dict, timeout: int = 10) -> tuple:
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=body,
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
    code, _ = _http_get(f"{SECURITY_API_URL}/health", timeout=3)
    return code == 200


def _call_security_api(prompt: str) -> dict:
    url = f"{SECURITY_API_URL}/analyze"
    logger.info(f"[SECURITE] → {url}  prompt={prompt[:60]!r}")

    status, result = _http_post(url, {"prompt": prompt}, timeout=60)

    if status is None:
        logger.error(f"[SECURITE] API INACCESSIBLE : {result}")
        return {
            "verdict":    "ERROR",
            "blocked_by": None,
            "reason":     f"API securite inaccessible ({SECURITY_API_URL}). Demarre api.py.",
            "layer1": {
                "is_puppetry": False, "malicious": False,
                "malicious_score": 0, "policy_like": False,
                "matches": {"malicious": [], "structure": []},
            },
            "layer2":   None,
            "layer3":   None,
            "metadata": {"elapsed_ms": 0, "layer2_triggered": False, "layer3_triggered": False},
            "_api_error": True,
        }

    logger.info(f"[SECURITE] ← HTTP {status}  verdict={result.get('verdict', '?')}")
    return result


def _interpret_verdict(security_result: dict) -> tuple:
    if security_result.get("_api_error"):
        return "ERROR", None, security_result["reason"]

    l1 = security_result.get("layer1", {})
    l2 = security_result.get("layer2")
    l3 = security_result.get("layer3")

    # REGLE 1 : Couche 1 (Regex)
    if l1.get("is_puppetry"):
        n_patterns = l1.get("malicious_score", 0)
        return (
            "BLOCKED",
            "layer1_regex",
            f"Injection detectee par signatures ({n_patterns} pattern(s) malicieux).",
        )

    # REGLES 2 & 3 : Couche 2 (ML BERT)
    if l2 is not None:
        confidence = l2.get("confidence", 0)
        mal_score  = l1.get("malicious_score", 0)
        rule2 = (confidence >= ML_BLOCK_THRESHOLD_COMBINED and mal_score > 0)
        rule3 = (confidence >= ML_BLOCK_THRESHOLD_ALONE)
        if rule2 or rule3:
            model = l2.get("model_used", "?")
            return (
                "BLOCKED",
                "layer2_ml",
                f"Injection ML ({model}) confiance={confidence:.0%}.",
            )

    # REGLE 4 : Couche 3 (XLM-RoBERTa)
    if l3 is not None:
        if l3.get("is_injection") and l3.get("confidence", 0) > 0.9:
            return (
                "BLOCKED",
                "layer3_transformer",
                f"Injection detectee par XLM-RoBERTa (conf={l3['confidence']:.0%}).",
            )

    return "ALLOWED", None, "Aucune menace detectee."


def _ollama_available() -> bool:
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2):
            return True
    except Exception:
        return False


def _call_ollama(prompt: str, history: list = None) -> str:
    messages = []
    messages.append({
        "role": "system",
        "content": (
            "You are a helpful, precise and friendly AI assistant. "
            "Always respond in the same language as the user. "
            "You are integrated in PromptDefender, a security system for LLMs. "
            "All messages have been pre-filtered for safety — respond normally."
        )
    })
    for turn in (history or [])[-6:]:
        role = turn.get("role", "user")
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": turn["content"]})
    messages.append({"role": "user", "content": prompt})

    body = json.dumps({
        "model":    OLLAMA_MODEL,
        "messages": messages,
        "stream":   False,
        "options":  {"temperature": 0.7, "num_predict": 512}
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read())
        return data["message"]["content"].strip()


def _get_llm_response(prompt: str, history: list = None) -> str:
    if _ollama_available():
        try:
            response = _call_ollama(prompt, history)
            logger.info(f"[LLM] Ollama ({OLLAMA_MODEL}) → {len(response)} chars")
            return response
        except Exception as e:
            logger.warning(f"[LLM] Ollama erreur: {e} → basculement vers mock")
    logger.info("[LLM] Mode mock active (Ollama non disponible)")
    return _mock_response(prompt)


def _mock_response(prompt: str) -> str:
    import re
    p = prompt.lower().strip()

    if any(w in p for w in ["bonjour", "salut", "hello", "hi", "hey", "bonsoir", "salam"]):
        return "Bonjour ! Comment puis-je vous aider aujourd'hui ?"

    if "planet" in p or "planete" in p or "solar system" in p:
        return (
            "Les 8 planetes du systeme solaire :\n\n"
            "Rocheuses : Mercure → Venus → Terre → Mars\n"
            "Geantes   : Jupiter → Saturne → Uranus → Neptune"
        )

    if "capital" in p or "capitale" in p:
        capitales = {
            "france": "Paris", "allemagne": "Berlin", "espagne": "Madrid",
            "italie": "Rome", "angleterre": "Londres", "japon": "Tokyo",
            "algerie": "Alger", "maroc": "Rabat", "tunisie": "Tunis",
        }
        for pays, capitale in capitales.items():
            if pays in p:
                return f"La capitale est : {capitale}."
        return "Precisez le pays !"

    math_match = re.search(r'(\d+(?:\.\d+)?)\s*([+\-*/])\s*(\d+(?:\.\d+)?)', p)
    if math_match:
        try:
            a, op, b = float(math_match.group(1)), math_match.group(2), float(math_match.group(3))
            res = {'+': a+b, '-': a-b, '*': a*b}.get(op)
            if op == '/' and b != 0: res = a / b
            if res is not None:
                return f"{a} {op} {b} = {int(res) if res == int(res) else round(res, 6)}"
        except Exception:
            pass

    if any(w in p for w in ["python", "code", "function", "fonction", "algorithm"]):
        return (
            "Voici un exemple Python :\n\n"
            "def saluer(nom):\n"
            "    return f'Bonjour, {nom} !'\n\n"
            "print(saluer('Monde'))  # → Bonjour, Monde !"
        )

    if any(w in p for w in ["machine learning", "deep learning", "ia", " ai ", "bert", "transformer"]):
        return (
            "Le Machine Learning est une branche de l'IA.\n"
            "Les modeles apprennent automatiquement a partir de donnees.\n\n"
            "Types : Supervise | Non-supervise | Renforcement"
        )

    return (
        f"Mode mock actif (Ollama non disponible).\n"
        f"Lance 'ollama serve' puis 'ollama pull {OLLAMA_MODEL}' pour activer le LLM."
    )


def _update_stats(verdict: str, blocked_by: str = None):
    session_stats["total"] += 1
    if verdict in ("BLOCKED", "BLOCKED_EGRESS"):
        session_stats["blocked"] += 1
        if blocked_by == "layer1_regex":
            session_stats["blocked_by_layer1"] += 1
        elif blocked_by == "layer2_ml":
            session_stats["blocked_by_layer2"] += 1
        elif blocked_by == "layer3_transformer":
            session_stats["blocked_by_layer3"] += 1
        elif blocked_by == "egress_llm":
            session_stats.setdefault("blocked_by_egress", 0)
            session_stats["blocked_by_egress"] += 1
    elif verdict == "ALLOWED":
        session_stats["allowed"] += 1


def _add_to_history(prompt: str, verdict: str, blocked_by: str):
    analysis_history.append({
        "ts":         datetime.now().isoformat(),
        "prompt":     prompt[:200],
        "verdict":    verdict,
        "blocked_by": blocked_by,
    })
    if len(analysis_history) > 50:
        analysis_history.pop(0)


def _build_response_body(security_result: dict, verdict: str,
                          blocked_by: str, reason: str) -> dict:
    l1   = security_result.get("layer1", {})
    l2   = security_result.get("layer2")
    l3   = security_result.get("layer3")
    meta = security_result.get("metadata", {})

    return {
        "verdict":    verdict,
        "blocked_by": blocked_by,
        "reason":     reason,
        "layer1": {
            "policy_like":     l1.get("policy_like", False),
            "malicious":       l1.get("malicious", False),
            "is_puppetry":     l1.get("is_puppetry", False),
            "malicious_score": l1.get("malicious_score", 0),
            "matches": {
                "structure": l1.get("matches", {}).get("structure", []),
                "malicious": l1.get("matches", {}).get("malicious", []),
            },
        },
        "layer2": {
            "is_injection": l2.get("is_injection", False),
            "confidence":   l2.get("confidence", 0),
            "label":        l2.get("label", "unknown"),
            "model_used":   l2.get("model_used", "?"),
            "threshold":    l2.get("threshold"),
        } if l2 else None,
        "layer3": {
            "is_injection": l3.get("is_injection", False),
            "confidence":   l3.get("confidence", 0),
            "threshold":    l3.get("threshold"),
            "elapsed_ms":   l3.get("elapsed_ms"),
        } if l3 else None,
        "metadata": {
            "elapsed_ms":       meta.get("elapsed_ms", 0),
            "layer2_triggered": meta.get("layer2_triggered", False),
            "layer3_triggered": meta.get("layer3_triggered", False),
            "llm_backend":      f"ollama:{OLLAMA_MODEL}" if _ollama_available() else "mock",
            "security_api":     SECURITY_API_URL,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES FLASK
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    html_path = Path(__file__).parent / "app_chatbot.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8"), 200, {
            "Content-Type": "text/html; charset=utf-8"
        }
    return (
        "<h2>PromptDefender — Interface non trouvee</h2>"
        f"<p>Placez <code>app_chatbot.html</code> dans "
        f"<code>{Path(__file__).parent}</code></p>"
    ), 200


@app.route("/chat", methods=["POST"])
def chat():
    data    = request.get_json(silent=True) or {}
    prompt  = str(data.get("prompt", "")).strip()
    history = data.get("history", [])

    if not prompt:
        return jsonify({"error": "Champ 'prompt' manquant ou vide."}), 400

    t_start = time.perf_counter()

    security_result             = _call_security_api(prompt)
    verdict, blocked_by, reason = _interpret_verdict(security_result)

    _update_stats(verdict, blocked_by)
    _add_to_history(prompt, verdict, blocked_by)

    body = _build_response_body(security_result, verdict, blocked_by, reason)

    if verdict == "BLOCKED":
        logger.info(f"BLOCKED [{blocked_by}] — {prompt[:80]!r}")
        return jsonify(body), 403

    if verdict == "ERROR":
        logger.error(f"API ERROR — {reason}")
        body["response"] = f"Erreur : {reason}"
        return jsonify(body), 503

    llm_response = _get_llm_response(prompt, history)

    # ── EGRESS : vérifier la réponse AVANT de l'envoyer au navigateur ────────
    # tinyllama classifie sa propre réponse via few-shot prompting
    egress_result = None
    if EGRESS_AVAILABLE and egress_clf:
        egress_result = egress_clf.classify(llm_response)
        if egress_result["is_unsafe"]:
            logger.warning(f"[EGRESS] 🚨 BLOQUÉ — {egress_result['reason']}")
            _update_stats("BLOCKED", "egress_llm")
            _add_to_history(prompt, "BLOCKED_EGRESS", "egress_llm")
            body["verdict"]    = "BLOCKED_EGRESS"
            body["blocked_by"] = "egress_llm"
            body["reason"]     = f"Egress : {egress_result['reason']}"
            body["egress"]     = egress_result
            body["response"]   = None
            return jsonify(body), 403

    body["response"] = llm_response
    body["egress"]   = egress_result
    body["metadata"]["total_elapsed_ms"] = round(
        (time.perf_counter() - t_start) * 1000, 2
    )

    logger.info(f"ALLOWED — {prompt[:60]!r} → {len(llm_response)} chars")
    return jsonify(body), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    if not prompt:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    security_result             = _call_security_api(prompt)
    verdict, blocked_by, reason = _interpret_verdict(security_result)
    _update_stats(verdict, blocked_by)

    body = _build_response_body(security_result, verdict, blocked_by, reason)
    return jsonify(body), (403 if verdict == "BLOCKED" else 200)


@app.route("/egress", methods=["POST"])
def debug_egress():
    """
    Debug : teste l'Egress seul sur une réponse LLM.
    Utile pour tester sans lancer les 3 couches Ingress.

    Body JSON : { "response": "texte à classifier" }
    """
    if not EGRESS_AVAILABLE or not egress_clf:
        return jsonify({"error": "Egress non disponible."}), 503

    data     = request.get_json(silent=True) or {}
    response = str(data.get("response", "")).strip()
    if not response:
        return jsonify({"error": "Champ 'response' manquant."}), 400

    result = egress_clf.classify(response)
    return jsonify(result)


@app.route("/layer1", methods=["POST"])
def debug_layer1():
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    _, result = _http_post(f"{SECURITY_API_URL}/layer1", {"prompt": prompt}, timeout=10)
    return jsonify(result)


@app.route("/layer2", methods=["POST"])
def debug_layer2():
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    _, result = _http_post(f"{SECURITY_API_URL}/layer2", {"prompt": prompt}, timeout=10)
    return jsonify(result)


@app.route("/layer3", methods=["POST"])
def debug_layer3():
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    _, result = _http_post(f"{SECURITY_API_URL}/layer3", {"prompt": prompt}, timeout=60)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    security_ok = _security_api_healthy()
    ollama_ok   = _ollama_available()
    return jsonify({
        "status":       "ok",
        "app_chat":     "ready",
        "security_api": "ready" if security_ok else "DOWN",
        "security_url": SECURITY_API_URL,
        "ollama":       "ready" if ollama_ok else "not running",
        "ollama_model": OLLAMA_MODEL,
        "llm_backend":  f"ollama:{OLLAMA_MODEL}" if ollama_ok else "mock",
        "layer3":       "ready" if security_ok else "unknown",
        "stats":        session_stats,
    })


@app.route("/stats", methods=["GET"])
def stats():
    total      = session_stats["total"]
    block_rate = round(session_stats["blocked"] / total * 100, 1) if total > 0 else 0
    return jsonify({
        **session_stats,
        "block_rate_pct": block_rate,
        "ollama_ready":   _ollama_available(),
        "recent_history": analysis_history[-10:],
    })


@app.route("/stats/reset", methods=["POST"])
def reset_stats():
    session_stats.update({
        "total": 0, "blocked": 0, "allowed": 0,
        "blocked_by_layer1": 0, "blocked_by_layer2": 0, "blocked_by_layer3": 0,
        "started_at": datetime.now().isoformat(),
    })
    analysis_history.clear()
    logger.info("Statistiques reinitialisees")
    return jsonify({"status": "reset ok"})


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PromptDefender — Interface Chatbot")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5001)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print("\n" + "=" * 62)
    print("  PromptDefender — Interface Chatbot  (app_chat.py)")
    print("=" * 62)
    print(f"  Racine projet  : {ROOT}")

    sec_ok = _security_api_healthy()
    if sec_ok:
        print(f"  API securite   : OK api.py repond → {SECURITY_API_URL}")
    else:
        print(f"  API securite   : ERREUR api.py ne repond pas sur {SECURITY_API_URL}")
        print(f"                   Lance d'abord : python api.py")

    if _ollama_available():
        print(f"  LLM Ollama     : Actif → modele : {OLLAMA_MODEL}")
    else:
        print(f"  LLM Ollama     : Non detecte → mode mock active")
        print(f"                   Lance : ollama serve")

    print(f"  Interface      : http://localhost:{args.port}/")
    print("=" * 62 + "\n")

    app.run(host=args.host, port=args.port, debug=args.debug)