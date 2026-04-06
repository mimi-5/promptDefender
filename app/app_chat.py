"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          PromptDefender — app_chat.py (MODULE APP — Couche 3)              ║
║                                                                              ║
║  MON TRAVAIL  : ce fichier (app_chat.py) — port 5001                       ║
║  MON COLLÈGUE : api.py — port 5000 (Couches 1 & 2 déjà faites)            ║
║                                                                              ║
║  CE QUE FAIT CE FICHIER :                                                   ║
║    1. Reçoit les messages de l'interface HTML (navigateur)                  ║
║    2. Envoie chaque prompt à api.py (collègue) pour analyse de sécurité    ║
║    3. Si BLOCKED → retourne l'erreur 403 à l'interface                     ║
║    4. Si ALLOWED → envoie le prompt à Ollama (LLM local) → retourne répons ║
║                                                                              ║
║  FLUX COMPLET :                                                              ║
║    Navigateur → POST /chat (5001)                                           ║
║         │                                                                    ║
║         ▼                                                                    ║
║    api.py:5000/analyze  (sécurité : L1 Regex + L2 ML)                      ║
║         │                                                                    ║
║    BLOCKED? → 403 → Interface affiche ⛔                                   ║
║    ALLOWED? → Ollama:11434 → réponse → Interface affiche 💬                ║
║                                                                              ║
║  DÉMARRAGE (3 terminaux) :                                                  ║
║    Terminal 1 : python api.py           (collègue, port 5000)              ║
║    Terminal 2 : ollama serve            (LLM local, port 11434)            ║
║    Terminal 3 : python app/app_chat.py  (moi, port 5001)                  ║
║    Navigateur : http://localhost:5001                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ─── Imports standard Python ──────────────────────────────────────────────────
import os               # lire les variables d'environnement (OLLAMA_URL, etc.)
import sys              # modifier sys.path pour trouver les modules du projet
import json             # encoder/décoder les données JSON dans les appels HTTP
import time             # mesurer le temps de traitement de chaque requête
import logging          # afficher des messages informatifs dans le terminal
import urllib.request   # faire des appels HTTP sans installer de bibliothèque externe
import urllib.error     # capturer les erreurs HTTP (4xx, 5xx)
from pathlib import Path        # manipuler les chemins de fichiers de façon portable
from datetime import datetime   # horodater les événements de session

# ─── FIX IMPORT CRITIQUE ──────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ─── Import Flask ─────────────────────────────────────────────────────────────
from flask import Flask, request, jsonify
from flask_cors import CORS

# ─── Configuration du logger ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("PromptDefender.App")

# ─── Création de l'application Flask ─────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_API_URL = os.getenv("SECURITY_API_URL", "http://localhost:5000")
OLLAMA_URL       = os.getenv("OLLAMA_URL",        "http://localhost:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL",      "phi3")

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
    "started_at": datetime.now().isoformat(),
}

analysis_history: list = []


# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 3) -> tuple:
    """
    Effectue un appel HTTP GET simple.

    Returns:
        (code_http, dict_réponse) ou (None, message_erreur_str)
    """
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
    """
    Effectue un appel HTTP POST avec un corps JSON.

    Returns:
        (code_http, dict_réponse) ou (None, message_erreur_str)
    """
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
    """
    Vérifie si api.py répond via GET /health (méthode correcte).
    """
    code, _ = _http_get(f"{SECURITY_API_URL}/health", timeout=3)
    return code == 200


def _call_security_api(prompt: str) -> dict:
    """
    Appelle l'API de sécurité de mon collègue (api.py, port 5000).
    """
    url = f"{SECURITY_API_URL}/analyze"
    logger.info(f"[SÉCURITÉ] → {url}  prompt={prompt[:60]!r}")

    status, result = _http_post(url, {"prompt": prompt}, timeout=15)

    if status is None:
        logger.error(f"[SÉCURITÉ] API INACCESSIBLE : {result}")
        return {
            "verdict":    "ERROR",
            "blocked_by": None,
            "reason":     f"API sécurité inaccessible ({SECURITY_API_URL}). Démarre api.py.",
            "layer1": {
                "is_puppetry": False, "malicious": False,
                "malicious_score": 0, "policy_like": False,
                "matches": {"malicious": [], "structure": []},
            },
            "layer2":   None,
            "metadata": {"elapsed_ms": 0, "layer2_triggered": False},
            "_api_error": True,
        }

    logger.info(f"[SÉCURITÉ] ← HTTP {status}  verdict={result.get('verdict', '?')}")
    return result


def _interpret_verdict(security_result: dict) -> tuple:
    """
    Interprète le résultat de l'API de sécurité pour décider le verdict final.
    """
    if security_result.get("_api_error"):
        return "ERROR", None, security_result["reason"]

    l1 = security_result.get("layer1", {})
    l2 = security_result.get("layer2")

    # RÈGLE 1 : Couche 1 (Regex)
    if l1.get("is_puppetry"):
        n_patterns = l1.get("malicious_score", 0)
        return (
            "BLOCKED",
            "layer1_regex",
            f"Injection détectée par signatures ({n_patterns} pattern(s) malicieux).",
        )

    # RÈGLES 2 & 3 : Couche 2 (ML BERT)
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

    return "ALLOWED", None, "Aucune menace détectée."


def _ollama_available() -> bool:
    """
    Vérifie si le serveur Ollama est actif en pingant /api/tags.
    """
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2):
            return True
    except Exception:
        return False


def _call_ollama(prompt: str, history: list = None) -> str:
    """
    Envoie le prompt à Ollama et retourne le texte généré.
    """
    messages = []

    messages.append({
        "role": "system",
        "content": (
            "You are a helpful, precise and friendly AI assistant. "
            "Always respond in the same language as the user "
            "(French if they write French, English if English, Arabic if Arabic, etc.). "
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
        "options": {
            "temperature": 0.7,
            "num_predict": 512,
        }
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
    """
    Obtient une réponse LLM avec fallback automatique :
      Priorité 1 → Ollama local
      Priorité 2 → Mock intelligent
    """
    if _ollama_available():
        try:
            response = _call_ollama(prompt, history)
            logger.info(f"[LLM] Ollama ({OLLAMA_MODEL}) → {len(response)} chars")
            return response
        except Exception as e:
            logger.warning(f"[LLM] Ollama erreur: {e} → basculement vers mock")

    logger.info("[LLM] Mode mock activé (Ollama non disponible)")
    return _mock_response(prompt)


def _mock_response(prompt: str) -> str:
    """
    Réponses préprogrammées quand Ollama n'est pas disponible.
    """
    import re

    p = prompt.lower().strip()

    if any(w in p for w in ["bonjour", "salut", "hello", "hi", "hey", "bonsoir", "salam"]):
        return "Bonjour ! Comment puis-je vous aider aujourd'hui ?"

    if "planet" in p or "planète" in p or "solar system" in p or "système solaire" in p:
        return (
            "Les 8 planètes du système solaire (ordre croissant de distance au Soleil) :\n\n"
            "Rocheuses : Mercure → Vénus → Terre → Mars\n"
            "Géantes   : Jupiter → Saturne → Uranus → Neptune\n\n"
            "Note : Pluton est une planète naine depuis 2006."
        )

    if "capital" in p or "capitale" in p:
        capitales = {
            "france": "Paris", "allemagne": "Berlin", "espagne": "Madrid",
            "italie": "Rome", "angleterre": "Londres", "royaume-uni": "Londres",
            "japon": "Tokyo", "japan": "Tokyo", "chine": "Pékin", "china": "Beijing",
            "algérie": "Alger", "algerie": "Alger", "maroc": "Rabat",
            "tunisie": "Tunis", "egypte": "Le Caire", "egypt": "Cairo",
            "usa": "Washington D.C.", "etats-unis": "Washington D.C.",
            "russie": "Moscou", "russia": "Moscow", "bresil": "Brasilia",
        }
        for pays, capitale in capitales.items():
            if pays in p:
                return f"La capitale est : {capitale}."
        return "Précisez le pays ! Exemple : 'quelle est la capitale de la France ?'"

    math_match = re.search(r'(\d+(?:\.\d+)?)\s*([+\-*/×÷])\s*(\d+(?:\.\d+)?)', p)
    if math_match:
        try:
            a  = float(math_match.group(1))
            op = math_match.group(2)
            b  = float(math_match.group(3))
            resultats = {'+': a + b, '-': a - b, '*': a * b, '×': a * b}
            if op in ('/', '÷') and b != 0:
                resultats[op] = a / b
            res = resultats.get(op)
            if res is not None:
                res_fmt = int(res) if res == int(res) else round(res, 6)
                a_fmt   = int(a)   if a  == int(a)  else a
                b_fmt   = int(b)   if b  == int(b)  else b
                return f"{a_fmt} {op} {b_fmt} = {res_fmt}"
        except Exception:
            pass

    if any(w in p for w in ["python", "code", "script", "function", "fonction",
                              "program", "algorithme", "algorithm", "programmer"]):
        return (
            "Voici un exemple Python :\n\n"
            "def saluer(nom):\n"
            "    return f'Bonjour, {nom} !'\n\n"
            "print(saluer('Monde'))  # → Bonjour, Monde !\n\n"
            "Décrivez votre besoin précis pour une aide plus adaptée."
        )

    if any(w in p for w in ["machine learning", "deep learning", "neural",
                              "intelligence artificielle", "ia", " ai ", "bert",
                              "transformer", "llm", "gpt"]):
        return (
            "Le Machine Learning (ML) est une branche de l'IA.\n\n"
            "Principe : les modèles apprennent automatiquement à partir\n"
            "de données, sans être explicitement programmés.\n\n"
            "Types principaux :\n"
            "• Supervisé   : apprend avec des exemples étiquetés\n"
            "• Non-supervisé: découvre des patterns sans étiquettes\n"
            "• Renforcement : apprend par essai/erreur (récompenses)"
        )

    if any(w in p for w in ["promptdefender", "sécurité", "security",
                              "injection", "layer", "couche", "defender"]):
        return (
            "PromptDefender — Architecture Full-Duplex :\n\n"
            "Couche 1 : Regex/Signatures (mon collègue - api.py)\n"
            "           → détecte les injections connues\n\n"
            "Couche 2 : ML BERT (mon collègue - api.py)\n"
            "           → détecte les injections reformulées\n\n"
            "Couche 3 : Interface Chat (moi - app_chat.py)\n"
            "           → orchestre sécurité + LLM Ollama"
        )

    if any(w in p for w in ["merci", "thanks", "thank you", "super", "parfait", "bravo"]):
        return "Avec plaisir ! N'hésitez pas si vous avez d'autres questions."

    if "?" in prompt:
        return (
            f"Je suis en mode mock (Ollama non disponible).\n"
            f"Pour activer le LLM complet :\n"
            f"  1. ollama serve\n"
            f"  2. ollama run {OLLAMA_MODEL} (première fois seulement)\n"
            f"  3. Redémarre : python app/app_chat.py\n\n"
            f"Je peux répondre aux questions sur : maths, capitales, planètes, code Python, ML."
        )

    return (
        "Mode mock actif (Ollama non disponible).\n"
        f"Lance 'ollama serve' puis 'python app/app_chat.py' pour activer {OLLAMA_MODEL}.\n\n"
        "Je reconnais : salutations, maths, capitales, planètes, Python, ML, PromptDefender."
    )


def _update_stats(verdict: str, blocked_by: str = None):
    session_stats["total"] += 1
    if verdict == "BLOCKED":
        session_stats["blocked"] += 1
        if blocked_by == "layer1_regex":
            session_stats["blocked_by_layer1"] += 1
        elif blocked_by == "layer2_ml":
            session_stats["blocked_by_layer2"] += 1
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
        "metadata": {
            "elapsed_ms":       meta.get("elapsed_ms", 0),
            "layer2_triggered": meta.get("layer2_triggered", False),
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
        "<h2>PromptDefender — Interface non trouvée</h2>"
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

    security_result              = _call_security_api(prompt)
    verdict, blocked_by, reason  = _interpret_verdict(security_result)

    _update_stats(verdict, blocked_by)
    _add_to_history(prompt, verdict, blocked_by)

    body = _build_response_body(security_result, verdict, blocked_by, reason)

    if verdict == "BLOCKED":
        logger.info(f"🚫 BLOCKED [{blocked_by}] — {prompt[:80]!r}")
        return jsonify(body), 403

    if verdict == "ERROR":
        logger.error(f"⚠  API ERROR — {reason}")
        body["response"] = f"⚠ Erreur : {reason}"
        return jsonify(body), 503

    llm_response   = _get_llm_response(prompt, history)
    body["response"] = llm_response
    body["metadata"]["total_elapsed_ms"] = round(
        (time.perf_counter() - t_start) * 1000, 2
    )

    logger.info(f"✅ ALLOWED — {prompt[:60]!r} → {len(llm_response)} chars")
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


@app.route("/health", methods=["GET"])
def health():
    """
    Statut de santé — utilise GET /health vers api.py (méthode correcte).
    """
    # ✅ CORRECTION : GET au lieu de POST pour correspondre à api.py
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
        "stats":        session_stats,
    })


@app.route("/stats", methods=["GET"])
def stats():
    total      = session_stats["total"]
    block_rate = round(session_stats["blocked"] / total * 100, 1) if total > 0 else 0
    return jsonify({
        **session_stats,
        "block_rate_pct":  block_rate,
        "ollama_ready":    _ollama_available(),
        "recent_history":  analysis_history[-10:],
    })


@app.route("/stats/reset", methods=["POST"])
def reset_stats():
    session_stats.update({
        "total": 0, "blocked": 0, "allowed": 0,
        "blocked_by_layer1": 0, "blocked_by_layer2": 0,
        "started_at": datetime.now().isoformat(),
    })
    analysis_history.clear()
    logger.info("📊 Statistiques réinitialisées")
    return jsonify({"status": "reset ok"})


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PromptDefender — Interface Chatbot")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5001)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print("\n" + "═" * 62)
    print("  PromptDefender — Interface Chatbot  (app_chat.py)")
    print("═" * 62)
    print(f"  Racine projet  : {ROOT}")

    # ✅ CORRECTION : GET au lieu de POST pour le health check au démarrage
    sec_ok = _security_api_healthy()
    if sec_ok:
        print(f"  API sécurité   : ✅ api.py répond → {SECURITY_API_URL}")
    else:
        print(f"  API sécurité   : ❌ api.py ne répond pas sur {SECURITY_API_URL}")
        print(f"                   ▶ Lance d'abord : python api.py")

    if _ollama_available():
        print(f"  LLM Ollama     : ✅ Actif → modèle : {OLLAMA_MODEL}")
    else:
        print(f"  LLM Ollama     : ⚠  Non détecté → mode mock activé")
        print(f"                   ▶ Lance : ollama serve")
        print(f"                   ▶ Puis  : ollama pull {OLLAMA_MODEL}")

    print(f"  Interface      : http://localhost:{args.port}/")
    print("═" * 62 + "\n")

    app.run(host=args.host, port=args.port, debug=args.debug)