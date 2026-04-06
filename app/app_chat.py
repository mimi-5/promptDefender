"""
PromptDefender — Module App : Interface Chatbot Sécurisée
==========================================================
Ce module étend l'API existante (api.py) avec :
  - Endpoint /chat  : analyse + réponse LLM en pipeline complet
  - Endpoint /stats : statistiques de session
  - Endpoint /reset : reset session stats

Architecture du flux complet :
  UI (browser) → POST /chat
                  ├─ PromptDefender Layer 1 (Regex)
                  ├─ PromptDefender Layer 2 (BERT ML)  [si L1 passe]
                  ├─ Si BLOCKED → retourne erreur 403 + détails
                  └─ Si ALLOWED → LLM (Claude / Ollama / mock) → réponse

Usage :
  python app/app_chat.py           (depuis la racine du projet)
  → Ouvre http://localhost:5001
"""

import os
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime

# ── FIX CRITIQUE : ajouter la racine du projet au sys.path ────────────────
# Peu importe d'où on lance le script, on remonte toujours à la racine
ROOT = Path(__file__).resolve().parent.parent   # app/ → racine/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# ──────────────────────────────────────────────────────────────────────────

from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Import des couches (fonctionne maintenant grâce au fix sys.path) ──────
from promptDefender_firstLayer.detector import PromptInjectionDetector
from promptDefender_secondLayer.ml_detector2 import MLDetector

# ── LLM Backend optionnel ─────────────────────────────────────────────────
try:
    import anthropic
    CLAUDE_AVAILABLE = bool(os.getenv("ANTHROPIC_API_KEY"))
except ImportError:
    CLAUDE_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("PromptDefender.App")

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────
# Initialisation des couches
# ─────────────────────────────────────────────────────────────────────────
logger.info("⚙  Chargement de la couche 1 (Regex)…")
layer1 = PromptInjectionDetector()
logger.info("✅ Couche 1 prête.")

logger.info("⚙  Chargement de la couche 2 (BERT ML)…")
try:
    layer2 = MLDetector()
    LAYER2_AVAILABLE = True
    logger.info(f"✅ Couche 2 prête — modèle : {layer2.model_name}")
except FileNotFoundError as e:
    logger.warning(f"⚠  Couche 2 indisponible : {e}")
    layer2 = None
    LAYER2_AVAILABLE = False
except Exception as e:
    logger.warning(f"⚠  Couche 2 erreur : {e}")
    layer2 = None
    LAYER2_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────
# Statistiques session (in-memory)
# ─────────────────────────────────────────────────────────────────────────
session_stats = {
    "total": 0,
    "blocked": 0,
    "allowed": 0,
    "blocked_by_layer1": 0,
    "blocked_by_layer2": 0,
    "started_at": datetime.now().isoformat(),
}
analysis_history: list = []


# ─────────────────────────────────────────────────────────────────────────
# Helpers internes
# ─────────────────────────────────────────────────────────────────────────

def _run_pipeline(prompt: str):
    """Exécute Layer 1 puis Layer 2 si nécessaire."""
    t0 = time.perf_counter()
    l1 = layer1.detect(prompt)
    l2 = None
    if not l1["is_puppetry"] and LAYER2_AVAILABLE:
        l2 = layer2.predict(prompt)
    elapsed = (time.perf_counter() - t0) * 1000
    return l1, l2, elapsed


def _build_verdict(l1: dict, l2):
    """
    Retourne (verdict, blocked_by, reason).

    Logique de décision :
      - L1 bloque si : structure suspecte ET patterns malicieux (is_puppetry)
      - L2 bloque si : confiance >= 0.92 ET le score L1 > 0
            → on exige un signal L1 non nul pour éviter les faux positifs ML
      - Sinon : ALLOWED
    """
    if l1["is_puppetry"]:
        return (
            "BLOCKED",
            "layer1_regex",
            f"Policy puppetry — {l1['malicious_score']} pattern(s) malicieux détecté(s).",
        )
    # L2 ne bloque QUE si la confiance est très haute ET L1 a aussi vu quelque chose
    if (l2 is not None
            and l2["confidence"] >= 0.92
            and l1.get("malicious_score", 0) > 0):
        return (
            "BLOCKED",
            "layer2_ml",
            f"Injection ML ({l2['model_used']}) confiance={l2['confidence']:.0%}.",
        )
    return "ALLOWED", None, "Aucune menace détectée."



# ── Config Ollama (modifiable ici) ────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")   # ou mistral, phi3, gemma2...


def _ollama_available() -> bool:
    """Vérifie si Ollama tourne en pingant /api/tags."""
    import urllib.request, urllib.error
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2):
            return True
    except Exception:
        return False


def _call_ollama(prompt: str, history: list = None) -> str:
    """
    Appelle Ollama via son API REST (/api/chat).
    Supporte l'historique de conversation multi-tour.
    """
    import urllib.request

    messages = []
    # Système : on donne un rôle clair à Ollama
    messages.append({
        "role": "system",
        "content": (
            "Tu es un assistant IA utile, précis et bienveillant. "
            "Tu réponds dans la même langue que l'utilisateur. "
            "Tu es intégré dans PromptDefender, un système de sécurité pour LLMs. "
            "Tes réponses ont déjà été filtrées — réponds normalement et avec précision."
        )
    })
    # Historique des échanges précédents (max 6 tours)
    for h in (history or [])[-6:]:
        role = h.get("role", "user")
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": h["content"]})
    # Message actuel
    messages.append({"role": "user", "content": prompt})

    body = json.dumps({
        "model":    OLLAMA_MODEL,
        "messages": messages,
        "stream":   False,
        "options": {
            "temperature": 0.7,
            "num_predict": 512,
        }
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read())
        return data["message"]["content"].strip()


def _call_llm(prompt: str, history: list = None) -> str:
    """
    Priorité LLM :
      1. Ollama local  (si disponible sur localhost:11434)
      2. Claude API    (si ANTHROPIC_API_KEY définie)
      3. Mock intelligent (toujours disponible en fallback)
    """
    # ── 1. Ollama local (priorité maximale — 100% local) ──────────────────
    if _ollama_available():
        try:
            response = _call_ollama(prompt, history)
            logger.info(f"[LLM] Ollama ({OLLAMA_MODEL}) → {len(response)} chars")
            return response
        except Exception as e:
            logger.warning(f"[LLM] Ollama error: {e} — fallback Claude/mock")

    # ── 2. Claude API (si clé configurée) ─────────────────────────────────
    if CLAUDE_AVAILABLE:
        try:
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            messages = []
            for h in (history or [])[-6:]:
                if h.get("role") in ("user", "assistant"):
                    messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": prompt})
            resp = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=512,
                system="Tu es un assistant IA utile et précis. Réponds dans la langue de l'utilisateur.",
                messages=messages,
            )
            logger.info("[LLM] Claude API")
            return resp.content[0].text
        except Exception as e:
            logger.warning(f"[LLM] Claude error: {e} — fallback mock")

    # ── 3. Mock intelligent (fallback sans LLM) ───────────────────────────
    logger.info("[LLM] Mock local (Ollama non détecté, pas de clé Claude)")
    return _mock_response(prompt)


def _mock_response(prompt: str) -> str:
    """
    Réponses de secours quand aucun LLM n'est disponible.
    Couvre les cas fréquents pour rester utile.
    """
    p = prompt.lower().strip()

    # Salutations
    if any(w in p for w in ["bonjour", "salut", "hello", "hi", "hey", "bonsoir"]):
        return "Bonjour ! Comment puis-je vous aider aujourd'hui ?"

    # Planètes
    if "planet" in p or "planète" in p:
        return (
            "Les 8 planètes du système solaire sont :\n"
            "Mercure, Vénus, Terre, Mars, Jupiter, Saturne, Uranus, Neptune.\n\n"
            "Les 4 premières sont des planètes rocheuses, les 4 dernières sont des géantes gazeuses ou glacées."
        )

    # Capitales
    if "capital" in p or "capitale" in p:
        capitales = {
            "france": "Paris", "allemagne": "Berlin", "espagne": "Madrid",
            "italie": "Rome", "angleterre": "Londres", "royaume-uni": "Londres",
            "japan": "Tokyo", "japon": "Tokyo", "chine": "Pékin",
            "algérie": "Alger", "maroc": "Rabat", "tunisie": "Tunis",
        }
        for pays, ville in capitales.items():
            if pays in p:
                return f"La capitale de {pays.capitalize()} est **{ville}**."
        return "Je connais les capitales de nombreux pays. Précisez le pays !"

    # Mathématiques simples
    import re
    math_match = re.search(r'(\d+)\s*([+\-*/×÷])\s*(\d+)', p)
    if math_match:
        try:
            a, op, b = int(math_match.group(1)), math_match.group(2), int(math_match.group(3))
            ops = {'+': a+b, '-': a-b, '*': a*b, '×': a*b}
            if op in ('/', '÷') and b != 0: ops[op] = a / b
            result = ops.get(op)
            if result is not None:
                return f"{a} {op} {b} = **{result}**"
        except Exception:
            pass

    # Code
    if any(w in p for w in ["python", "code", "script", "function", "fonction", "program"]):
        return (
            "Voici un exemple Python :\n\n"
            "```python\n"
            "def hello(name):\n"
            "    return f'Bonjour, {name} !'\n\n"
            "print(hello('Monde'))\n"
            "```\n\n"
            "Précisez ce que vous voulez programmer pour une réponse plus adaptée."
        )

    # Machine learning / IA
    if any(w in p for w in ["machine learning", "deep learning", "neural", "ia", "ai", "intelligence"]):
        return (
            "Le Machine Learning est une branche de l'IA où les algorithmes apprennent "
            "à partir de données pour faire des prédictions ou prendre des décisions, "
            "sans être explicitement programmés pour chaque tâche."
        )

    # Remerciements
    if any(w in p for w in ["merci", "thanks", "thank you", "super", "parfait"]):
        return "Avec plaisir ! N'hésitez pas si vous avez d'autres questions."

    # Question générale avec ?
    if "?" in prompt:
        sujet = prompt.replace("?", "").strip()
        return (
            f"C'est une bonne question à propos de « {sujet[:60]} ».\n\n"
            f"Pour une réponse précise, installez Ollama (ollama.ai) avec :\n"
            f"  ollama pull llama3\n"
            f"Le serveur détectera automatiquement Ollama au prochain démarrage."
        )

    # Fallback générique
    return (
        f"Je comprends votre message. Pour des réponses plus complètes et précises, "
        f"installez Ollama (ollama.ai) et lancez : ollama pull llama3\n"
        f"Le système détectera automatiquement le LLM local."
    )


def _update_stats(verdict: str, blocked_by: str = None):
    session_stats["total"] += 1
    if verdict == "BLOCKED":
        session_stats["blocked"] += 1
        if blocked_by == "layer1_regex":
            session_stats["blocked_by_layer1"] += 1
        elif blocked_by == "layer2_ml":
            session_stats["blocked_by_layer2"] += 1
    else:
        session_stats["allowed"] += 1


def _build_response_body(prompt, l1, l2, verdict, blocked_by, reason, elapsed_ms):
    return {
        "verdict":    verdict,
        "blocked_by": blocked_by,
        "reason":     reason,
        "layer1": {
            "policy_like":       l1["policy_like"],
            "malicious":         l1["malicious"],
            "is_puppetry":       l1["is_puppetry"],
            "malicious_score":   l1["malicious_score"],
            "matches": {
                "structure": l1["structure_matches"],
                "malicious": l1["malicious_matches"],
            },
        },
        "layer2": {
            "is_injection": l2["is_injection"],
            "confidence":   l2["confidence"],
            "label":        l2["label"],
            "model_used":   l2["model_used"],
            "threshold":    l2.get("threshold"),
        } if l2 else None,
        "metadata": {
            "elapsed_ms":       round(elapsed_ms, 2),
            "layer2_triggered": l2 is not None,
            "llm_backend":      "claude" if CLAUDE_AVAILABLE else "ollama_or_mock",
        },
    }


# ─────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Sert l'interface chatbot HTML."""
    html_path = Path(__file__).parent / "app_chatbot.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"}
    return (
        "<h2>PromptDefender</h2>"
        "<p>Placez <code>app_chatbot.html</code> dans le dossier <code>app/</code>.</p>"
        "<p>API disponible sur <code>/chat</code>, <code>/analyze</code>, <code>/health</code>.</p>"
    ), 200


@app.route("/chat", methods=["POST"])
def chat():
    """
    Pipeline complet : sécurité + LLM.

    Body JSON : { "prompt": "...", "history": [...] }  (history optionnel)
    Retour 200 si ALLOWED, 403 si BLOCKED.
    """
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    history = data.get("history", [])

    if not prompt:
        return jsonify({"error": "Champ 'prompt' manquant ou vide."}), 400

    l1, l2, elapsed_ms = _run_pipeline(prompt)
    verdict, blocked_by, reason = _build_verdict(l1, l2)
    _update_stats(verdict, blocked_by)

    # Historique session
    analysis_history.append({
        "ts": datetime.now().isoformat(),
        "prompt": prompt[:200],
        "verdict": verdict,
        "blocked_by": blocked_by,
    })
    if len(analysis_history) > 50:
        analysis_history.pop(0)

    body = _build_response_body(prompt, l1, l2, verdict, blocked_by, reason, elapsed_ms)

    if verdict == "BLOCKED":
        logger.info(f"🚫 BLOCKED [{blocked_by}] — {prompt[:80]!r}")
        return jsonify(body), 403

    # Appel LLM uniquement si prompt autorisé
    body["response"] = _call_llm(prompt, history)
    logger.info(f"✅ ALLOWED — {prompt[:60]!r}")
    return jsonify(body), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyse sécurité seule (compatible avec l'ancien api.py)."""
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    if not prompt:
        return jsonify({"error": "Champ 'prompt' manquant."}), 400

    l1, l2, elapsed_ms = _run_pipeline(prompt)
    verdict, blocked_by, reason = _build_verdict(l1, l2)
    _update_stats(verdict, blocked_by)

    body = _build_response_body(prompt, l1, l2, verdict, blocked_by, reason, elapsed_ms)
    return jsonify(body), (200 if verdict == "ALLOWED" else 403)


@app.route("/layer1", methods=["POST"])
def debug_layer1():
    """Debug : couche 1 seule."""
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    return jsonify(layer1.detect(prompt))


@app.route("/layer2", methods=["POST"])
def debug_layer2():
    """Debug : couche 2 seule."""
    if not LAYER2_AVAILABLE:
        return jsonify({"error": "Couche 2 non disponible."}), 503
    data   = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    return jsonify(layer2.predict(prompt))


@app.route("/health", methods=["GET"])
def health():
    ollama_ok = _ollama_available()
    return jsonify({
        "status":       "ok",
        "layer1":       "ready",
        "layer2":       "ready" if LAYER2_AVAILABLE else "unavailable",
        "llm":          f"ollama:{OLLAMA_MODEL}" if ollama_ok else ("claude" if CLAUDE_AVAILABLE else "mock"),
        "ollama":       "ready" if ollama_ok else "not running",
        "ollama_model": OLLAMA_MODEL,
        "stats":        session_stats,
    })


@app.route("/stats", methods=["GET"])
def stats():
    total = session_stats["total"]
    rate  = round(session_stats["blocked"] / total * 100, 1) if total > 0 else 0
    return jsonify({
        **session_stats,
        "block_rate_pct":   rate,
        "layer2_available": LAYER2_AVAILABLE,
        "recent_history":   analysis_history[-10:],
    })


@app.route("/stats/reset", methods=["POST"])
def reset_stats():
    session_stats.update({
        "total": 0, "blocked": 0, "allowed": 0,
        "blocked_by_layer1": 0, "blocked_by_layer2": 0,
        "started_at": datetime.now().isoformat(),
    })
    analysis_history.clear()
    return jsonify({"status": "reset ok"})


# ─────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PromptDefender — Chatbot App")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5001)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logger.info(f"🚀 Démarrage sur http://{args.host}:{args.port}")
    logger.info(f"   Racine projet : {ROOT}")
    logger.info(f"   Layer 2 : {'✅ actif' if LAYER2_AVAILABLE else '⚠  inactif'}")
    ollama_ok = _ollama_available()
    if ollama_ok:
        logger.info(f"   LLM     : ✅ Ollama détecté — modèle : {OLLAMA_MODEL}")
        logger.info(f"   Changer de modèle : OLLAMA_MODEL=mistral python app/app_chat.py")
    elif CLAUDE_AVAILABLE:
        logger.info(f"   LLM     : ✅ Claude API (Anthropic)")
    else:
        logger.info(f"   LLM     : ⚠  Mock local (installe Ollama pour un vrai LLM)")
        logger.info(f"   → https://ollama.ai  puis : ollama pull llama3")
    logger.info(f"   UI      : http://localhost:{args.port}/")

    app.run(host=args.host, port=args.port, debug=args.debug)