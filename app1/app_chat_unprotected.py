"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       PromptDefender — app_chat_unprotected.py (SANS PROTECTION)           ║
║                                                                              ║
║  CE QUE FAIT CE FICHIER :                                                   ║
║    1. Reçoit les messages de l'interface HTML (navigateur)                  ║
║    2. Envoie le prompt DIRECTEMENT à Ollama — AUCUNE couche de sécurité    ║
║    3. Retourne la réponse brute du LLM                                      ║
║                                                                              ║
║  USAGE : Tests / comparaison avec la version protégée                       ║
║  ⚠  NE PAS UTILISER EN PRODUCTION                                          ║
║                                                                              ║
║  DÉMARRAGE :                                                                 ║
║    Terminal 1 : ollama serve            (LLM local, port 11434)            ║
║    Terminal 2 : python app/app_chat_unprotected.py  (port 5002)            ║
║    Navigateur : http://localhost:5002                                        ║
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
logger = logging.getLogger("PromptDefender.Unprotected")

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")

# ─────────────────────────────────────────────────────────────────────────────
# STATISTIQUES DE SESSION
# ─────────────────────────────────────────────────────────────────────────────
session_stats = {
    "total":      0,
    "started_at": datetime.now().isoformat(),
}

chat_history_log: list = []


# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

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
            "Always respond in the same language as the user."
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
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read())
        return data["message"]["content"].strip()


def _mock_response(prompt: str) -> str:
    import re
    p = prompt.lower().strip()
    if any(w in p for w in ["bonjour", "salut", "hello", "hi", "hey"]):
        return "Bonjour ! Comment puis-je vous aider ?"
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
    return (
        f"Mode mock actif (Ollama non disponible).\n"
        f"Lance 'ollama serve' puis 'ollama pull {OLLAMA_MODEL}' pour activer le LLM."
    )


def _get_llm_response(prompt: str, history: list = None) -> str:
    if _ollama_available():
        try:
            response = _call_ollama(prompt, history)
            logger.info(f"[LLM] Ollama ({OLLAMA_MODEL}) → {len(response)} chars")
            return response
        except Exception as e:
            logger.warning(f"[LLM] Ollama erreur: {e} → basculement vers mock")
    logger.info("[LLM] Mode mock actif")
    return _mock_response(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES FLASK
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    html_path = Path(__file__).parent / "app_chatbot_unprotected.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8"), 200, {
            "Content-Type": "text/html; charset=utf-8"
        }
    return (
        "<h2>Interface non trouvée</h2>"
        f"<p>Placez <code>app_chatbot_unprotected.html</code> dans "
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
    session_stats["total"] += 1

    llm_response = _get_llm_response(prompt, history)
    elapsed_ms   = round((time.perf_counter() - t_start) * 1000, 2)

    chat_history_log.append({
        "ts":     datetime.now().isoformat(),
        "prompt": prompt[:200],
    })
    if len(chat_history_log) > 50:
        chat_history_log.pop(0)

    logger.info(f"[UNPROTECTED] {prompt[:60]!r} → {len(llm_response)} chars ({elapsed_ms} ms)")

    return jsonify({
        "response":   llm_response,
        "model":      OLLAMA_MODEL,
        "elapsed_ms": elapsed_ms,
        "protected":  False,
    }), 200


@app.route("/health", methods=["GET"])
def health():
    ollama_ok = _ollama_available()
    return jsonify({
        "status":      "ok",
        "mode":        "UNPROTECTED — no security layers",
        "ollama":      "ready" if ollama_ok else "not running",
        "ollama_model": OLLAMA_MODEL,
        "llm_backend": f"ollama:{OLLAMA_MODEL}" if ollama_ok else "mock",
        "stats":       session_stats,
    })


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify({
        **session_stats,
        "ollama_ready":   _ollama_available(),
        "recent_history": chat_history_log[-10:],
    })


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PromptDefender — Chat Non Protégé")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=5002)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print("\n" + "=" * 62)
    print("  PromptDefender — Chat SANS PROTECTION  ⚠")
    print("=" * 62)
    print(f"  Racine projet  : {ROOT}")
    print(f"  ⚠  AUCUNE couche de sécurité active")
    print(f"  ⚠  Usage : tests / comparaison uniquement")

    if _ollama_available():
        print(f"  LLM Ollama     : Actif → modele : {OLLAMA_MODEL}")
    else:
        print(f"  LLM Ollama     : Non détecté → mode mock actif")
        print(f"                   Lance : ollama serve")

    print(f"  Interface      : http://localhost:{args.port}/")
    print("=" * 62 + "\n")

    app.run(host=args.host, port=args.port, debug=args.debug)