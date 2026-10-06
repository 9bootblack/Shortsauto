import os
import secrets
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request


app = Flask(__name__)


# ============================================================
# CONFIGURAÇÕES
# ============================================================

TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"

CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "").strip()
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "").strip()
DESKTOP_API_KEY = os.environ.get("SHORTSAUTO_API_KEY", "").strip()


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def error(message, status=400):
    return jsonify({
        "ok": False,
        "error": message
    }), status


def valid_redirect(uri):
    """
    Aceita apenas callback local usado pelo ShortsAuto.

    Exemplos:
    http://127.0.0.1:54321/callback/
    http://localhost:54321/callback/
    """

    try:
        p = urlparse(uri)

        return (
            p.scheme == "http"
            and p.hostname in {"127.0.0.1", "localhost"}
            and p.port is not None
            and p.path == "/callback/"
            and not p.query
            and not p.fragment
        )

    except Exception:
        return False


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return jsonify({
        "ok": True,
        "service": "ShortsAuto API",
        "version": "1.1"
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "configured": bool(
            CLIENT_KEY
            and CLIENT_SECRET
            and DESKTOP_API_KEY
        )
    })


# ============================================================
# TIKTOK - TROCAR AUTHORIZATION CODE POR TOKENS
# ============================================================

@app.post("/v1/tiktok/exchange")
def exchange():

    # --------------------------------------------------------
    # 1. VALIDAR API KEY DO SHORTSAUTO
    # --------------------------------------------------------

    supplied = request.headers.get("X-ShortsAuto-Key", "")

    if (
        not DESKTOP_API_KEY
        or not secrets.compare_digest(
            supplied,
            DESKTOP_API_KEY
        )
    ):
        return error(
            "unauthorized",
            401
        )


    # --------------------------------------------------------
    # 2. VERIFICAR CONFIGURAÇÃO DO TIKTOK
    # --------------------------------------------------------

    if not CLIENT_KEY or not CLIENT_SECRET:
        return error(
            "TikTok OAuth is not configured.",
            503
        )


    # --------------------------------------------------------
    # 3. RECEBER DADOS DO SHORTSAUTO
    # --------------------------------------------------------

    body = request.get_json(silent=True) or {}

    code = str(
        body.get("code", "")
    ).strip()

    verifier = str(
        body.get("code_verifier", "")
    ).strip()

    redirect_uri = str(
        body.get("redirect_uri", "")
    ).strip()


    # --------------------------------------------------------
    # 4. VALIDAR DADOS
    # --------------------------------------------------------

    if not code or not verifier or not redirect_uri:
        return error(
            "code, code_verifier and redirect_uri are required."
        )


    if not 43 <= len(verifier) <= 128:
        return error(
            "Invalid code_verifier."
        )


    if not valid_redirect(redirect_uri):
        return error(
            "Invalid redirect_uri."
        )


    # --------------------------------------------------------
    # 5. ENVIAR AUTHORIZATION CODE PARA O TIKTOK
    # --------------------------------------------------------

    try:

        r = requests.post(
            TIKTOK_TOKEN_URL,

            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded",

                "Cache-Control":
                    "no-cache",
            },

            data={
                "client_key":
                    CLIENT_KEY,

                "client_secret":
                    CLIENT_SECRET,

                "code":
                    code,

                "grant_type":
                    "authorization_code",

                "redirect_uri":
                    redirect_uri,

                "code_verifier":
                    verifier,
            },

            timeout=30,
        )


        # ----------------------------------------------------
        # TENTAR LER JSON DO TIKTOK
        # ----------------------------------------------------

        try:

            payload = r.json()

        except ValueError:

            return jsonify({
                "ok": False,
                "error": "invalid_tiktok_response",
                "message":
                    "TikTok retornou uma resposta que não é JSON.",
                "http_status":
                    r.status_code
            }), 502


    except requests.RequestException as exc:

        return jsonify({
            "ok": False,
            "error": "tiktok_connection_error",
            "message":
                "Não foi possível acessar o serviço OAuth do TikTok.",
            "exception":
                type(exc).__name__
        }), 502


    # --------------------------------------------------------
    # 6. VERIFICAR ERRO RETORNADO PELO TIKTOK
    # --------------------------------------------------------

    if not r.ok or payload.get("error"):

        return jsonify({
            "ok": False,

            "error":
                payload.get(
                    "error",
                    "tiktok_oauth_error"
                ),

            "error_description":
                payload.get(
                    "error_description",
                    "Falha na autorização do TikTok."
                ),

            "log_id":
                payload.get("log_id"),

            "http_status":
                r.status_code

        }), 400


    # --------------------------------------------------------
    # 7. PEGAR TOKENS
    # --------------------------------------------------------

    access_token = payload.get(
        "access_token"
    )

    refresh_token = payload.get(
        "refresh_token"
    )

    open_id = payload.get(
        "open_id"
    )

    expires_in = payload.get(
        "expires_in"
    )

    refresh_expires_in = payload.get(
        "refresh_expires_in"
    )

    scope = payload.get(
        "scope"
    )

    token_type = payload.get(
        "token_type",
        "Bearer"
    )


    # --------------------------------------------------------
    # 8. VALIDAR RESPOSTA
    # --------------------------------------------------------

    if not access_token or not open_id:

        return jsonify({
            "ok": False,

            "error":
                "invalid_tiktok_token_response",

            "message":
                "TikTok não retornou access_token/open_id.",

            # Apenas nomes dos campos.
            # NÃO retorna tokens.
            "received_fields":
                list(payload.keys())

        }), 502


    # --------------------------------------------------------
    # 9. RETORNAR TOKENS PARA O SHORTSAUTO
    # --------------------------------------------------------

    return jsonify({

        "ok":
            True,

        "access_token":
            access_token,

        "refresh_token":
            refresh_token,

        "expires_in":
            expires_in,

        "refresh_expires_in":
            refresh_expires_in,

        "open_id":
            open_id,

        "scope":
            scope,

        "token_type":
            token_type

    })


# ============================================================
# EXECUÇÃO LOCAL
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
