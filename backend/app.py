import os
import secrets
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
META_TOKEN_URL = "https://graph.facebook.com/v24.0/oauth/access_token"

CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "").strip()
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "").strip()
DESKTOP_API_KEY = os.environ.get("SHORTSAUTO_API_KEY", "").strip()
META_APP_ID = os.environ.get("META_APP_ID", "").strip()
META_APP_SECRET = os.environ.get("META_APP_SECRET", "").strip()
META_STATE_SECRET = os.environ.get("META_STATE_SECRET", "").strip()
META_REDIRECT_URI = os.environ.get("META_REDIRECT_URI", "").strip()


def error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def authorized():
    supplied = request.headers.get("X-ShortsAuto-Key", "")
    return bool(DESKTOP_API_KEY and secrets.compare_digest(supplied, DESKTOP_API_KEY))


def valid_redirect(uri):
    try:
        p = urlparse(uri)
        return (p.scheme == "http" and p.hostname in {"127.0.0.1", "localhost"}
                and p.port is not None and p.path == "/callback/"
                and not p.query and not p.fragment)
    except (ValueError, TypeError):
        return False


@app.get("/")
def home():
    return jsonify({"ok": True, "service": "ShortsAuto API", "version": "1.2"})


@app.get("/health")
def health():
    return jsonify({"ok": True,
                    "configured": bool(CLIENT_KEY and CLIENT_SECRET and DESKTOP_API_KEY),
                    "tiktok_configured": bool(CLIENT_KEY and CLIENT_SECRET and DESKTOP_API_KEY),
                    "instagram_configured": bool(META_APP_ID and META_APP_SECRET and META_REDIRECT_URI and DESKTOP_API_KEY)})


@app.post("/v1/tiktok/exchange")
def exchange():
    if not authorized():
        return error("unauthorized", 401)
    if not CLIENT_KEY or not CLIENT_SECRET:
        return error("TikTok OAuth is not configured.", 503)

    body = request.get_json(silent=True) or {}
    code = str(body.get("code", "")).strip()
    verifier = str(body.get("code_verifier", "")).strip()
    redirect_uri = str(body.get("redirect_uri", "")).strip()

    if not code or not verifier or not redirect_uri:
        return error("code, code_verifier and redirect_uri are required.")
    if not 43 <= len(verifier) <= 128:
        return error("Invalid code_verifier.")
    if not valid_redirect(redirect_uri):
        return error("Invalid redirect_uri.")

    try:
        r = requests.post(TIKTOK_TOKEN_URL,
                          headers={"Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache"},
                          data={"client_key": CLIENT_KEY, "client_secret": CLIENT_SECRET,
                                "code": code, "grant_type": "authorization_code",
                                "redirect_uri": redirect_uri, "code_verifier": verifier}, timeout=30)
        try:
            payload = r.json()
        except ValueError:
            return jsonify({"ok": False, "error": "invalid_tiktok_response",
                            "message": "TikTok retornou uma resposta que não é JSON.",
                            "http_status": r.status_code}), 502
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": "tiktok_connection_error",
                        "message": "Não foi possível acessar o serviço OAuth do TikTok.",
                        "exception": type(exc).__name__}), 502

    if not r.ok or payload.get("error"):
        return jsonify({"ok": False, "error": payload.get("error", "tiktok_oauth_error"),
                        "error_description": payload.get("error_description", "Falha na autorização do TikTok."),
                        "log_id": payload.get("log_id"), "http_status": r.status_code}), 400

    if not payload.get("access_token") or not payload.get("open_id"):
        return jsonify({"ok": False, "error": "invalid_tiktok_token_response",
                        "message": "TikTok não retornou access_token/open_id.",
                        "received_fields": list(payload.keys())}), 502

    return jsonify({"ok": True, "access_token": payload.get("access_token"),
                    "refresh_token": payload.get("refresh_token"),
                    "expires_in": payload.get("expires_in"),
                    "refresh_expires_in": payload.get("refresh_expires_in"),
                    "open_id": payload.get("open_id"), "scope": payload.get("scope"),
                    "token_type": payload.get("token_type", "Bearer")})


@app.post("/v1/instagram/exchange")
def instagram_exchange():
    if not authorized():
        return error("unauthorized", 401)
    if not META_APP_ID or not META_APP_SECRET or not META_REDIRECT_URI:
        return error("Instagram OAuth is not configured.", 503)

    body = request.get_json(silent=True) or {}
    code = str(body.get("code", "")).strip()
    redirect_uri = str(body.get("redirect_uri", "")).strip()
    if not code or not redirect_uri:
        return error("code and redirect_uri are required.")
    if not secrets.compare_digest(redirect_uri, META_REDIRECT_URI):
        return error("Invalid redirect_uri.")

    try:
        response = requests.get(META_TOKEN_URL,
                                params={"client_id": META_APP_ID,
                                        "client_secret": META_APP_SECRET,
                                        "redirect_uri": META_REDIRECT_URI,
                                        "code": code}, timeout=30)
        try:
            payload = response.json()
        except ValueError:
            return error("invalid_meta_response", 502)
    except requests.RequestException:
        return error("meta_connection_error", 502)

    if not response.ok or payload.get("error"):
        meta_error = payload.get("error") or {}
        return jsonify({"ok": False, "error": "meta_oauth_error",
                        "message": meta_error.get("message", "Falha na autorização do Instagram."),
                        "http_status": response.status_code}), 400

    if not payload.get("access_token"):
        return error("invalid_meta_token_response", 502)

    return jsonify({"ok": True, "access_token": payload["access_token"],
                    "token_type": payload.get("token_type", "bearer"),
                    "expires_in": payload.get("expires_in")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
