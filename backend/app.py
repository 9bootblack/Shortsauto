import os
import secrets
import time
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

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


def state_serializer():
    if not META_STATE_SECRET:
        return None
    return URLSafeTimedSerializer(META_STATE_SECRET, salt="shortsauto-meta-oauth-v1")


@app.get("/")
def home():
    return jsonify({"ok": True, "service": "ShortsAuto API", "version": "1.3"})


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "configured": bool(CLIENT_KEY and CLIENT_SECRET and DESKTOP_API_KEY),
        "tiktok_configured": bool(CLIENT_KEY and CLIENT_SECRET and DESKTOP_API_KEY),
        "instagram_configured": bool(META_APP_ID and META_APP_SECRET and META_REDIRECT_URI and META_STATE_SECRET and DESKTOP_API_KEY),
    })


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
        r = requests.post(
            TIKTOK_TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache"},
            data={"client_key": CLIENT_KEY, "client_secret": CLIENT_SECRET,
                  "code": code, "grant_type": "authorization_code",
                  "redirect_uri": redirect_uri, "code_verifier": verifier},
            timeout=30,
        )
        try:
            payload = r.json()
        except ValueError:
            return jsonify({"ok": False, "error": "invalid_tiktok_response",
                            "message": "TikTok retornou uma resposta que não é JSON.",
