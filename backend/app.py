import os
import secrets
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "").strip()
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "").strip()
DESKTOP_API_KEY = os.environ.get("SHORTSAUTO_API_KEY", "").strip()


def error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def valid_redirect(uri):
    try:
        p = urlparse(uri)
        return (p.scheme == "http" and p.hostname in {"127.0.0.1", "localhost"}
                and p.port is not None and p.path == "/callback/"
                and not p.query and not p.fragment)
    except Exception:
        return False


@app.get("/")
def home():
    return jsonify({"ok": True, "service": "ShortsAuto API", "version": "1.0"})


@app.get("/health")
def health():
    return jsonify({"ok": True, "configured": bool(CLIENT_KEY and CLIENT_SECRET and DESKTOP_API_KEY)})


@app.post("/v1/tiktok/exchange")
def exchange():
    supplied = request.headers.get("X-ShortsAuto-Key", "")
    if not DESKTOP_API_KEY or not secrets.compare_digest(supplied, DESKTOP_API_KEY):
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
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
            timeout=20,
        )
        payload = r.json()
    except (requests.RequestException, ValueError):
        return error("TikTok token service is unavailable.", 502)

    if not r.ok:
        return jsonify({"ok": False, "error": "tiktok_oauth_error", "details": payload}), r.status_code

    return jsonify({
        "ok": True,
        "access_token": payload.get("access_token"),
        "refresh_token": payload.get("refresh_token"),
        "expires_in": payload.get("expires_in"),
        "refresh_expires_in": payload.get("refresh_expires_in"),
        "open_id": payload.get("open_id"),
        "scope": payload.get("scope"),
        "token_type": payload.get("token_type"),
    })
