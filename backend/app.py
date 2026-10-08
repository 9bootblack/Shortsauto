import os
import secrets
import time
from urllib.parse import urlparse, urlencode
from threading import Lock
from flask import redirect, Response

import requests
from flask import Flask, jsonify, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)
_OAUTH_SESSIONS = {}
_OAUTH_LOCK = Lock()
_OAUTH_TTL = 600

TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
META_TOKEN_URL = "https://graph.facebook.com/v24.0/oauth/access_token"
IG_TOKEN_URL = "https://api.instagram.com/oauth/access_token"
IG_LONG_TOKEN_URL = "https://graph.instagram.com/access_token"

CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "").strip()
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "").strip()
DESKTOP_API_KEY = os.environ.get("SHORTSAUTO_API_KEY", "").strip()
META_APP_ID = os.environ.get("META_APP_ID", "").strip()
META_APP_SECRET = os.environ.get("META_APP_SECRET", "").strip()
META_STATE_SECRET = os.environ.get("META_STATE_SECRET", "").strip()
META_REDIRECT_URI = os.environ.get("META_REDIRECT_URI", "").strip()
IG_APP_ID = os.environ.get("IG_APP_ID", "").strip()
IG_APP_SECRET = os.environ.get("IG_APP_SECRET", "").strip()
IG_REDIRECT_URI = os.environ.get("IG_REDIRECT_URI", "").strip()


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
        "instagram_configured": bool(IG_APP_ID and IG_APP_SECRET and IG_REDIRECT_URI and META_STATE_SECRET and DESKTOP_API_KEY),
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


@app.post("/v1/instagram/state")
def instagram_state():
    """Issue a short-lived, signed OAuth state. Requires the desktop API key."""
    if not authorized():
        return error("unauthorized", 401)
    serializer = state_serializer()
    if serializer is None:
        return error("Instagram OAuth state is not configured.", 503)
    return jsonify({"ok": True, "state": serializer.dumps({"nonce": secrets.token_urlsafe(24)}),
                    "expires_in": 600})


def _cleanup_oauth():
    now = time.time()
    for key in list(_OAUTH_SESSIONS):
        if now - _OAUTH_SESSIONS[key]["created"] > _OAUTH_TTL:
            del _OAUTH_SESSIONS[key]


@app.post("/v1/meta/start")
def meta_start():
    if not authorized():
        return error("unauthorized", 401)
    if not all((META_APP_ID, META_APP_SECRET, META_REDIRECT_URI, META_STATE_SECRET)):
        return error("instagram_oauth_not_configured", 503)
    state = secrets.token_urlsafe(32)
    poll_key = secrets.token_urlsafe(32)
    with _OAUTH_LOCK:
        _cleanup_oauth()
        _OAUTH_SESSIONS[state] = {"poll_key": poll_key, "created": time.time(), "status": "pending"}
    params = {"client_id": META_APP_ID, "redirect_uri": META_REDIRECT_URI,
              "state": state, "response_type": "code",
              "scope": "pages_show_list,instagram_basic,instagram_content_publish,pages_read_engagement"}
    return jsonify({"ok": True, "url": "https://www.facebook.com/v24.0/dialog/oauth?" + urlencode(params),
                    "state": state, "poll_key": poll_key})


@app.get("/v1/meta/callback")
def meta_callback():
    state = request.args.get("state", "")
    with _OAUTH_LOCK:
        session = _OAUTH_SESSIONS.get(state)
        if not session or time.time() - session["created"] > _OAUTH_TTL:
            return Response("Sessão inválida ou expirada. Volte ao ShortsAuto.", status=400)
        if session["status"] != "pending":
            return Response("Esta autorização já foi utilizada.", status=409)
        if request.args.get("error"):
            session.update(status="error", message="Autorização recusada no Facebook.")
            return Response("Autorização cancelada. Pode fechar esta aba.", content_type="text/plain; charset=utf-8")
        code = request.args.get("code", "")
        if not code:
            session.update(status="error", message="Código de autorização ausente.")
            return Response("Código ausente.", status=400)
        session["status"] = "processing"
    try:
        r = requests.get(META_TOKEN_URL, params={"client_id": META_APP_ID,
            "client_secret": META_APP_SECRET, "redirect_uri": META_REDIRECT_URI,
            "code": code}, timeout=30)
        data = r.json()
        if not r.ok or not data.get("access_token"):
            raise RuntimeError((data.get("error") or {}).get("message", "Falha no OAuth Meta"))
        with _OAUTH_LOCK:
            session.update(status="done", token=data["access_token"])
        return Response("Instagram autorizado! Volte ao ShortsAuto. Pode fechar esta aba.", content_type="text/plain; charset=utf-8")
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        with _OAUTH_LOCK:
            session.update(status="error", message=str(exc)[:300])
        return Response("Não foi possível concluir a autorização. Volte ao ShortsAuto.", status=502)


@app.post("/v1/meta/poll")
def meta_poll():
    if not authorized():
        return error("unauthorized", 401)
    body = request.get_json(silent=True) or {}
    state = str(body.get("state", ""))
    poll_key = str(body.get("poll_key", ""))
    with _OAUTH_LOCK:
        _cleanup_oauth()
        session = _OAUTH_SESSIONS.get(state)
        if not session or not poll_key or not secrets.compare_digest(poll_key, session["poll_key"]):
            return error("invalid_or_expired_session", 404)
        status = session["status"]
        if status == "done":
            token = session.pop("token")
            del _OAUTH_SESSIONS[state]
            return jsonify({"ok": True, "status": "done", "access_token": token})
        if status == "error":
            message = session.get("message", "Erro de autorização")
            del _OAUTH_SESSIONS[state]
            return jsonify({"ok": False, "status": "error", "message": message})
        return jsonify({"ok": True, "status": status})


@app.post("/v1/instagram/start")
def ig_start():
    if not authorized():
        return error("unauthorized", 401)
    if not all((IG_APP_ID, IG_APP_SECRET, IG_REDIRECT_URI, META_STATE_SECRET)):
        return error("instagram_login_not_configured", 503)
    state, poll_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with _OAUTH_LOCK:
        _cleanup_oauth()
        _OAUTH_SESSIONS[state] = {"poll_key": poll_key, "created": time.time(),
                                  "status": "pending", "provider": "instagram"}
    params = {"client_id": IG_APP_ID, "redirect_uri": IG_REDIRECT_URI,
              "response_type": "code", "state": state,
              "scope": "instagram_business_basic,instagram_business_content_publish",
              "enable_fb_login": "0", "force_authentication": "1"}
    return jsonify({"ok": True, "url": "https://www.instagram.com/oauth/authorize?" + urlencode(params),
                    "state": state, "poll_key": poll_key})


@app.get("/v1/instagram/callback")
def ig_callback():
    state = request.args.get("state", "")
    with _OAUTH_LOCK:
        session = _OAUTH_SESSIONS.get(state)
        if not session or session.get("provider") != "instagram" or time.time() - session["created"] > _OAUTH_TTL:
            return Response("Sessão inválida ou expirada.", status=400)
        if session["status"] != "pending":
            return Response("Autorização já utilizada.", status=409)
        if request.args.get("error"):
            session.update(status="error", message="Autorização recusada no Instagram.")
            return Response("Autorização cancelada. Pode fechar esta aba.", content_type="text/plain; charset=utf-8")
        code = request.args.get("code", "")
        if not code:
            session.update(status="error", message="Código de autorização ausente.")
            return Response("Código ausente.", status=400)
        session["status"] = "processing"
    try:
        r = requests.post(IG_TOKEN_URL, data={"client_id": IG_APP_ID, "client_secret": IG_APP_SECRET,
                         "grant_type": "authorization_code", "redirect_uri": IG_REDIRECT_URI,
                         "code": code}, timeout=30)
        payload = r.json()
        if not r.ok or not payload.get("access_token"):
            raise RuntimeError("Não foi possível trocar o código OAuth do Instagram.")
        token = payload["access_token"]
        # Troca opcional por token de longa duração (60 dias).
        long_resp = requests.get(IG_LONG_TOKEN_URL, params={"grant_type": "ig_exchange_token",
                            "client_secret": IG_APP_SECRET, "access_token": token}, timeout=30)
        if long_resp.ok:
            long_data = long_resp.json()
            token = long_data.get("access_token") or token
        with _OAUTH_LOCK:
            session.update(status="done", token=token)
        return Response("Instagram autorizado! Volte ao ShortsAuto e feche esta aba.",
                        content_type="text/plain; charset=utf-8")
    except (requests.RequestException, ValueError, RuntimeError):
        with _OAUTH_LOCK:
            session.update(status="error", message="Falha ao concluir login do Instagram.")
        return Response("Falha ao concluir login. Volte ao ShortsAuto.", status=502)


@app.post("/v1/instagram/poll")
def ig_poll():
    if not authorized():
        return error("unauthorized", 401)
    body = request.get_json(silent=True) or {}
    state, poll_key = str(body.get("state", "")), str(body.get("poll_key", ""))
    with _OAUTH_LOCK:
        _cleanup_oauth()
        session = _OAUTH_SESSIONS.get(state)
        if not session or session.get("provider") != "instagram" or not poll_key or not secrets.compare_digest(poll_key, session["poll_key"]):
            return error("invalid_or_expired_session", 404)
        status = session["status"]
        if status == "done":
            token = session.pop("token")
            del _OAUTH_SESSIONS[state]
            return jsonify({"ok": True, "status": "done", "access_token": token})
        if status == "error":
            message = session.get("message", "Erro de autorização")
            del _OAUTH_SESSIONS[state]
            return jsonify({"ok": False, "status": "error", "message": message})
        return jsonify({"ok": True, "status": status})


@app.post("/v1/instagram/exchange")
def instagram_exchange():
    """Legacy server-side code exchange. Caller must supply the configured redirect URI."""
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
        response = requests.get(
            META_TOKEN_URL,
            params={"client_id": META_APP_ID, "client_secret": META_APP_SECRET,
                    "redirect_uri": META_REDIRECT_URI, "code": code},
            timeout=30,
        )
        try:
            payload = response.json()
        except ValueError:
            return error("invalid_meta_response", 502)
    except requests.RequestException:
        return error("meta_connection_error", 502)

    if not response.ok or payload.get("error"):
        meta_error = payload.get("error") or {}
        message = meta_error.get("message", "Falha na autorização do Instagram.") if isinstance(meta_error, dict) else "Falha na autorização do Instagram."
        return jsonify({"ok": False, "error": "meta_oauth_error",
                        "message": message, "http_status": response.status_code}), 400
    if not payload.get("access_token"):
        return error("invalid_meta_token_response", 502)
    return jsonify({"ok": True, "access_token": payload["access_token"],
                    "token_type": payload.get("token_type", "bearer"),
                    "expires_in": payload.get("expires_in")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
