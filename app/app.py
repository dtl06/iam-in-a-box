"""Portail RH de Nordivia : application cliente OIDC de Keycloak.

À lancer sur la machine hôte (pas dans Docker) : le navigateur et Flask doivent
joindre Keycloak par la même URL, sinon l'émetteur (issuer) des jetons ne correspond plus.
"""
import os
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, session, url_for

# Un seul .env pour tout le dépôt
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM = "nordivia"
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # signe le cookie de session
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    # Authlib y lit toutes les URL utiles (authorize, token, jwks, logout…)
    server_metadata_url=f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration",
    # code_challenge_method active PKCE : Authlib génère et envoie le code_verifier lui-même
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)


def session_keycloak_active():
    """Demande à Keycloak si le jeton d'accès est toujours valide (introspection, RFC 7662).

    Le cookie Flask seul ne suffit pas : si Keycloak ferme la session (départ traité
    par jml.py, déconnexion forcée), il faut que le portail le voie immédiatement.
    """
    token = session.get("access_token")
    if not token:
        return False
    endpoint = oauth.keycloak.load_server_metadata()["introspection_endpoint"]
    reponse = requests.post(
        endpoint,
        data={"token": token, "token_type_hint": "access_token"},
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=5,
    )
    return reponse.ok and reponse.json().get("active", False)


def login_requis(vue):
    @wraps(vue)
    def wrapper(*args, **kwargs):
        if not session_keycloak_active():
            session.clear()
            return redirect(url_for("login"))
        return vue(*args, **kwargs)
    return wrapper


def role_requis(role):
    def decorateur(vue):
        @wraps(vue)
        @login_requis
        def wrapper(*args, **kwargs):
            if role not in session["user"]["roles"]:
                abort(403)
            return vue(*args, **kwargs)
        return wrapper
    return decorateur


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.route("/login")
def login():
    return oauth.keycloak.authorize_redirect(url_for("callback", _external=True))


@app.route("/callback")
def callback():
    # Échange code → jetons (avec client_secret + code_verifier), puis vérifie
    # la signature, l'émetteur, l'audience et l'expiration de l'ID token
    token = oauth.keycloak.authorize_access_token()
    claims = token["userinfo"]

    # On ne garde que l'utile : le cookie de session est limité à ~4 Ko
    session["user"] = {
        "username": claims.get("preferred_username"),
        "nom": claims.get("name"),
        "email": claims.get("email"),
        "matricule": claims.get("matricule"),
        "poste": claims.get("poste"),
        "service": claims.get("service"),
        "roles": claims.get("realm_access", {}).get("roles", []),
    }
    session["access_token"] = token["access_token"]
    session["id_token"] = token["id_token"]
    return redirect(url_for("profil"))


@app.route("/profil")
@login_requis
def profil():
    return render_template("profil.html", user=session["user"])


@app.route("/admin")
@role_requis("admin_it")
def admin():
    return render_template("admin.html", user=session["user"])


@app.route("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()  # ferme la session locale…

    # …puis la session SSO chez Keycloak, sinon /login reconnecterait sans mot de passe
    params = {"post_logout_redirect_uri": url_for("index", _external=True), "client_id": CLIENT_ID}
    if id_token:
        params["id_token_hint"] = id_token  # évite la page de confirmation de Keycloak
    end_session = oauth.keycloak.load_server_metadata()["end_session_endpoint"]
    return redirect(f"{end_session}?{urlencode(params)}")


@app.errorhandler(403)
def interdit(_erreur):
    return render_template("403.html", user=session.get("user")), 403


if __name__ == "__main__":
    # localhost (et non 127.0.0.1) : doit correspondre exactement aux redirect URIs du client
    app.run(host="localhost", port=5000, debug=True)
