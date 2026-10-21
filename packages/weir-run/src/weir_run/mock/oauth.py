"""The mock's OAuth endpoints: authorization server for every flow.

Every credential they issue (authorization code, device code, access,
refresh and ID token) is a fresh fake value, ledgered as a `mock-oauth`
placement with `minted` evidence before the reply that hands it out
(docs/canary.md, "Runtime values"). Nothing a program sends is ever
ledgered; the credential-field rules for these endpoints run in the server
before a request reaches this module.

Grants are scripted and always succeed: a code, device code or refresh
token the mock did not issue still gets tokens, and the server has already
recorded it as `unexpected`, which makes the run incomplete.
"""

from __future__ import annotations

import base64
import json
import threading
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from weir_run.ledger import Ledger
from weir_run.shapes import ALNUM, ByteSource

PREFIX = "/oauth"
TOKEN_PATH = "/oauth/token"
AUTHORIZE_PATH = "/oauth/authorize"
DEVICE_PATH = "/oauth/device_authorization"
METADATA_PATHS = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
PATHS = (TOKEN_PATH, AUTHORIZE_PATH, DEVICE_PATH, *METADATA_PATHS)

# The form fields the contract makes credential fields on these endpoints.
CREDENTIAL_FORM_FIELDS = (
    "client_secret",
    "client_assertion",
    "assertion",
    "code",
    "device_code",
    "refresh_token",
    "subject_token",
    "actor_token",
    "password",
)

GRANT_DEVICE = "urn:ietf:params:oauth:grant-type:device_code"
GRANTS = {
    "authorization_code": True,  # value: also issue a refresh token
    "refresh_token": True,
    "password": True,
    GRANT_DEVICE: True,
    "client_credentials": False,
    "urn:ietf:params:oauth:grant-type:token-exchange": False,
    "urn:ietf:params:oauth:grant-type:jwt-bearer": False,
}

USER_CODE = "BCDF-GHJK"
EXPIRES_IN = 3600
# Fixed claims: the runner never reads the wall clock (G1). exp is far ahead.
ID_TOKEN_IAT = 1_700_000_000
ID_TOKEN_EXP = 4_102_444_800

type Reply = tuple[int, bytes, str, dict[str, str]]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _json(status: int, body: object) -> Reply:
    headers = {"Cache-Control": "no-store"}
    return status, json.dumps(body).encode(), "application/json", headers


class OAuth:
    def __init__(self, ledger: Ledger, source: ByteSource) -> None:
        self.ledger = ledger
        self.source = source
        self.base_url = ""
        self._lock = threading.Lock()
        # code -> scope it was authorized for (to decide on an ID token).
        self._code_scopes: dict[str, str] = {}

    def _opaque(self) -> str:
        return self.source.choose(ALNUM, 40)

    def _mint(self, token: str) -> str:
        return self.ledger.mint(token, self._opaque).value

    def _mint_id_token(self, audience: str) -> str:
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())

        def make() -> str:
            claims = {
                "iss": self.base_url,
                "sub": self.source.choose(ALNUM, 24),
                "aud": audience,
                "iat": ID_TOKEN_IAT,
                "exp": ID_TOKEN_EXP,
            }
            payload = _b64url(json.dumps(claims).encode())
            return f"{header}.{payload}.{_b64url(self.source.read(32))}"

        return self.ledger.mint("id_token", make).value

    def metadata(self) -> Reply:
        u = self.base_url
        return _json(
            200,
            {
                "issuer": u,
                "authorization_endpoint": u + AUTHORIZE_PATH,
                "token_endpoint": u + TOKEN_PATH,
                "device_authorization_endpoint": u + DEVICE_PATH,
                "response_types_supported": ["code"],
                "grant_types_supported": sorted(GRANTS),
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
                "code_challenge_methods_supported": ["S256", "plain"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["HS256"],
            },
        )

    def authorize(self, query: dict[str, list[str]]) -> Reply:
        redirect = query.get("redirect_uri", [""])[0]
        if not redirect:
            return _json(400, {"error": "invalid_request", "error_description": "redirect_uri"})
        code = self._mint("code")
        with self._lock:
            self._code_scopes[code] = query.get("scope", [""])[0]
        params = {"code": code}
        if "state" in query:
            params["state"] = query["state"][0]
        parts = urlsplit(redirect)
        joined = "&".join(p for p in (parts.query, urlencode(params)) if p)
        location = urlunsplit(parts._replace(query=joined))
        return 302, b"", "text/plain", {"Location": location, "Cache-Control": "no-store"}

    def device(self) -> Reply:
        return _json(
            200,
            {
                "device_code": self._mint("device_code"),
                "user_code": USER_CODE,
                "verification_uri": self.base_url + PREFIX + "/device",
                "expires_in": 600,
                "interval": 1,
            },
        )

    def token(self, form: dict[str, list[str]], basic_client_id: str | None) -> Reply:
        grant = form.get("grant_type", [""])[0]
        if grant not in GRANTS:
            return _json(400, {"error": "unsupported_grant_type"})
        scope = form.get("scope", [""])[0]
        if grant == "authorization_code":
            with self._lock:
                scope = scope or self._code_scopes.get(form.get("code", [""])[0], "")
        client_id = form.get("client_id", [basic_client_id or "client"])[0]
        body: dict[str, Any] = {
            "access_token": self._mint("access_token"),
            "token_type": "Bearer",
            "expires_in": EXPIRES_IN,
        }
        if GRANTS[grant]:
            body["refresh_token"] = self._mint("refresh_token")
        if scope:
            body["scope"] = scope
        if "openid" in scope.split():
            body["id_token"] = self._mint_id_token(client_id)
        return _json(200, body)


def parse_form(body: bytes) -> dict[str, list[str]]:
    return parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
