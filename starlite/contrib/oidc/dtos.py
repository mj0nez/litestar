from dataclasses import dataclass
from time import time
from typing import Optional, Dict, Any


@dataclass
class ClientMetaData:
    """Container for OIC Client meta data."""

    client_id: Optional[str] = None
    """
    Identifier representing the client.
    """
    client_secret: Optional[str] = None
    """
    Secret to authenticate the client with the OP.
    """
    extra: Optional[Dict[str, Any]] = None
    """
    Kwargs to pass to the client on init.
    """

@dataclass()
class ProviderMetaData:
    """Container for an OpenID Connect Provider (OP)."""

    issuer: Optional[str] = None
    """
    OP Issuer Identifier.
    """
    authorization_endpoint: Optional[str] = None
    """
    URL of the OP's OAuth 2.0 Authorization endpoint.
    """
    jwks_uri: Optional[str] = None
    """
    URL of the OP's JSON Web Key Set [JWK] document.
    """
    token_endpoint: Optional[str] = None
    """
    URL of the OP's OAuth 2.0 Token endpoint.
    """
    user_info_endpoint: Optional[str] = None
    """
    URL of the OP's user_info endpoint.
    """
    end_session_endpoint: Optional[str] = None
    """
    URL of the OP's end Session endpoint.
    """
    introspection_endpoint: Optional[str] = None
    """
    URL of the OP's token introspection endpoint.
    """
    registration_endpoint: Optional[str] = None
    """
    URL of the OP's Dynamic Client Registration endpoint.
    """
    revocation_endpoint: Optional[str] = None
    """
    URL of the OP's token revocation endpoint.
    """
    extra: Optional[Dict[str, Any]] = None
    """
    Extra arguments to OpenID Provider Metadata.

    Notes:
        - see the [openID reference](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
            for further details.
    """


@dataclass
class UserSession:
    """User session object that can track authenticating against multiple
    providers."""

    access_token: Optional[str] = None
    access_token_expires_at: int = 0
    id_token: Optional[Dict[str, Any]] = None
    id_token_jwt: Optional[str] = None
    last_authenticated: Optional[int] = None
    last_session_refresh: int = 0
    refresh_token: Optional[str] = None
    user_info: Optional[Dict[str, Any]] = None

    def update(
            self,
            *,
            access_token: Optional[str] = None,
            expires_in: Optional[int] = None,
            id_token: Optional[Dict[str, Any]] = None,
            id_token_jwt: Optional[str] = None,
            refresh_token: Optional[str] = None,
            user_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        now = int(time())
        self.last_authenticated = id_token.get("auth_time", now)
        self.last_session_refresh = now

        if access_token:
            self.access_token = access_token
        if expires_in:
            self.access_token_expires_at = now + expires_in
        if id_token:
            self.id_token = id_token
        if id_token_jwt:
            self.id_token_jwt = id_token_jwt
        if user_info:
            self.user_info = user_info
        if refresh_token:
            self.refresh_token = refresh_token

