from dataclasses import asdict
from functools import partial
from time import time
from typing import TYPE_CHECKING, List, Optional, Any, Awaitable, Literal, Dict, cast

from anyio.to_thread import run_sync
from oic import rndstr

from starlite import AbstractMiddleware, AbstractAuthenticationMiddleware, ASGIConnection, PermissionDeniedException, \
    NotAuthorizedException, AuthenticationResult, ImproperlyConfiguredException
from starlite.contrib.oidc.dtos import ClientMetaData, ProviderMetaData, UserSession
from starlite.datastructures import Headers
from starlite.response import RedirectResponse
from starlite.utils import AsyncCallable
from oic.oauth2.message import AccessTokenResponse, Message
from oic.oic import RegistrationResponse

from oic.extension.message import TokenIntrospectionResponse


if TYPE_CHECKING:
    from oic.extension.client import Client as ClientExtension
    from oic.oic import Client as OIDCClient
    from starlite.types import ASGIApp, Receive, Scope, Scopes, Send


access_token_response = AccessTokenResponse()


class TokenAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    """OIDC Middleware."""

    __slots__ = ("retrieve_user_handler", "client", "client_extension")

    def __init__(
            self,
            app: "ASGIApp",
            exclude: Optional[List[str]],
            exclude_opt_key: Optional[str],
            scopes: Optional["Scopes"],
            retrieve_user_handler: "AsyncCallable[[Any, ASGIConnection[Any, Any, Any]], Awaitable[Any]]",
            client: "OIDCClient",
            client_extension: "ClientExtension"
    ):
        super().__init__(app=app, exclude=exclude, exclude_from_auth_key=exclude_opt_key, scopes=scopes)
        self.retrieve_user_handler = retrieve_user_handler
        self.client = client
        self.client_extension = client_extension
        self.introspection_endpoint = cast("Optional[str]", getattr(self.client, "introspection_endpoint", None))


    async def authenticate_request(self, connection: "ASGIConnection[Any,Any,Any]") -> AuthenticationResult:
        """Given an HTTP Connection, parse the JWT api key stored in the header and retrieve the user correlating to the
        token from the DB.

        Args:
            connection: An Starlite HTTPConnection instance.

        Returns:
            AuthenticationResult

        Raises:
            [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is invalid or user is not found.
        """

        authorization_header = connection.headers.get("authorization", "")
        if not authorization_header or not authorization_header.startswith("Bearer"):
            raise NotAuthorizedException("missing or invalid authorization header")

        access_token = authorization_header.replace("Bearer", "").strip()

        opt = connection.scope["route_handler"].opt

        should_introspect = bool(opt.get("do_introspect_request"))
        if should_introspect:
            access_token_message = await self.request_token_introspection(access_token=access_token)
        else:
            access_token_message = access_token_response.from_jwt(txt=access_token, keyjar=self.client.keyjar)

        if not self.validate_token(token=access_token_message, scopes=opt.get("scopes")):
            raise PermissionDeniedException()

        auth = access_token_message.to_dict()
        user = await self.retrieve_user_handler(auth, connection)
        if not user:
            raise NotAuthorizedException

        return AuthenticationResult(user=user, auth=auth)

    async def request_token_introspection(self, access_token: str) -> Optional[Message]:
        """

        Args:
            access_token: Access token to be validated.

        Returns:
            Response object contains result of the token introspection.
        """
        if not self.introspection_endpoint:
            return None

        client_auth_method = self.client.registration_response.get(
            "introspection_endpoint_auth_method", "client_secret_basic"
        )

        return await run_sync(
            partial(
                self.client_extension.do_token_introspection,
                request_args={"token": access_token, "token_type_hint": "access_token"},
                authn_method=client_auth_method,
                endpoint=self.introspection_endpoint,
            )
        )

    def validate_token(
            self, token: Message, scopes: Optional[List[str]]
    ) -> bool:
        """Validate the token expiry, audience and scopes.

        Args:
            token: An OIDC Message.
            scopes: OIDC scopes required by the endpoint.

        Returns:
            A boolean dictating whether the token is valid or not.
        """

        if isinstance(token, AccessTokenResponse) and token["exp"] < time():
            return False

        if isinstance(token, TokenIntrospectionResponse) and not token.get("active"):
            return False

        if self.client.client_id not in token.get("aud"):
            return False

        if scopes and not set(scopes).issubset(token["scope"]):
            return False

        return True



class OAuthAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    """OIDC Middleware."""

    __slots__ = ("retrieve_user_handler", "client", "client_metadata", "provider_metadata", "redirect_uri", "session_refresh_seconds")

    def __init__(
            self,
            app: "ASGIApp",
            auth_request_params: Dict[str, Any],
            client: "OIDCClient",
            client_metadata: Optional["ClientMetaData"],
            exclude: Optional[List[str]],
            exclude_opt_key: Optional[str],
            provider_metadata: Optional["ProviderMetaData"],
            redirect_uri: str,
            retrieve_user_handler: "AsyncCallable[[Any, ASGIConnection[Any, Any, Any]], Awaitable[Any]]",
            scopes: Optional["Scopes"],
            session_refresh_seconds: int,
    ):
        super().__init__(app=app, exclude=exclude, exclude_from_auth_key=exclude_opt_key, scopes=scopes)
        self.auth_request_params = auth_request_params
        self.client = client
        self.client_metadata = client_metadata
        self.provider_metadata = provider_metadata
        self.redirect_uri = redirect_uri
        self.retrieve_user_handler = retrieve_user_handler
        self.session_refresh_seconds = session_refresh_seconds

    async def authenticate_request(self, connection: "ASGIConnection[Any,Any,Any]") -> AuthenticationResult:
        """Given an HTTP Connection, parse the JWT api key stored in the header and retrieve the user correlating to the
        token from the DB.

        Args:
            connection: An Starlite HTTPConnection instance.

        Returns:
            AuthenticationResult

        Raises:
            [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is invalid or user is not found.
        """
        user_session = UserSession(**connection.scope.get("session", {}))

        should_refresh_token = user_session.last_session_refresh + self.session_refresh_seconds <= time()

        if not should_refresh_token and (
                user_session.access_token_expires_at >= time() or user_session.last_authenticated is not None
        ):
            auth = user_session.user_info
            user = await self.retrieve_user_handler(auth, connection)
            if not user:
                raise NotAuthorizedException

            return AuthenticationResult(user=user, auth=auth)

        if not self.client_metadata:
            if not self.provider_metadata or not self.provider_metadata.registration_endpoint:
                raise ImproperlyConfiguredException(
                    "provider_metadata.registration_endpoint' is not set, cannot dynamically register an OpenID Connect Client"
                )

            await self.register_client()

        authorization_request = self.client.construct_AuthorizationRequest(
            request_args={
                "client_id": self.client.client_id,
                "response_type": "code",
                "scope": ["openid"],
                "redirect_uri": self.redirect_uri,
                "state": rndstr(),
                "nonce": rndstr(),
                "prompt": "none",
                **self.auth_request_params,
            }
        )


        login_url = facade.get_login_url_from_auth_request(authorization_request)

        scope.setdefault("session", {})
        scope["session"]["destination"] = scope["path"]
        scope["session"]["auth_request"] = authorization_request.to_json()
        scope["session"]["fragment_encoded_response"] = expect_fragment_encoded_response(  # type: ignore
            dict(parse_qsl(urlparse(login_url).query))
        )

        return RedirectResponse(url=login_url, status_code=HTTP_303_SEE_OTHER)

    async def register_client(self) -> None:
        """Registers the client using the OIDC Dynamic Client Registration
        Protocol.

        Notes:
            - This method can make an HTTP call to dynamically register a client.
        """
        if not self.client_metadata:
            registration_response = await run_sync(
                partial(client.register, url=self.provider_metadata.registration_endpoint, **self.client_registration_info)
            )
            self.client_metadata = ClientMetaData(**registration_response)

        registration_response = RegistrationResponse(**asdict(self.client_metadata))
        self.client.store_registration_info(registration_response)
        self.oidc_client_extension.store_registration_info(registration_response)
        self.oauth2_client.client_id = registration_response["client_id"]
        self.oauth2_client.client_secret = registration_response["client_secret"]
