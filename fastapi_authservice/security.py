from typing import Any, Callable, Optional

from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.base import SecurityBase
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN, HTTP_200_OK


class JWTBase(SecurityBase):
    def __init__(
        self,
        *,
        verifier: Callable[[Any], Any],
        decoder: Callable[[Any], Any],
        scheme_name: str = None,
        auto_error: bool = True
    ):
        self.verify = verifier
        self.decode = decoder
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error
        self.model: APIKey = None
        self.getter = None

    async def __call__(self, request: Request) -> Optional[dict]:
        token = self.getter(request).get(self.model.name)

        if not token:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None

        verified_token = await self.verify(token)
        return self.decode(verified_token)


class JWTCookie(JWTBase):
    def __init__(
        self,
        *,
        name: str,
        verifier: Callable[[Any], Any],
        decoder: Callable[[Any], Any],
        scheme_name: str = None,
        auto_error: bool = True
    ):
        super().__init__(
            verifier=verifier,
            decoder=decoder,
            scheme_name=scheme_name,
            auto_error=auto_error,
        )

        self.model: APIKey = APIKey(**{"in": APIKeyIn.cookie}, name=name)
        self.getter = lambda x: x.cookies


class JWTHeader(JWTBase):
    def __init__(
        self,
        *,
        name: str,
        verifier: Callable[[Any], Any],
        decoder: Callable[[Any], Any],
        scheme_name: str = None,
        auto_error: bool = True
    ):
        super().__init__(
            verifier=verifier,
            decoder=decoder,
            scheme_name=scheme_name,
            auto_error=auto_error,
        )

        self.model: APIKey = APIKey(**{"in": APIKeyIn.header}, name=name)
        self.getter = lambda x: x.headers
