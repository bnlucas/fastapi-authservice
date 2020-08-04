from httpx import AsyncClient, HTTPError
from jwt import decode
from jwt.exceptions import InvalidTokenError
from fastapi import Security
from starlette.exceptions import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from .security import JWTCookie, JWTHeader


class JWTAuthenticator:
    def __init__(
        self, *, secret_key: str, algorithm: str, verify_url: str,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.verify_url = verify_url
        self.client = AsyncClient()

    def from_cookie(
        self, name: str, *, scheme_name: str = None, auto_error: bool = True,
    ) -> Security:
        token = JWTCookie(
            name=name,
            verifier=self.verify,
            decoder=self.decode,
            scheme_name=scheme_name,
            auto_error=auto_error,
        )

        return Security(token)

    def from_header(
        self, name: str, *, scheme_name: str = None, auto_error: bool = True,
    ) -> Security:
        token = JWTHeader(
            name=name,
            verifier=self.verify,
            decoder=self.decode,
            scheme_name=scheme_name,
            auto_error=auto_error,
        )

        return Security(token)

    async def verify(self, token: str,) -> str:
        response = await self.client.post(self.verify_url, json={"token": token})

        try:
            response.raise_for_status()
        except HTTPError:
            raise HTTPException(
                status_code=response.status_code, detail="Not authenticated"
            )
        finally:
            data = response.json()
            token = data.get("token", None)

            if token is None:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )

            return token

    def decode(self, token: str) -> dict:
        try:
            return decode(token, key=self.secret_key, algorithms=[self.algorithm])
        except InvalidTokenError:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )
