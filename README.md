# fastapi-authservice
A simple way to interact with an external auth service within your FastAPI services. Currently
this only supports JWT, but there are plans for future implementations.

When interacting with an external auth service, you want to verify tokens with it. With
fastapi-authservice, a call will be made to the `verify_url` with the provided token
and will throw `HTTPException` if the auth service is unable to verify it. Future plans will
allow for calling refresh endpoints as well.


## Usage
`JWTAuthenticator` has two options for collecting the JWT, either from the Authorization header
or from a cookie using `JWTAuthenticator.from_header(name=...) and .from_cookies(name=...)`
```python
import os

from fastapi import Depends, FastAPI
from fastapi_authservice import JWTAuthenticator
from pydantic import BaseModel


auth = JWTAuthenticator(
    secret_key=os.getenv('JWT_SECRET_KEY'),
    algorithm=os.getenv('JWT_ALGORITHM'),
    verify_url="http://127.0.0.1:8000/verify/",
)


class AuthData(BaseModel):
    user_id: str


def get_auth_data(data: dict = auth.from_cookie(name='sso')):
    return AuthData(**data)


app = FastAPI()

@app.get("/")
def base_route(auth_data: AuthData = Depends(get_auth_data)):
    return auth_data
```

Providing a valid JWT within a cookie named `sso`:

```shell script
$ http http://127.0.0.1:8000/ 'Cookie:sso=MY_JWT'

{
    "user_id": "user_id_from_jwt"
}
```
