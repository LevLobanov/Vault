from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from starlette.requests import Request
import uvicorn
from typing import Annotated, Dict, List, Optional
from vault.vault import auth, secrets_engine


# App and limiter


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="VAULT")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
token_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Pydantic models


class SetSecretKVRequest(BaseModel):
    token: str

class SetSecretKVResponse(BaseModel):
    class Data(BaseModel):
        class CustomMetadata(BaseModel):
            owner: str
            mission_critical: str
        
        created_time: str
        custom_metadata: CustomMetadata
        deletion_time: Optional[str]
        destroyed: bool
        version: int

    data: Data

class AuthUserpassRequest(BaseModel):
    password: str
    token_ttl: Optional[int]

class AuthUserpassResponse(BaseModel):
    token: str


# Handlers


@app.post("/auth/userpass/login/{username}", response_model=AuthUserpassResponse)
@limiter.limit("5/second")
async def authorize_userpass(request: Request, username: str, data: AuthUserpassRequest):
    return AuthUserpassResponse(token = auth.auth_userpass(username, data.password, token_ttl=data.token_ttl))

@app.get("/v1/secret/{path}")
async def get_secret_kv(path: str, token: Annotated[str, Depends(token_scheme)]):
    return secrets_engine.kv.get_secret(token, path)

@app.post("/v1/secret/data/{path}", response_model=SetSecretKVResponse)
async def set_secret_kv(secret_engine: str, path: str, data: SetSecretKVRequest, token: Annotated[str, Depends(token_scheme)]):
    return SetSecretKVResponse(data = {
        "created_time": "2018-03-22T02:36:43.986212308Z",
        "custom_metadata": {
            "owner": "jdoe",
            "mission_critical": "false"
        },
        "deletion_time": "",
        "destroyed": False,
        "version": 1
    })



# Entry point


if __name__ == "__main__":
    print(secrets_engine.kv.get_secret("my token", "path/to/secret/"))
    # uvicorn.run("rest_api:app", host = "127.0.0.1", port = 8000, reload = True)