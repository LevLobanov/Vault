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


# Handlers

## Sealing / Unsealing

### Pydantic models

class UnsealRequest(BaseModel):
    key: str
    reset: bool

class UnsealResponse(BaseModel):
    sealed: bool
    t: int
    n: int
    progress: int

class SealStatusResponse(BaseModel):
    sealed: bool
    t: int
    n: int
    progress: int

### Handlers


@app.post("/sys/seal")
async def seal_vault(token: Annotated[str, Depends(token_scheme)]):
    ...


@app.post("/sys/unseal", response_model=UnsealResponse)
async def unseal_vault(data: UnsealRequest):
    ...


@app.get("sys/seal-status", response_model=SealStatusResponse)
async def seal_status():
    ...


# Sys

## Auth methods

### Pydantic models

### Handlers


@app.get("/sys/auth")
async def list_auth_methods(token: Annotated[str, Depends(token_scheme)]):
    ...


@app.post("/sys/auth/{path}")
async def enable_auth_method(path: str, token: Annotated[str, Depends(token_scheme)]):
    ...


@app.delete("/sys/auth/{path}")
async def disable_auth_method(path: str, token: Annotated[str, Depends(token_scheme)]):
    ...


## Policies

### Pydantic models

### Handlers


@app.get("sys/policy")
async def list_policies(token: Annotated[str, Depends(token_scheme)]):
    ...


@app.get("/sys/policy/{name}")
async def read_policy(name: str, token: Annotated[str, Depends(token_scheme)]):
    ...


@app.post("/sys/policy/{name}")
async def create_update_policy(name: str, token: Annotated[str, Depends(token_scheme)]):
    ...


@app.delete("/sys/policy/{name}")
async def delete_policy(name: str, token: Annotated[str, Depends(token_scheme)]):
    ...


# Auth

## UserPass

### Pydantic models

class AuthUserpassRequest(BaseModel):
    username: str
    password: str
    token_ttl: Optional[int]

class AuthUserpassResponse(BaseModel):
    token: str

### Handlers


@app.post("/auth/userpass/login/{username}", response_model=AuthUserpassResponse)
@limiter.limit("5/second")
async def authorize_userpass(request: Request, username: str, data: AuthUserpassRequest):
    return AuthUserpassResponse(token = auth.auth_userpass(username, data.password, token_ttl=data.token_ttl))


@app.post("/auth/userpass/users/{username}")
async def create_update_userpass_auth(username: str, data: ..., token: Annotated[str, Depends(token_scheme)]):
    ...


@app.delete("auth/userpass/users/{username}")
async def delete_userpass_auth(username: str, data: ..., token: Annotated[str, Depends(token_scheme)]):
    ...


@app.post("/auth/userpass/users/{username}/password")
async def update_password_userpass_auth(username: str, data: ..., token: Annotated[str, Depends(token_scheme)]):
    ...


@app.post("/auth/users/{username}/policies")
async def update_policies_user(username: str, data: ..., token: Annotated[str, Depends(token_scheme)]):
    ...


# Secrets

## Key - Value (v1)

### Pydantic models

class SetSecretKVRequest(BaseModel):
    __root__: Dict[str, str]

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

class GetSecretKVResponse(BaseModel):
    data: Dict[str, str]

### Handlers


@app.get("/secret/{path}", response_model=GetSecretKVResponse)
async def get_secret_kv(path: str, token: Annotated[str, Depends(token_scheme)]):
    return secrets_engine.kv.get_secret(token, path)


@app.post("/secret/data/{path}", response_model=SetSecretKVResponse)
async def set_secret_kv(path: str, data: SetSecretKVRequest, token: Annotated[str, Depends(token_scheme)]):
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


@app.delete("secret/{path}")
async def delete_secret_kv(path: str, token: Annotated[str, Depends(token_scheme)]):
    ...


# Entry point


if __name__ == "__main__":
    uvicorn.run("rest_api:app", host = "127.0.0.1", port = 8000, reload = True)