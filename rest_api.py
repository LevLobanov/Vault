from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from starlette.requests import Request
import uvicorn
from typing import Dict, List, Optional


# App and limiter


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="VAULT")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Pydantic models


class SetSecretRequest(BaseModel):
    token: str

class SetSecretResponse(BaseModel):
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


# Handlers


@app.post("/auth/{auth_method}")
@limiter.limit("5/minute")
async def authorize(request: Request, auth_method: str):
    return "Works with limit 5 requests per minute"

@app.get("/v1/{secret_engine}/{path}")
async def get_secret(secret_engine: str, path: str):
    return "Your secret: 🍆"

@app.post("/v1/{secret_engine}/{path}", response_model=SetSecretResponse)
async def set_secret(secret_engine: str, path: str, data: SetSecretRequest):
    return SetSecretResponse(data = {
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
    uvicorn.run("main:app", host = "0.0.0.0", port = 8000, reload = True)