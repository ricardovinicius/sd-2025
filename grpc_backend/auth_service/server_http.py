import os
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from .logic import fake_users_db, create_access_token

SERVICE_NAME = "auth"
SERVICE_PORT = 8003
SERVICE_HOST = "localhost"
SERVICE_URL = f"http://{SERVICE_HOST}:{SERVICE_PORT}"
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:8100")

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient() as client:
        try:
            await client.post(f"{REGISTRY_URL}/register", json={"name": SERVICE_NAME, "url": SERVICE_URL})
            print(f"{SERVICE_NAME} registrado")
        except:
            print("Falha no registro")
    yield
    async with httpx.AsyncClient() as client:
        try:
            await client.delete(f"{REGISTRY_URL}/deregister", json={"name": SERVICE_NAME, "url": SERVICE_URL})
            print(f"{SERVICE_NAME} desregistrado")
        except:
            print("Falha ao desregistrar")

app = FastAPI(lifespan=lifespan)

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or user["hashed_password"] != form_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário ou senha inválidos")
    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/.well-known/jwks.json")
async def jwks():
    return {"keys": [jwks_json]}
