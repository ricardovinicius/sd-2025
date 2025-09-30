import os
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, jwk
from jose.utils import base64url_encode
import hashlib
from passlib.context import CryptContext

# --- Configuração ---
SERVICE_NAME = "auth"
SERVICE_PORT = 8003
SERVICE_HOST = "localhost"
SERVICE_URL = f"http://{SERVICE_HOST}:{SERVICE_PORT}"
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:8100")

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Carregando as Chaves ---
with open("auth_service/private_key.pem", "rb") as f:
    private_key = f.read()
with open("auth_service/public_key.pem", "rb") as f:
    public_key = f.read()

key_obj = jwk.construct(public_key, algorithm=ALGORITHM)
KEY_ID = base64url_encode(hashlib.sha256(public_key).digest()).decode('utf-8')

# --- Segurança de Senha ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- "Banco de Dados" de Usuários em Memória ---
# Em um projeto real, use um banco de dados como PostgreSQL.
# A senha 'wonderland' foi hasheada com: pwd_context.hash("wonderland")
fake_users_db = {
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderland",
        "hashed_password": pwd_context.hash("wonderland"),
        "disabled": False,
    }
}
hashed_password = pwd_context.hash("wonderland")
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    headers = {"kid": KEY_ID}
    encoded_jwt = jwt.encode(to_encode, private_key, headers=headers, algorithm=ALGORITHM)
    return encoded_jwt

# --- Ciclo de Vida (Lifespan para registrar no Registry) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient() as client:
        try:
            await client.post(f"{REGISTRY_URL}/register", json={"name": SERVICE_NAME, "url": SERVICE_URL})
            print(f"Serviço '{SERVICE_NAME}' registrado.")
        except httpx.RequestError:
            print("Falha ao registrar no Service Registry.")
    yield
    async with httpx.AsyncClient() as client:
        try:
            await client.delete(f"{REGISTRY_URL}/deregister", json={"name": SERVICE_NAME, "url": SERVICE_URL})
            print(f"Serviço '{SERVICE_NAME}' desregistrado.")
        except httpx.RequestError:
            print("Falha ao desregistrar do Service Registry.")

# --- Aplicação FastAPI ---
app = FastAPI(title="Serviço de Autenticação", lifespan=lifespan)

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/login")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}
@app.get("/.well-known/jwks.json")
async def jwks():
    """Expõe a chave pública no formato JWK para verificação por outros serviços."""
    key = jwk.construct(public_key, algorithm=ALGORITHM)
    # Gera um 'kid' (Key ID) único baseado no hash da chave pública
    thumbprint = base64url_encode(hashlib.sha256(public_key).digest()).decode('utf-8')
    return {"keys": [{**key.to_dict(), "kid": thumbprint}]}

@app.post("/test")
async def test(request: Request):
    print(await request.body())
