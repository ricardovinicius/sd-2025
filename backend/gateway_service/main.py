import os
import random
import time
from fastapi.security import OAuth2PasswordBearer
import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from jose import jwt, JWTError

REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:8100")
AUTH_SERVICE_NAME = "auth"
ALGORITHM = "RS256"


client = httpx.AsyncClient(timeout=5.0)
jwks_cache = {"data": None, "timestamp": 0}
CACHE_TTL = 300  # 5 minutos

# --- Lógica de Autenticação ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"/{AUTH_SERVICE_NAME}/login")

async def get_jwks():
    """Busca o JWKS do serviço de autenticação, com cache."""
    now = time.time()
    if jwks_cache["data"] and (now - jwks_cache["timestamp"]) < CACHE_TTL:
        return jwks_cache["data"]
    
    auth_service_url = await get_service_url(AUTH_SERVICE_NAME)
    if not auth_service_url:
        raise HTTPException(status_code=503, detail="Serviço de autenticação indisponível.")
    
    try:
        response = await client.get(f"{auth_service_url}/.well-known/jwks.json")
        response.raise_for_status()
        jwks = response.json()
        jwks_cache["data"] = jwks
        jwks_cache["timestamp"] = now
        return jwks
    except (httpx.RequestError, httpx.HTTPStatusError):
        raise HTTPException(status_code=503, detail="Não foi possível obter a chave de verificação.")

async def verify_token(token: str = Depends(oauth2_scheme)):
    """Dependência que valida o token JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        jwks = await get_jwks()
        print("JWKS obtido:", jwks)
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        if "kid" not in unverified_header:
            raise credentials_exception
        
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = key
        print("Chave RSA encontrada:", rsa_key)

        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=[ALGORITHM],
                audience=None, # Defina a audiência se necessário
                issuer=None,   # Defina o emissor se necessário
            )
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            return username
        raise credentials_exception
    except JWTError:
        raise credentials_exception

app = FastAPI(title="API Gateway")

async def get_service_url(service_name: str) -> str:
    """Consulta o Registry para obter a URL de uma instância de serviço."""
    try:
        response = await client.get(f"{REGISTRY_URL}/services/{service_name}")
        response.raise_for_status() # Lança exceção para status 4xx/5xx
        instances = response.json()
        if not instances:
            return None
        # Simples balanceamento de carga: escolhe uma instância aleatoriamente
        return random.choice(instances)['url']
    except (httpx.RequestError, httpx.HTTPStatusError):
        return None
    
async def proxy_request(request: Request, service_name: str, path: str):
    target_service_url = await get_service_url(service_name)
    if not target_service_url:
        return JSONResponse(status_code=503, content={"detail": f"Serviço '{service_name}' indisponível."})
    
    target_url = f"{target_service_url}/{path}"
    if request.query_params:
        target_url += f"?{request.query_params}"
    
    headers = dict(request.headers)
    headers["host"] = httpx.URL(target_service_url).host
    
    try:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=await request.body()
        )
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
    except httpx.RequestError:
        return JSONResponse(status_code=503, detail=f"Erro ao contatar o serviço de {service_name}.")

# Rota pública para autenticação
@app.api_route("/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def auth_proxy(request: Request, path: str):
    return await proxy_request(request, "auth", path)

# Rotas protegidas para outros serviços
@app.api_route("/{service_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def protected_proxy(request: Request, service_name: str, path: str, current_user: str = Depends(verify_token)):
    # O token já foi validado pela dependência 'verify_token'
    # Opcional: você pode adicionar o 'current_user' aos cabeçalhos antes de encaminhar
    # request.headers["X-User"] = current_user
    print(f"Usuário autenticado: {current_user}")
    return await proxy_request(request, service_name, path)