import json
import grpc
import asyncio
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
import jwt

# Módulos gRPC
import auth_pb2
import auth_pb2_grpc
import images_pb2 as img_pb2
import images_pb2_grpc as img_grpc

app = FastAPI()

# 1. (Correção) Usar o esquema de segurança do FastAPI para extrair o token do cabeçalho "Authorization: Bearer <token>"
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token"
)  # tokenUrl é usado para a documentação da API


# 2. (Correção) Transformar a função em 'async' e usar gRPC assíncrono
async def get_current_user_payload(token: str = Depends(oauth2_scheme)):
    """
    Dependência assíncrona para:
    1. Extrair o token Bearer da requisição.
    2. Chamar o serviço de autenticação gRPC de forma não-bloqueante para obter o JWKS.
    3. Verificar e decodificar o token JWT.
    4. Levantar HTTPException em caso de falha.
    5. Retornar o payload do token em caso de sucesso.
    """
    try:
        # Obtém o cabeçalho do token para encontrar o Key ID (kid)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        # Usa o canal gRPC assíncrono (não-bloqueante)
        async with grpc.aio.insecure_channel("localhost:50051") as channel:
            stub = auth_pb2_grpc.AuthServiceStub(channel)
            # A chamada gRPC agora é 'await'
            response = await stub.GetJWKS(auth_pb2.Empty())
            jwks = json.loads(response.keys_json)

        # Encontra a chave pública correspondente no JWKS
        public_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if public_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Chave pública para assinatura do token não encontrada",
            )

        # Decodifica e valida o token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="urn:meu-servico",
            issuer="urn:servico-auth",
        )
        # Retorna o payload para ser usado no endpoint, se necessário
        return payload

    # 3. (Correção) Capturar exceções específicas e levantar HTTPException
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado",
        )
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token com 'audience' ou 'issuer' inválidos",
        )
    except (jwt.PyJWTError, Exception) as e:
        # Captura outras exceções do JWT e erros genéricos
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Não foi possível validar o token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/auth/login")
async def login(request: Request):
    """
    Endpoint para login.
    Recebe credenciais, chama o serviço de autenticação gRPC e retorna o token JWT.
    """
    credentials = await request.json()
    username = credentials.get("username")
    password = credentials.get("password")

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username e password são obrigatórios",
        )

    async with grpc.aio.insecure_channel("localhost:50051") as channel:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        grpc_request = auth_pb2.LoginRequest(username=username, password=password)
        try:
            response = await stub.Login(grpc_request)
            return JSONResponse(
                content={
                    "access_token": response.access_token,
                    "token_type": response.token_type,
                }
            )
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAUTHENTICATED:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Credenciais inválidas",
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Erro ao comunicar com o serviço de autenticação",
                )


@app.get("/images")
# 4. (Correção) A dependência agora retorna o payload do token decodificado
async def get_images(user_payload: dict = Depends(get_current_user_payload)):
    """
    Endpoint protegido para buscar imagens.
    Só será executado se a dependência 'get_current_user_payload' for bem-sucedida.
    """
    print(f"Acesso autorizado para o usuário: {user_payload.get('sub')}")

    async with grpc.aio.insecure_channel(
        "localhost:50052"
    ) as channel:  # Assumindo que o serviço de imagem está em outra porta
        stub = img_grpc.ImagesServiceStub(channel)
        response = await stub.GetImages(img_pb2.Empty())
        return [
            dict(id=i.id, url=i.url, description=i.description) for i in response.images
        ]


@app.get("/health")
async def health_check():
    return {"status": "ok"}


def main():
    import uvicorn

    uvicorn.run(app, host="localhost", port=8000)


if __name__ == "__main__":
    main()
