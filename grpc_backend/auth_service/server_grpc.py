import grpc
import time
import json
from concurrent import futures

# Módulos gerados pelo gRPC
import auth_pb2
import auth_pb2_grpc

# Bibliotecas para JWT e chaves
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Carregamento das Chaves a partir de arquivos PEM ---

# Carrega o conteúdo da chave privada do arquivo
with open("private_key.pem", "rb") as f:
    private_key_bytes = f.read()
# Carrega o objeto da chave privada
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,  # Use a senha aqui se a chave for criptografada
    backend=default_backend(),
)

# Carrega o conteúdo da chave pública do arquivo
with open("public_key.pem", "rb") as f:
    public_key_bytes = f.read()
# Carrega o objeto da chave pública
public_key = serialization.load_pem_public_key(
    public_key_bytes, backend=default_backend()
)


# --- Geração do JWKS a partir da chave pública carregada ---

# Crie o JWK a partir do objeto de chave pública
# Esta lógica permanece a mesma, mas agora usa a chave que foi carregada
jwk = {
    "kty": "RSA",
    "kid": "chave-producao-20250930",  # Um Key ID mais descritivo
    "use": "sig",
    "alg": "RS256",
    "n": jwt.utils.base64url_encode(
        public_key.public_numbers().n.to_bytes(256, "big")
    ).decode("utf-8"),
    "e": jwt.utils.base64url_encode(
        public_key.public_numbers().e.to_bytes(3, "big")
    ).decode("utf-8"),
}

jwks = {"keys": [jwk]}
jwks_json = json.dumps(jwks)


# --- Implementação do Serviço gRPC ---


class AuthService(auth_pb2_grpc.AuthServiceServicer):

    USUARIOS_VALIDOS = {"usuario1": "senha123", "admin": "admin123"}

    def Login(self, request, context):
        print(f"Recebida requisição de login para o usuário: {request.username}")

        if (
            request.username in self.USUARIOS_VALIDOS
            and self.USUARIOS_VALIDOS[request.username] == request.password
        ):
            payload = {
                "sub": request.username,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "aud": "urn:meu-servico",
                "iss": "urn:servico-auth",
            }

            # Assina o token com o objeto da chave privada que foi carregado
            access_token = jwt.encode(
                payload,
                private_key,  # Usa o objeto da chave privada diretamente
                algorithm="RS256",
                headers={"kid": jwk["kid"]},
            )

            print(f"Login bem-sucedido para {request.username}. Token gerado.")
            return auth_pb2.LoginResponse(
                access_token=access_token, token_type="Bearer"
            )
        else:
            print(f"Falha na autenticação para o usuário: {request.username}")
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Usuário ou senha inválidos")
            return auth_pb2.LoginResponse()

    def GetJWKS(self, request, context):
        print("Requisição recebida para o endpoint JWKS.")
        return auth_pb2.JWKSResponse(keys_json=jwks_json)


def serve():
    """Inicia o servidor gRPC."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print(
        "Servidor de Autenticação gRPC iniciado. Carregando chaves de 'private_key.pem' e 'public_key.pem'."
    )
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
