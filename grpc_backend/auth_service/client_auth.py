import grpc
import json
import jwt

# Módulos gerados pelo gRPC
import auth_pb2
import auth_pb2_grpc


def verificar_token(token, jwks_endpoint_url):
    """
    Função para decodificar e verificar um token JWT usando um endpoint JWKS.
    """
    try:
        # Primeiro, obtemos o cabeçalho do token sem verificar a assinatura
        # para descobrir qual chave (kid) foi usada.
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        # Em um cenário real, você faria uma requisição HTTP para jwks_endpoint_url
        # Aqui, vamos simular isso chamando nosso método gRPC.
        print("\nBuscando chaves públicas (JWKS) do servidor...")
        with grpc.insecure_channel("localhost:50051") as channel:
            stub = auth_pb2_grpc.AuthServiceStub(channel)
            response = stub.GetJWKS(auth_pb2.Empty())
            jwks = json.loads(response.keys_json)

        print(f"JWKS recebido: {json.dumps(jwks, indent=2)}")

        # Encontre a chave correta no JWKS usando o 'kid'
        public_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if public_key is None:
            raise ValueError(
                "Chave pública com o 'kid' especificado não encontrada no JWKS."
            )

        # Agora, decodifique e verifique o token usando a chave pública
        decoded_payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="urn:meu-servico",  # Verifique se a audiência está correta
            issuer="urn:servico-auth",  # Verifique se o emissor está correto
        )

        print("\n--- Verificação do Token ---")
        print("Assinatura do Token é VÁLIDA.")
        print(f"Payload decodificado: {decoded_payload}")
        print("--------------------------")

    except jwt.ExpiredSignatureError:
        print("Erro: O token expirou.")
    except jwt.InvalidAudienceError:
        print("Erro: Audiência (aud) do token é inválida.")
    except jwt.InvalidIssuerError:
        print("Erro: Emissor (iss) do token é inválido.")
    except Exception as e:
        print(f"Ocorreu um erro ao verificar o token: {e}")


def run():
    """Executa o cliente gRPC."""
    with grpc.insecure_channel("localhost:50051") as channel:
        stub = auth_pb2_grpc.AuthServiceStub(channel)

        # --- Teste 1: Login com sucesso ---
        print("--- Tentativa de Login com Sucesso (usuario1) ---")
        try:
            login_request = auth_pb2.LoginRequest(
                username="usuario1", password="senha123"
            )
            login_response = stub.Login(login_request)
            print(f"Login bem-sucedido! Token Type: {login_response.token_type}")
            print(
                f"Access Token: {login_response.access_token[:30]}..."
            )  # Mostra apenas o início do token

            # Verifica o token recebido
            verificar_token(login_response.access_token, "localhost:50051")

        except grpc.RpcError as e:
            print(f"Erro no RPC: [{e.code()}] {e.details()}")

        # --- Teste 2: Login com falha ---
        print("\n\n--- Tentativa de Login com Falha (senha errada) ---")
        try:
            login_request = auth_pb2.LoginRequest(
                username="admin", password="senha_errada"
            )
            login_response = stub.Login(login_request)
        except grpc.RpcError as e:
            print(f"Erro no RPC esperado: [{e.code()}] {e.details()}")


if __name__ == "__main__":
    run()
