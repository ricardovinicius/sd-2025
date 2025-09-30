from concurrent import futures
import grpc
from . import auth_pb2
from . import auth_pb2_grpc
from fastapi import HTTPException
from .main import fake_users_db, create_access_token, jwks_json

class AuthServicer(auth_pb2_grpc.AuthServiceServicer):
    def Login(self, request, context):
        user = fake_users_db.get(request.username)
        if not user:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Usuário inválido")
        token = create_access_token({"sub": user["username"]})
        return auth_pb2.LoginResponse(access_token=token, token_type="bearer")

    def GetJWKS(self, request, context):
        return auth_pb2.JWKSResponse(keys_json=jwks_json)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthServicer(), server)
    server.add_insecure_port("[::]:50052")
    print("Auth gRPC ouvindo em 50052")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
